#include "dbt/guest/rv32_cpu.h"
#include "dbt/fault_snapshot.h"
#include "dbt/ccrf_materializer.h"
#include "dbt/guest/rv32_lane_region_bridge.h"
#include "dbt/guest/rv32_vector_lower.h" // RVV chunk counters + HOST_CHUNK_BYTES for --rvv-stats
#include "dbt/guest/rv32_pc_census.h"
#include "dbt/guest/rv32_vector_census.h" // P13 dynamic RVV cost census (--rvv-census)
#include "dbt/guest/rv32_route_census.h" // T3a per-opcode direct/handler route census
#include "dbt/guest/rv32_vrun.h"	 // P7M-E per-frame dynamic vector-run census
#include "dbt/guest/rv32_seqtrace.h"
#ifdef RVDBT_ASYNC_SIGNAL_PROBE
// G1: directed probe for the ASYNCHRONOUS HOST SIGNAL boundary.
//
// Guest signal delivery does not exist in rvdbt (linux_rt_sigaction is a TODO stub), but that does
// NOT settle whether a host signal interrupting the emulator while an FP run is open is safe. Two
// distinct questions:
//   (a) is the guest's MXCSR state preserved across delivery+sigreturn?  The kernel saves and
//       restores the FP state in the signal frame, so it should be -- but that is an assumption
//       until measured.
//   (b) does the HANDLER run with the guest's rounding mode installed?  If a run is open, MXCSR.RC
//       holds the guest's mode, and any host FP inside the handler silently uses it.
// This probe answers both by sampling at high frequency during real guest execution.
#include <csignal>
#include <sys/time.h>
#include <immintrin.h>
static volatile unsigned long long g_sig_n, g_sig_rc_nondefault, g_sig_rc_changed;
static void async_probe_handler(int)
{
	unsigned const mx = _mm_getcsr();
	g_sig_n++;
	if ((mx & 0x6000u) != 0u) g_sig_rc_nondefault++;   // handler entered under a non-RNE mode
	unsigned const after = _mm_getcsr();
	if (after != mx) g_sig_rc_changed++;
}
static void async_probe_start()
{
	struct sigaction sa{};
	sa.sa_handler = async_probe_handler;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGPROF, &sa, nullptr);
	struct itimerval it{};
	it.it_interval.tv_usec = 200;   // ~5 kHz
	it.it_value.tv_usec = 200;
	setitimer(ITIMER_PROF, &it, nullptr);
}
static void async_probe_report()
{
	struct itimerval off{};
	setitimer(ITIMER_PROF, &off, nullptr);
	fprintf(stderr, "ASYNC_SIGNAL_PROBE samples=%llu rc_nondefault=%llu rc_changed=%llu\n",
		g_sig_n, g_sig_rc_nondefault, g_sig_rc_changed);
}
#endif
#ifdef RVDBT_CHECK_TBEXIT_MXCSR
extern "C" unsigned long long g_tbexit_mxcsr_violations;
#endif

// P14 chunk-dispatch hoist A/B flag, defined in guest/rv32_vector_run_flags.cpp.
extern "C" unsigned rvv_run_hoist;
extern "C" unsigned rvv_run_unroll2; // P13 phase-A dynamic sequence collector (--rvv-seqtrace-out)
#include "dbt/guest/rv32_vector_fast.h"   // P13 semantic-class chunk lowering (--rvv-fast)
#include <ucontext.h>
#include <dlfcn.h>
#include "dbt/tcache/objprof.h"
#include "dbt/tcache/tcache.h"
#include "dbt/qmc/ngr.h"
#include "dbt/ukernel.h"
#include "dbt/util/fsmanager.h"
#include "dbt/aot/loop_tier.h" // T5d2a
#include <boost/any.hpp>
#include <boost/program_options.hpp>
#include <sys/time.h>
#include <csignal>
#include <boost/tokenizer.hpp>
#include <iostream>
#include <sstream>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <utility>

namespace bpo = boost::program_options;

namespace dbt { void dump_load_values(char const *); } // Family-A probe, defined in rv32_interp.cpp
namespace dbt {
void phase_window_flush_final();
void phase_window_dump(char const *path);
}

struct ElfRunOptions {
	std::span<char *> guest_args{};

	std::string fsroot{};
	std::string cache{};
	bool use_aot{};
	bool merge_ls{};
	bool trace{};
	std::string logs{};
	bool not_freq{};
	bool no_tb_clip{};
	bool tb_through_brind{};
	unsigned code_pad{};
	bool count_brind{};
	bool dump_region_hits{};
	bool aot_region_hit_count{};
	bool aot_count_gbrind{};
	bool aot_link_multientry_trace{};
	bool qcg_resident{};
	bool qcg_pin{};
	unsigned qcg_pin_k{};
	std::string brind_edges_out{};
	std::string sr_cheap_edges_out{};
	unsigned long sr_bounded_exhaustive{0};
	bool sr_live_edges_dump{};
	std::string sr_revoke_watch{};
	std::string wmax_sample_out{};
	std::string dump_tbmap{};
	std::string dump_tbcode{};
	std::string load_values_out{};
	std::string selfprof_out{};
	std::string dispatch_selfprof_out{};
	std::string phase_windows_out{};
	unsigned long long phase_window_insns{};
	unsigned long long phase_window_max{};
	std::string aot_reuse{};
	std::string aot_reuse_elf{};
	bool tier_census{};
	bool qcg_code_bytes{};
	bool measure_translation{};
	std::string translate_ip_out{};
	bool ngr{};
	bool ngr_verify{};
	bool ngr_loops{};
	bool fast_boot{};
	bool qcg_code_huge_pages{};
	unsigned vlen{128};
	unsigned rvv_lowering{1};
	bool rvv_verify{};
	bool rvv_stats{};
	bool rvv_route_census{};
	bool rvv_direct{true};
	bool rvv_qcg_diag_chunk{};
	bool rvv_qcg_diag_chunk_force_emit{};
	// Mirrors elfaot's --llvm. Only elfaot could set config::aot_use_llvm before, so the
	// pure-QCG chunk paths -- which admit only when it is FALSE -- were unreachable from the
	// runner. Default true keeps every existing elfrun invocation byte-identical.
	bool aot_use_llvm{true};
	bool rvv_qcg_typed_chunk{};
	bool rvv_qcg_typed_chunk_force_emit{};
	bool rvv_qcg_typed_chunk_falu{};
	bool rvv_qcg_typed_chunk_falu_force_emit{};
	bool rvv_qcg_typed_chunk_fma{};
	bool rvv_qcg_typed_chunk_fma_force_emit{};
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
	bool rvv_qcg_typed_chunk_fsqrt_force_emit{};
	bool rvv_qcg_typed_chunk_fcmp{};
	bool rvv_qcg_typed_chunk_fcmp_force_emit{};
	bool rvv_qcg_typed_chunk_fwiden{};
	bool rvv_qcg_typed_chunk_fwiden_fma{};
	bool rvv_qcg_typed_chunk_fwiden_force_emit{};
	bool rvv_qcg_typed_chunk_mul{};
	bool rvv_qcg_typed_chunk_mul_force_emit{};
	bool rvv_qcg_typed_chunk_sub{};
	bool rvv_qcg_typed_chunk_sub_force_emit{};
	bool rvv_qcg_typed_chunk_xor{};
	bool rvv_qcg_typed_chunk_shift{};
	bool rvv_qcg_typed_chunk_shift_force_emit{};
	bool rvv_run_live_range_split{};
	bool rvv_run_frame_census{};
	bool rvv_run_split_value_weighted{};
	bool rvv_qcg_narrow_chunk_width{};
	bool rvv_qcg_narrow_chunk_width_force_emit{};
	bool rvv_qcg_typed_chunk_xor_force_emit{};
	bool rvv_qcg_typed_chunk_or{};
	bool rvv_qcg_typed_chunk_or_force_emit{};
	bool rvv_qcg_typed_chunk_and{};
	bool rvv_qcg_typed_chunk_and_force_emit{};
	bool rvv_qcg_typed_chunk_vle{};
	bool rvv_qcg_typed_chunk_vle_force_emit{};
	bool rvv_qcg_typed_chunk_vse{};
	bool rvv_qcg_typed_chunk_vse_force_emit{};
	bool rvv_qcg_typed_chunk_vlse_gather{};
	bool rvv_qcg_typed_chunk_vlse_gather_force_emit{};
	bool rvv_qcg_typed_chunk_vlse_gather_census{};
	bool rvv_qcg_active_chunk_census{};
	bool rvv_qcg_direct_setvl{};
	bool rvv_state_hash{};
	bool rvv_vector_run{};
	bool rvv_run_scan_fast_reject{};
	bool rvv_run_fp_store_masked_partial_vl{};
	bool rvv_run_fp_store_mask_reuse_shared{};
	bool rvv_run_scalar_passthrough{};
	bool rvv_run_component_separable{};
	bool rvv_run_bounded_batches{};
	bool rvv_run_component_demand_placement{};
	bool rvv_run_grouped_component_major{};
	bool rvv_qcg_active_vl_run_bound{};
	bool rvv_qcg_active_vl_bound_placebo{};
	std::string rvv_lane_census_out{};
	std::string fault_snapshot_plan{};
	std::string fault_snapshot_out{};
	std::string ccrf_certificate{};
	std::string ccrf_affine_facts{};
	std::string ccrf_exact_qir{};
	std::string ccrf_result_out{};
	bool ccrf_sequential{};
	bool ccrf_concurrent{};
	bool ccrf_precompiled_sequential{};
	bool ccrf_require_avx512{};
	int ccrf_worker_cpu0{-1}, ccrf_worker_cpu1{-1};
	std::string rvv_run_body{"ssa"};
	std::string rvv_run_order{"member"};
	unsigned rvv_run_dep_probe_depth{};
	std::string rvv_run_dep_probe{"indep"};
	bool rvv_qcg_hit_counter{true};
	bool rvv_vector_ssa{};
	bool rvv_llvm_wide_vadd{};
	bool rvv_llvm_wide_vadd_ssa{};
	bool rvv_vector_ssa_counters{};
	unsigned long long rvv_inject_fault{};
	unsigned rvv_census{};
	std::string rvv_census_out{};
	bool rvv_pc_census{};
	std::string rvv_pc_census_out{};
	unsigned rvv_probe{};
	bool rvv_fast{};
	bool rvv_fuse_pairs{};
	bool rvv_tail_round{};
	bool rvv_preadmit_extent{};
	bool rvv_gather{};
	unsigned rvv_fast_classes{15};
	bool rvv_fround_batch{true};
	unsigned rvv_fround_mxcsr_mode{};
	bool rvv_vfcmp_batch_mask{};
	unsigned rvv_fred_specialize{};
	unsigned rvv_fround_oracle_mode{};
	std::string rvv_fround_oracle_file{};
	unsigned rvv_width_policy{};
	std::string rvv_probe_out{};
	std::string rvv_seqtrace_out{};
	bool rvv_run_hoist{false};
	bool rvv_run_unroll2{false};
	bool rvv_scalar_fround_run{false};
	bool rvv_scalar_fround_rcmirror{false};
	bool rvv_fixed_copy{false};
	bool tier0_lazy{};
	unsigned tier0_threshold{};
	bool update_profile_on_aot{};
	bool inrun_tier{};
	int inrun_flush_ms{};
	std::string inrun_artifact{};
	std::string inrun_artifact_seq{}; // Round-40: comma-separated armed-artifact sequence (small-hot,full / chunks)
	bool inrun_auto_escalate{false};
	bool escalate_time_census{false};
	bool sr_log_ratecontrol{false};
	bool escalate_quality_proxy{false};
	bool single_run{false};
	bool inrun_observe_only{false};
	bool inrun_evidence_gate{false};
	bool esc_ski_full{false};
	long sr_gate_ms{0};
	bool sr_sampled_edges{false};
	bool sr_edges_all_misses{false};
	bool shadow_edges{false};
	std::string shadow_edges_out{};
	unsigned shadow_edges_k{0};
	std::string shadow_edges_k_out{};
	bool shadow_edges2{false};
	std::string shadow_edges2_out{};
	bool shadow_edges2_all_jalr{false};
	bool gbrind_hitrate_collect{false};
	std::string gbrind_hitrate_out{};
	bool temporal_order_collect{false};
	std::string temporal_order_out{};
	bool temporal_order_all_jalr{false};
	bool shadow_majority{false};
	std::string shadow_majority_out{};
	bool qcg_dispatch_ic{false};
	std::string qcg_dispatch_ic_site{};
	bool qcg_ic_regret{false};
	bool qcg_gbrind_outline{false};
	bool qcg_freq_scratch{false};
	bool qcg_freq_sat{false};
	unsigned long long qcg_freq_sat_t{262144};
	bool qcg_freq_edge{false};
	bool qcg_freq_retire{false};
	bool qcg_freq_entry{false};
	bool sr_edges_epochs{false};
	bool sr_web_repack{false};
	bool qcg_leaf_inline{false};
	bool qcg_jal_closure{false};
	bool qcg_ic_lasttarget{false};
	bool sr_record_returns{false};
	std::string qcg_ic_edges_out{};
	std::string qcg_freq_shadow_out{};
	bool sr_descent{true};
	bool sr_census{true};
	bool sr_ablate_realized{};
	bool sr_ablate_promote{};
	bool sr_ablate_updprof{};
	bool sr_ablate_regime_reset_parent{};
	bool sr_ablate_regime_reset_builder{};
	bool sr_realized_pend_check{};
	bool sr_census_flip_check{};
	long long sr_oracle_flip_at_ms{};
	bool sr_unconditional_poll{};
	bool rvv_qcg_whole_reg{};
	bool rvv_qcg_vx_mulacc{};
	bool rvv_qcg_vx_mulacc_force_emit{};
	bool rvv_qcg_typed_chunk_vmv{};
	bool rvv_qcg_typed_chunk_vmv_force_emit{};
	bool rvv_qcg_typed_chunk_vadd_scalar{};
	bool rvv_qcg_typed_chunk_vadd_scalar_force_emit{};
	bool rvv_qcg_partial_vl{};
	bool rvv_qcg_fp_shared_mask{}; // A12
	bool rvv_qcg_active_vl_bound{}; // S1-2A
	bool rvv_qcg_active_vl_mask_fusion{};
	bool rvv_qcg_active_vl_int_bound{}; // S1-3A
	bool rvv_qcg_active_mask_memory{};
	bool rvv_qcg_active_vl_narrow_bound{true}; // W28 ablation control, default ON
	bool rvv_qcg_active_vl_widen_bound{}; // S1-3W
	bool rvv_qcg_full_vl_fast_body{}; // G11-A
	bool rvv_qcg_typed_chunk_mem_e64{}; // A13
	bool inrun_escape_unlink{};
	bool qcg_backedge_safepoint{};
	bool aot_loop_entry{};
	bool loop_tier{}; // T5d2a
	bool loop_tier_side_exit{}; // T5d2a3
	bool loop_tier_completion_exit{}; // T5d2b0
	bool loop_tier_load{}; // T5d2b1
	bool loop_tier_install{};
	bool loop_tier_exit_cancel{true}; // 2026-09-17 exit-cancel
	bool loop_tier_route_census{}; // C5c: promotion-route census, read-only diagnostic
	std::string loop_tier_elfaot{}, loop_tier_elf{}, loop_tier_stage{};
	bool sr_activation_invariant{};
	bool sr_cf_no_override{};
	bool sr_cf_no_regime{};
	bool sr_cf_no_wake{};
	bool sr_cf_no_reboot{};
	bool sr_cf_once{};
	int sr_cf_site{};
	unsigned long sr_cf_reset_gap_us{1};
	bool dvet_enable{};
	bool esc_contra{true};
	long sr_chunk_threshold{262144};
	std::string escalate_elfaot{}, escalate_cache{}, escalate_elf{};
	bool p1_promote{};
	std::string p1_staging{}, p1_elf{}, p1_elfaot{};
	int p1_flush_ms{50};
	unsigned long long p1_threshold{262144};
};

static std::pair<std::span<char *>, std::span<char *>> SplitArgs(unsigned argc, char **argv)
{
	std::span<char *> args{argv, argc};

	std::optional<unsigned> split_pos;
	for (int i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "--")) {
			split_pos = i;
			break;
		}
	}
	if (!split_pos.has_value()) {
		return {args, {}};
	}

	auto dbt_args = args.subspan(0, split_pos.value());
	auto guest_args = args.subspan(dbt_args.size() + 1);
	return {dbt_args, guest_args};
}

static void PrintHelp(bpo::options_description &adesc)
{
	std::cout << "usage: [options] -- [guest argv]\n";
	std::cout << adesc << "\n";
}

static bool ParseOptions(ElfRunOptions &o, int argc, char **argv)
{
	assert(argc > 0);
	auto [dbt_args, guest_args] = SplitArgs(static_cast<unsigned>(argc), argv);
	o.guest_args = guest_args;

	bpo::options_description adesc("options");
	// clang-format off
	adesc.add_options()
	    ("rvv-qcg-active-vl-mask-fusion", bpo::value(&o.rvv_qcg_active_vl_mask_fusion)->default_value(false), "Fuse adjacent active-suffix and FP lane-mask checks without duplicating the frame")
	    ("rvv-qcg-active-mask-memory", bpo::value(&o.rvv_qcg_active_mask_memory)->default_value(false), "Enumerate enabled mask bits for native QCG vector memory; preserve element order and restart state")
	    ("rvv-run-bounded-batches", bpo::value(&o.rvv_run_bounded_batches)->default_value(false), "Resource-bounded batches for lane-local FP vector runs; preserve member order within each batch and recycle shared masks")
	    ("help",   "help")
	    ("logs",   bpo::value(&o.logs)->default_value(""), "enabled log streams separated by :")
	    ("fsroot", bpo::value(&o.fsroot)->required(), "isolated path for emulated process")
	    ("cache",  bpo::value(&o.cache)->required(), "dbt cache path")
	    ("aot",    bpo::value(&o.use_aot)->default_value(false), "boot aot file if available")
	    ("merge-ls", bpo::value(&o.merge_ls)->default_value(false), "merge load/store instructions")
	    ("trace", bpo::value(&o.trace)->default_value(false), "enable trace cache")
	    ("not-freq", bpo::value(&o.not_freq)->default_value(false), "disable frequency tracking")
	    ("no-tb-clip", bpo::value(&o.no_tb_clip)->default_value(false), "H4 probe: translate through existing TB ranges (drop LookupUpperBound clip)")
	    ("tb-through-brind", bpo::value(&o.tb_through_brind)->default_value(false), "H1pp: translate through ONLY brind-target TBs (source-conditioned partition)")
	    ("code-pad", bpo::value(&o.code_pad)->default_value(0u), "layout control: dead padding bytes at code_pool start")
	    ("count-brind", bpo::value(&o.count_brind)->default_value(false), "count indirect-dispatch slowpath hits (mechanism)")
	    ("dump-region-hits", bpo::value(&o.dump_region_hits)->default_value(false), "2026-07-28: dump nonzero CPUState::region_entry_hits[] slots at exit (join with elfaot's --aot-region-hit-map-out)")
	    ("aot-region-hit-count", bpo::value(&o.aot_region_hit_count)->default_value(false), "T3b: ask every artifact this process builds in-run to emit CPUState::region_entry_hits[slot]++ at each admitted region entry. The flag is carried to the child elfaot by kRvvRouteContract, which renders THIS process's value -- so without this option elfrun could only ever send 0 and a mid-run-promoted artifact could be shown to have loaded but never to have been ENTERED. Pair with --dump-region-hits to read the slots back at exit. Default off")
	    ("aot-count-gbrind", bpo::value(&o.aot_count_gbrind)->default_value(false), "A-line round 18: print AOT_GBRIND_COUNT at exit (the counter itself is compiled in by elfaot's --aot-count-gbrind=1; this flag only controls whether elfrun reads and prints it -- zero effect on codegen).")
	    ("aot-link-multientry-trace", bpo::value(&o.aot_link_multientry_trace)->default_value(false), "Design 8 multi-entry diagnostic: print CPUState dbg_multientry_switch_hits/default_hits/wrapper_calls at exit")
	    ("qcg-resident", bpo::value(&o.qcg_resident)->default_value(false), "2026-06-21 QCG cross-block guest-register residency: keep guest regs in host regs across single-pred intra-region edges (sync to mem, reset only at merges/region-exit)")
	    ("qcg-pin", bpo::value(&o.qcg_pin)->default_value(false), "2026-06-21 QCG loop register pinning: reserve K host regs for the K most-used guest regs in call-free backedge regions (resident whole-region)")
	    ("qcg-pin-k", bpo::value(&o.qcg_pin_k)->default_value(0), "number of guest registers to pin per loop region (with --qcg-pin)")
	    ("brind-edges-out", bpo::value(&o.brind_edges_out)->default_value(""), "Round-15 DIA: record indirect src->dst edges during this (profiling) run and dump to this path")
	    ("sr-live-edges-dump", bpo::value(&o.sr_live_edges_dump)->default_value(false), "B-line: also call brindedges::Dump() periodically mid-run (not just at exit), from the existing EvaluateAndMaybeEscalate host-stack call site -- requires --brind-edges-out")
	    ("sr-cheap-edges-out", bpo::value(&o.sr_cheap_edges_out)->default_value(""), "2026-07-22: sets the live-edges-dump output path WITHOUT forcing profile_brind_edges (unlike --brind-edges-out, no exhaustive slowpath-forcing) -- pair with --sr-sampled-edges=1 and --sr-live-edges-dump=1 for a cheap live observer")
	    ("sr-bounded-exhaustive", bpo::value(&o.sr_bounded_exhaustive)->default_value(0), "A-line 2026-07-27: caps --brind-edges-out's exhaustive recording to the first N dispatches (0 = unlimited); reverts to normal l1-cached dispatch after N, bounding the exhaustive collector's cost")
	    ("sr-revoke-watch", bpo::value(&o.sr_revoke_watch)->default_value(""), "B-line B2: path to poll (same host-stack call site as sr-live-edges-dump) for a pending real single-target revoke request written by an external controller -- applies tcache::RevokeTarget()")
	    ("selfprof-out", bpo::value(&o.selfprof_out)->default_value(""), "Round-26: SIGPROF self-sampling host-IP profile (1ms ITIMER_PROF); resolves against the tbmap for per-region QCG time attribution -- no perf permissions needed")
	    ("dispatch-selfprof-out", bpo::value(&o.dispatch_selfprof_out)->default_value(""), "A-line Round 40: separate, independent SIGPROF sampler (same 1ms ITIMER_PROF substrate as --selfprof-out, own buffer/handler, does not change --selfprof-out's existing output format) that ALSO records the host RAX register at each sample -- the L1-cache-hit fastpath's indirect jump (`jmp *rax`, confirmed via perf annotate across every workload examined this session) uses RAX as its target register, so (RIP,RAX) samples give a cheap, in-process, hardware-relevant estimate of dispatch-target distribution at hot gbrind sites, decoupled from the SOFTWARE L1 cache's own (separately shown uninformative) hit/miss behavior. Runs during the SAME mandatory profiling pass every deployment already needs -- no separate forced-slowpath recording, no L1 cache disabling.")
	    ("phase-windows-out", bpo::value(&o.phase_windows_out)->default_value(""), "2026-06-21 EXEC-PHASE: deterministically window the run by guest instruction count; dump per-window hot-TB set (ip:exec) to this path. Requires --phase-window-insns.")
	    ("phase-window-insns", bpo::value(&o.phase_window_insns)->default_value(0), "2026-06-21 EXEC-PHASE: window size in guest instructions for --phase-windows-out")
	    ("phase-window-max", bpo::value(&o.phase_window_max)->default_value(0), "2026-06-21 EXEC-PHASE: cap -- stop guest + dump after N windows (0 = run to completion)")
	    ("dump-tbmap", bpo::value(&o.dump_tbmap)->default_value(""), "Round-26: dump guest_ip -> host QCG code range map at exit (perf attribution)")
	    ("dump-tbcode", bpo::value(&o.dump_tbcode)->default_value(""), "A-line Round 61: hex-dump each QCG TB's raw generated machine code bytes at exit, for offline disassembly classification (direct vs indirect terminator register-allocation comparison)")
	    ("aot-reuse", bpo::value(&o.aot_reuse)->default_value(""), "2026-06-19 AARS: ALSO boot this OTHER binary's .aot.so by gip (cross-program AOT reuse). Matching gips serve AOT; rest fall back to QCG. Use with --aot=1 or without this binary's own artifact.")
	    ("aot-reuse-elf", bpo::value(&o.aot_reuse_elf)->default_value(""), "2026-06-19 AARS: the ELF the --aot-reuse artifact was built from; enables the per-region BYTE-IDENTITY filter (serve reuse AOT only where the current binary's region bytes match -> correct by construction).")
	    ("load-values-out", bpo::value(&o.load_values_out)->default_value(""), "Family-A: record per-load-PC value stability during interpreted (tier-0) samples; dump CSV at exit")
	    ("wmax-sample-out", bpo::value(&o.wmax_sample_out)->default_value(""), "Round-23: deployment-form W_max sampler -- 50ms SIGALRM samples the brind slowpath visit counter under keeper-like (dirty-list re-poison) channel conditions; dump per-window visit counts to this path")
	    ("tier-census", bpo::value(&o.tier_census)->default_value(false), "R47: print QCG_EXEC/AOT_EXEC tier census at exit (runtime drift signal: QCG_EXEC mass high => admission profile mismatches input); no execution change")
	    ("qcg-code-bytes", bpo::value(&o.qcg_code_bytes)->default_value(false), "T4: print QCG_CODE_BYTES at exit -- the summed host machine-code size, in bytes, of the QCG code this process generated (sum of tb->tcode.size over non-AOT TBs), with the QCG and AOT translation-block counts beside it. --tier-census reports block COUNTS, which are not a code size; --dump-tbcode reports the bytes but writes every block to a file at exit and charges that I/O to the run's wall clock, so neither is usable for a per-row timed measurement. One map walk on the exit path: no execution path, no emitted byte and no pinned disassembly golden changes. Default off")
	    ("measure-translation", bpo::value(&o.measure_translation)->default_value(false), "2026-06-16: time JIT-translation (CompilerDoJob) vs execution; prints TRANSLATE_NS/TRANSLATE_COUNT at exit (single-run cost decomposition)")
	    ("translate-ip-out", bpo::value(&o.translate_ip_out)->default_value(""), "2026-07-28: with --measure-translation, dump each JIT-translated target's guest ip (one per line) for set-correspondence proof")
	    ("ngr", bpo::value(&o.ngr)->default_value(false), "2026-06-23 NGR: reuse a QCG translation across structurally-identical blocks differing only in immediates (copy host code + patch immediate bytes instead of re-translating)")
	    ("ngr-verify", bpo::value(&o.ngr_verify)->default_value(false), "NGR: re-translate + byte-compare each reuse (correctness check; defeats the speedup)")
	    ("ngr-loops", bpo::value(&o.ngr_loops)->default_value(false), "NGR RESEARCH: enable heuristic loop/branch (R_ADDR) reuse; gen-code-scoped but has residual false positives (antlr4); pair with --ngr-verify. Default NGR is straight-line-only.")
	    ("fast-boot", bpo::value(&o.fast_boot)->default_value(false), "skip the redundant boot fill of the 4M-entry L1 caches (~160MB); rely on BSS zero + lazy commit. Behavior-preserving; cuts rvdbt fixed startup.")
	    ("qcg-code-huge-pages", bpo::value(&o.qcg_code_huge_pages)->default_value(false), "align the QCG code cache and request transparent huge pages; normal pages remain the fallback")
	    ("vlen", bpo::value(&o.vlen)->default_value(128), "RVV guest VLEN in bits (power of two in [128,4096]). One guest binary runs at any legal VLEN. NOTE: QEMU, the external differential oracle, only implements [128,1024], so 2048 and 4096 are checked against this substrate's own reference lowering and cross-VLEN output identity instead.")
	    ("rvv-lowering", bpo::value(&o.rvv_lowering)->default_value(1), "RVV execution path: 0 = scalar element-at-a-time reference (oracle/fallback), 1 = width-parametric fixed-width host chunks (SSE2/128-bit here)")
	    ("rvv-verify", bpo::value(&o.rvv_verify)->default_value(false), "run BOTH RVV paths on every vector op and abort on the first disagreement (correctness mode; defeats the point of the fixed-width path)")
	    ("rvv-stats", bpo::value(&o.rvv_stats)->default_value(false), "print RVV chunk/tail/fallback/verify counters at exit")
	    ("rvv-route-census", bpo::value(&o.rvv_route_census)->default_value(false), "T3a: count, PER GUEST OPCODE, every execution of a vector instruction that ran in the C++ handler instead of as emitted host code -- reached either through the JIT stub call on a guard miss or through the interpreter. Prints one RVV_ROUTE line per opcode at exit. Exists because CPUState::rvv_direct_hits and rvv_direct_fallbacks are aggregate over all typed frames and cannot say WHICH opcode fell back, and because vsub/vand/vor/vxor share the single rv32_vialu helper so per-stub counting cannot separate them either. Classification is from the guest encoding (funct3/funct6), not from a handler name. Changes nothing in emitted code, so pinned disassembly goldens are byte-identical either way. Default off")
	    ("rvv-run-unroll2", bpo::value(&o.rvv_run_unroll2)->default_value(false), "P14 G7: emit two host chunks per run-loop iteration straight-line, so the second chunk issues without an intervening loop back-edge. Same arithmetic, same results -- the A/B control for the VLEN1024 IPC gap")
	    ("rvv-run-hoist", bpo::value(&o.rvv_run_hoist)->default_value(false), "P14: hoist the opcode dispatch out of the per-chunk run loop so each chunk's body is straight-line. Same arithmetic, same results -- the A/B control for docs/T3_TRANSFER_GAP.md")
	    ("rvv-direct", bpo::value(&o.rvv_direct)->default_value(true), "enable implemented direct RVV QCG routes; unsupported host features or runtime shapes use their semantic fallback. 0 disables these direct QCG routes")
	    ("rvv-qcg-diag-chunk", bpo::value(&o.rvv_qcg_diag_chunk)->default_value(false), "DIAGNOSTIC CONTROL ARM, not the method: emit the admitted vadd.vv form (LMUL=1, unmasked, vstart=0, vl=VLMAX, VLEN 512/1024) as one untyped side-effect QIR node per 512-bit host chunk, each into a hardcoded ZMM. No QIR vector value, no def-use, no register allocation; data still round-trips through CPUState. Requires --rvv-direct 1. Default off")
	    ("rvv-qcg-diag-chunk-force-emit", bpo::value(&o.rvv_qcg_diag_chunk_force_emit)->default_value(false), "AUDIT ONLY: bypass the host AVX-512 feature test so the emitted chunk shape can be disassembled on a host that cannot execute it. Such code will SIGILL if run. Does not relax the architectural guard")
    ("aot-use-llvm", bpo::value(&o.aot_use_llvm)->default_value(true), "use the LLVM backend where applicable (mirrors elfaot --llvm). Set 0 for pure QCG; the RVV chunk lowerings admit only in that mode")
    ("rvv-qcg-typed-chunk", bpo::value(&o.rvv_qcg_typed_chunk)->default_value(true), "common direct RVV QCG lowering for implemented integer, floating-point, mask, permutation, reduction and memory families; requires rvv-direct and pure QCG. Architectural/host guards remain active; this is not a guarantee that every operation avoids fallback. Individual family switches can enable isolated legacy routes when this common switch is off")
    ("rvv-qcg-typed-chunk-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_force_emit)->default_value(false), "AUDIT ONLY: bypass the host AVX-512 feature test for the typed path so its emitted shape can be disassembled on a host that cannot execute it. Such code will SIGILL if run. Does not relax the architectural guard")
    ("rvv-qcg-typed-chunk-mul", bpo::value(&o.rvv_qcg_typed_chunk_mul)->default_value(false), "P3.5a TYPED chunk lowering for the one admitted vmul.vv case (VLEN=512/1024, SEW=32, LMUL=1, unmasked, vstart=0, vl=VLMAX): vstatechunkload/vchunkmul/vstatechunkstore with real def-use and QRegAlloc-assigned ZMMs, in pure QCG, emitting vpmulld. Own switch, independent of --rvv-qcg-typed-chunk. Guarded at run time on vtype/vl/vstart; ANY mismatch runs the existing rv32_vimul helper unchanged. Requires --rvv-direct 1. Default off")
    ("rvv-qcg-typed-chunk-mul-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_mul_force_emit)->default_value(false), "AUDIT ONLY: bypass the host AVX-512F feature test for the vmul.vv typed path so its emitted shape can be disassembled on a host that cannot execute it. Such code will SIGILL if run. Does not relax the architectural guard")
    ("rvv-qcg-typed-chunk-sub", bpo::value(&o.rvv_qcg_typed_chunk_sub)->default_value(false), "S2.1/S3.10a TYPED chunk lowering for the one admitted vsub.vv case (VLEN=512/1024, SEW=32, LMUL=1, unmasked, vstart=0, vl=VLMAX): vstatechunkload/vchunksub/vstatechunkstore. In pure QCG (--aot-use-llvm 0) that is real def-use and QRegAlloc-assigned ZMMs emitting vpsubd; with --aot-use-llvm 1 AND --rvv-vector-ssa the SAME admitted shape takes the S3.10a LLVM route instead, emitting `sub <16 x i32>` per 512-bit chunk. Exactly one of the two arms can admit for a given compile, so this is a backend selection and not a widening. Own switch, independent of --rvv-qcg-typed-chunk and --rvv-qcg-typed-chunk-mul. Guarded at run time on vtype/vl/vstart (the LLVM arm also checks vlenb); ANY mismatch runs the existing rv32_vialu helper unchanged. Requires --rvv-direct 1. Default off")
    ("rvv-qcg-typed-chunk-sub-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_sub_force_emit)->default_value(false), "AUDIT ONLY: bypass the host AVX-512F feature test for the vsub.vv typed path so its emitted shape can be disassembled on a host that cannot execute it. Such code will SIGILL if run. Does not relax the architectural guard")
    ("rvv-qcg-typed-chunk-xor", bpo::value(&o.rvv_qcg_typed_chunk_xor)->default_value(false), "S2.2/T1d TYPED chunk lowering for the one admitted vxor.vv case (VLEN=512/1024, SEW=32, LMUL=1, unmasked, vstart=0, vl=VLMAX): vstatechunkload/vchunkxor/vstatechunkstore. In pure QCG (--aot-use-llvm 0) that is real def-use and QRegAlloc-assigned ZMMs emitting vpxord; with --aot-use-llvm 1 AND --rvv-vector-ssa the SAME admitted shape takes the T1d LLVM route instead, emitting `xor <16 x i32>` per 512-bit chunk. Exactly one of the two arms can admit for a given compile, so this is a backend selection and not a widening. Own switch, independent of --rvv-qcg-typed-chunk, --rvv-qcg-typed-chunk-mul, --rvv-qcg-typed-chunk-sub and --rvv-qcg-typed-chunk-or. Neither its remaining family sibling vand.vv nor the separately-switched vor.vv is affected by this switch; both keep the helper unless their own switch is on, and NEITHER has an LLVM route at all. Guarded at run time on vtype/vl/vstart (the LLVM arm also checks vlenb); ANY mismatch runs the existing rv32_vialu helper unchanged. Requires --rvv-direct 1. Default off")
	    ("rvv-qcg-typed-chunk-shift", bpo::value(&o.rvv_qcg_typed_chunk_shift)->default_value(false), "P7N-B: typed QCG chunk lowering for exact unmasked vsll.vi/vsrl.vi (the RVV logical shift-immediate forms), plus their vector-run member rows. Default off. ONE switch covers both because a rotate needs both; vsra is out of scope. Chunk geometry is width-correct -- min(VLEN/8,64) bytes per chunk, VLEN/bytes chunks -- so VLEN 128/256/512/1024 give one xmm, one ymm, one zmm and two zmm chunks. Masked forms, the .vv/.vx forms and vsra keep the rv32_vialu helper.")
	    ("rvv-qcg-typed-chunk-shift-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_shift_force_emit)->default_value(false), "AUDIT ONLY: bypass the AVX-512F/VL host probes for the shift route so emitted bytes can be inspected on a host that cannot execute them. Never set this on an arm that runs the code.")
	    ("rvv-run-frame-census", bpo::value(&o.rvv_run_frame_census)->default_value(false), "P7M-E DIAGNOSTIC, not a lowering: give every emitted MULTI-member vector-run frame a stable identity (region entry guest PC, emission index within that translation, static member count, host components per guest vector register k) and make that frame's fast-arm join increment its own 64-bit counter, then print one `RVV_RUN_FRAME` CSV row per frame at exit. Answers the question neither existing counter can: `RVV_RUN members_admitted` is a TRANSLATION-time formation count and `RVV_DIRECT inline_hits` is one global `inc` at the join of EVERY typed frame, so neither says how often an admitted multi-member run actually executed or in which TB. Guard MISSES are not counted -- the fallback arm never crosses the join, and `guard_fallbacks` already counts it. Changes no admission, no member order, no body, no live splitting and no existing counter's meaning; single-member runs are deliberately not registered. ARMING IT CHANGES EMITTED BYTES (two instructions per multi-member frame execution), so it must NEVER be set on an arm that is being timed. Requires --rvv-vector-run=1 and pure QCG (--aot-use-llvm 0). Default off")
	    ("rvv-run-live-range-split", bpo::value(&o.rvv_run_live_range_split)->default_value(false), "P7N-G: manage the vector run's SSA body residency per host chunk component with exact next-use information instead of loading every live-in at frame entry and storing every live-out at the end. A live-in chunk is loaded at its FIRST use, a component whose last use has passed is released, and ONLY when the resident set would exceed the QCG vector pool is a live range split -- dead components first, then the farthest next use, materialized to its OWN existing CPUState slot and reloaded on demand. Members stay in guest order with the chunk loop inside, so low/high sibling chunks are still issued adjacently; combining this with --rvv-run-order=chunk is refused. Changes NO allocator limit and adds no helper. Requires --rvv-run-body=ssa. Default off")
	    ("rvv-run-split-value-weighted", bpo::value(&o.rvv_run_split_value_weighted)->default_value(false), "P7N-J experimental residency surrogate INSIDE the live-range-splitting SSA body, from CHACHA20_LIVE_SPLIT_OPTIMALITY_AND_MEMORY_FOLDING.md. 0 (default) keeps the shipped P7N-G rules exactly -- same decisions, same nodes, same host bytes. 1 applies two structural repairs together, neither of which reads a workload constant, a guest PC or a threshold: (D1) next-use becomes VALUE-aware, i.e. the scan stops at the next DEFINITION of the register, so a component whose value a later member overwrites before any read is recognised as dead -- released with NO store when a later definition will re-establish the slot, and stored NOW when it is that component's FINAL value, since that store is owed at the close anyway; (D2) the eviction victim is ranked by COST CLASS first -- clean, final-value and dead-and-later-redefined components all cost one reload and no store, a dirty non-final value costs a store as well -- and by farthest next use only within a class. Same members, same member-major order, same lane operations, same CPUState slots, same pool, same admission decision; only WHICH component is evicted and WHETHER its store is emitted change. It is a greedy surrogate for an exact min-cost planner and claims no global optimality. Requires --rvv-run-live-range-split=1 (and so --rvv-vector-run=1, --rvv-run-body=ssa, --rvv-run-order=member); refused otherwise. Default off")
	    ("rvv-qcg-narrow-chunk-width", bpo::value(&o.rvv_qcg_narrow_chunk_width)->default_value(false), "P7N-D: derive the host chunk geometry from VLEN -- width min(VLEN/8,64) bytes, count (VLEN/8)/width -- instead of requiring a whole number of 512-bit chunks, for the vxor.vv, vor.vv, vse32.v and vsetvli routes. So VLEN 128/256/512/1024 lower to one xmm, one ymm, one zmm and two zmm chunks on ONE route instead of falling to the helper below 512. At every VLEN >= 512 it returns exactly the shape the old rule returned, so it can only change VLEN 128/256. Pure QCG only (the LLVM/AOT backend keeps the whole-512 rule at every width). vsub.vv/vmul.vv/vand.vv/vle32.v are deliberately NOT reached and keep their helper below VLEN 512. Unsupported SEW/LMUL/masked/tail forms keep their existing fail-closed helper fallback unchanged. Requires --rvv-direct 1. Default off")
	    ("rvv-qcg-narrow-chunk-width-force-emit", bpo::value(&o.rvv_qcg_narrow_chunk_width_force_emit)->default_value(false), "AUDIT ONLY: bypass the AVX512VL host probe the narrow (xmm/ymm) chunk forms carry, so emitted bytes can be inspected on a host that cannot execute them. Never set this on an arm that runs the code.")
    ("rvv-qcg-typed-chunk-xor-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_xor_force_emit)->default_value(false), "AUDIT ONLY: bypass the host AVX-512F feature test for the vxor.vv typed path so its emitted shape can be disassembled on a host that cannot execute it. Such code will SIGILL if run. Does not relax the architectural guard")
    ("rvv-qcg-typed-chunk-or", bpo::value(&o.rvv_qcg_typed_chunk_or)->default_value(false), "S2.3/T1e TYPED chunk lowering for the one admitted vor.vv case (VLEN=512/1024, SEW=32, LMUL=1, unmasked, vstart=0, vl=VLMAX): vstatechunkload/vchunkor/vstatechunkstore. In pure QCG (--aot-use-llvm 0) that is real def-use and QRegAlloc-assigned ZMMs emitting vpord; with --aot-use-llvm 1 AND --rvv-vector-ssa the SAME admitted shape takes the T1e LLVM route instead, emitting `or <16 x i32>` per 512-bit chunk. Exactly one of the two arms can admit for a given compile, so this is a backend selection and not a widening. Own switch, independent of --rvv-qcg-typed-chunk, --rvv-qcg-typed-chunk-mul, --rvv-qcg-typed-chunk-sub and --rvv-qcg-typed-chunk-xor. Its funct6 sibling vand.vv is NOT affected by this switch and keeps the helper unless --rvv-qcg-typed-chunk-and is also on, and this switch does not change what --rvv-qcg-typed-chunk-xor does to vxor.vv. Guarded at run time on vtype/vl/vstart; ANY mismatch runs the existing rv32_vialu helper unchanged. Requires --rvv-direct 1. Default off")
    ("rvv-qcg-typed-chunk-or-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_or_force_emit)->default_value(false), "AUDIT ONLY: bypass the host AVX-512F feature test for the vor.vv typed path so its emitted shape can be disassembled on a host that cannot execute it. Such code will SIGILL if run. Does not relax the architectural guard")
    ("rvv-qcg-typed-chunk-and", bpo::value(&o.rvv_qcg_typed_chunk_and)->default_value(false), "S2.4/T1f TYPED chunk lowering for the one admitted vand.vv case (VLEN=512/1024, SEW=32, LMUL=1, unmasked, vstart=0, vl=VLMAX): vstatechunkload/vchunkand/vstatechunkstore. In pure QCG (--aot-use-llvm 0) that is real def-use and QRegAlloc-assigned ZMMs emitting vpandd; with --aot-use-llvm 1 AND --rvv-vector-ssa the SAME admitted shape takes the T1f LLVM route instead, emitting `and <16 x i32>` per 512-bit chunk. Exactly one of the two arms can admit for a given compile, so this is a backend selection and not a widening. Own switch, independent of --rvv-qcg-typed-chunk, --rvv-qcg-typed-chunk-mul, --rvv-qcg-typed-chunk-sub, --rvv-qcg-typed-chunk-xor and --rvv-qcg-typed-chunk-or. It does not change what those switches do to their own opcodes: vor.vv and vxor.vv keep their own routes and their own vpord/vpxord, and the funct6-identical OPMVV vaadd.vv is untouched. Guarded at run time on vtype/vl/vstart; ANY mismatch runs the existing rv32_vialu helper unchanged. Requires --rvv-direct 1. Default off")
    ("rvv-qcg-typed-chunk-and-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_and_force_emit)->default_value(false), "AUDIT ONLY: bypass the host AVX-512F feature test for the vand.vv typed path so its emitted shape can be disassembled on a host that cannot execute it. Such code will SIGILL if run. Does not relax the architectural guard")
    ("rvv-qcg-typed-chunk-falu", bpo::value(&o.rvv_qcg_typed_chunk_falu)->default_value(false), "T7R direct typed-QIR/QCG lowering for the dynamically observed unmasked e32/e64,ta,ma vfadd/vfsub/vfmul/vfdiv/vfrdiv forms; exact runtime vtype/vl/vstart/frm guard and helper fallback. P7E: an OBSERVED vtype admits LMUL 1 or 2; a block with no vsetvli observation still proposes m2")
    ("rvv-qcg-typed-chunk-falu-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_falu_force_emit)->default_value(false), "AUDIT ONLY: bypass T7R AVX-512F/BMI2 host feature admission")
    ("rvv-qcg-typed-chunk-fma", bpo::value(&o.rvv_qcg_typed_chunk_fma)->default_value(false), "P7I direct fused typed-QIR/QCG lowering for the dynamically observed unmasked e32/e64,ta,ma OPFVF vfmadd.vf/vfnmsub.vf forms at LMUL 1 or 2; requires an OBSERVED vtype, an AVX-512F+FMA3 host, and passes the same exact runtime vtype/vl/vstart/frm guard with rv32_vfma helper fallback")
    ("rvv-qcg-typed-chunk-fma-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_fma_force_emit)->default_value(false), "AUDIT ONLY: bypass the P7I AVX-512F+FMA3/BMI2 host feature admission. Emitted code SIGILLs on a host lacking them; never valid for a measurement arm")
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
    ("rvv-qcg-typed-chunk-fsqrt", bpo::value(&o.rvv_qcg_typed_chunk_fsqrt)->default_value(false), "P8 direct typed-QIR/QCG lowering for vfsqrt.v at an OBSERVED unmasked e32/e64,ta,ma vtype with integer LMUL 1/2/4/8; emits vsqrtps/vsqrtpd (the correctly-rounded IEEE square root, never a reciprocal estimate), requires an AVX-512F+BMI2 host and vl == VLMAX, and passes the same runtime vtype/vl/vstart/frm guard with rv32_vfunary1 helper fallback")
    ("rvv-qcg-typed-chunk-fsqrt-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_fsqrt_force_emit)->default_value(false), "AUDIT ONLY: bypass the P8 AVX-512F/BMI2 host feature admission. Emitted code SIGILLs on a host lacking them; never valid for a measurement arm")
    ("rvv-qcg-typed-chunk-fcmp", bpo::value(&o.rvv_qcg_typed_chunk_fcmp)->default_value(false), "P9 direct typed-QIR/QCG lowering for the FP compare family vmfeq/vmfne/vmflt/vmfle (.vv and .vf) and vmfgt/vmfge (.vf) at an OBSERVED unmasked e32/e64 vtype with integer LMUL 1/2/4/8; emits masked EVEX vcmpp{s,d} with the quiet predicates for eq/ne and the signalling ones for the ordered compares, deposits the mask bits with a read-modify-write so masked-off and tail bits stay undisturbed, requires an AVX-512F+BMI2 host and a destination disjoint from the sources, and passes the same runtime vtype/vl/vstart guard with rv32_vfcmp helper fallback")
    ("rvv-qcg-typed-chunk-fcmp-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_fcmp_force_emit)->default_value(false), "AUDIT ONLY: bypass the P9 AVX-512F/BMI2 host feature admission. Emitted code SIGILLs on a host lacking them; never valid for a measurement arm")
    ("rvv-qcg-typed-chunk-fwiden", bpo::value(&o.rvv_qcg_typed_chunk_fwiden)->default_value(false), "P10 direct typed-QIR/QCG lowering for the widening FP family vfwadd/vfwsub (.vv .vf .wv .wf) and vfwmul (.vv .vf), e32 -> e64 only (2*SEW must fit ELEN 64, so LMUL 8 and SEW 64 are illegal encodings rather than refusals), at an OBSERVED e32 vtype with any tail/mask policy and LMUL mf2/1/2/4, masked or unmasked; widens each narrow operand exactly with a masked vcvtps2pd and then performs ONE wide operation through the existing vchunkfalu, requires an AVX-512F+BMI2 host (plus AVX512VL below a 64-byte chunk) and a destination group whose overlap with a source is one RVV 1.0 5.2 permits, and passes the same runtime vtype/vl/vstart/frm guard with rv32_vfwarith helper fallback")
    ("rvv-qcg-typed-chunk-fwiden-fma", bpo::value(&o.rvv_qcg_typed_chunk_fwiden_fma)->default_value(false), "P10b direct typed-QIR/QCG lowering for the WIDENING FMA family vfwmacc/vfwnmacc/vfwmsac/vfwnmsac (.vv .vf), e32 -> e64, on the same frame, guard, source conversion and admitted vtype set as --rvv-qcg-typed-chunk-fwiden (which it does NOT require): it adds a load of the old vd -- the addend, so vd is read before it is written -- and performs the multiply-add in ONE fused host instruction through the existing vchunkfma node, never a multiply node plus an add node. Needs FMA3 on top of AVX-512F+BMI2, and refuses an unobserved vtype for the same reason the narrow FMA route does. rv32_vfwarith helper fallback")
    ("rvv-qcg-typed-chunk-fwiden-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_fwiden_force_emit)->default_value(false), "AUDIT ONLY: bypass the P10/P10b AVX-512F/BMI2 (and, for the widening FMA forms, FMA3) host feature admission. Emitted code SIGILLs on a host lacking them; never valid for a measurement arm")
    ("rvv-qcg-typed-chunk-vle", bpo::value(&o.rvv_qcg_typed_chunk_vle)->default_value(false), "S2.6 TYPED chunk lowering for the one admitted vle32.v case (exact unmasked unit-stride, EEW=32 from the encoding, SEW=32/LMUL=1/EMUL=1 from vtype, VLEN=512/1024, vstart=0, vl=VLMAX, base register != x0): vchunkload/vstatechunkstore with real def-use and QRegAlloc-assigned ZMMs, in pure QCG, emitting one 64-byte vmovdqu64 pair per chunk. Own switch, independent of the six vadd/vmul/vsub/vxor/vor/vand chunk switches, and it does not change what they do to their own opcodes. Masked vle32.v, vle8/16/64.v, EMUL!=1, strided/indexed/fault-only-first/whole-register/segment loads and every vse form keep the unchanged rv32_vle / rv32_vse helper. Guarded at run time on vtype/vl/vstart; ANY mismatch runs the existing rv32_vle helper unchanged. Requires --rvv-direct 1 and a non-Ref --rvv-lowering. Default off")
    ("rvv-qcg-typed-chunk-vle-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_vle_force_emit)->default_value(false), "AUDIT ONLY: bypass the host AVX-512F feature test for the vle32.v typed path so its emitted shape can be disassembled on a host that cannot execute it. Such code will SIGILL if run. Does not relax the architectural guard")
    ("rvv-qcg-typed-chunk-vse", bpo::value(&o.rvv_qcg_typed_chunk_vse)->default_value(false), "S2.7 TYPED chunk lowering for the one admitted vse32.v case (exact unmasked unit-stride, EEW=32 from the encoding, SEW=32/LMUL=1/EMUL=1 from vtype, VLEN=512/1024, vstart=0, vl=VLMAX, base register != x0): vstatechunkload/vchunkstore with real def-use and QRegAlloc-assigned ZMMs, in pure QCG, emitting one 64-byte guest-memory vmovdqu64 per chunk. Own switch, independent of the six ALU chunk switches and of --rvv-qcg-typed-chunk-vle, and it does not change what any of them do to their own opcodes. Masked vse32.v, vse8/16/64.v, EMUL!=1, strided/indexed/whole-register/segment/mask stores and every vle form keep the unchanged rv32_vse / rv32_vle helper. Guarded at run time on vtype/vl/vstart; ANY mismatch runs the existing rv32_vse helper unchanged. Requires --rvv-direct 1 and a non-Ref --rvv-lowering. Default off")
    ("rvv-qcg-typed-chunk-vse-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_vse_force_emit)->default_value(false), "AUDIT ONLY: bypass the host AVX-512F feature test for the vse32.v typed path so its emitted shape can be disassembled on a host that cannot execute it. Such code will SIGILL if run. Does not relax the architectural guard")
    ("rvv-qcg-typed-chunk-vlse-gather", bpo::value(&o.rvv_qcg_typed_chunk_vlse_gather)->default_value(false), "Z3 (default off, PURE QCG): lower the STRIDED load `vlse32.v` (mop=10, EEW=32 from the encoding, unmasked, nf=1, VLEN>=512) to AVX-512 gather chunks instead of the per-element host loop the integer-family memory route already emits for it. This opcode is NOT a helper call today and this switch does not change its route, its frame or its VTypeInteger guard: it replaces ONE node's body and leaves the element loop in the same region as the body's own fallback. Per 64-byte chunk: the live vl/vstart lane mask, a lane-wise vpmulld/vpaddd that reproduces the loop's 32-bit imul/add bit for bit (so negative, zero and non-multiple-of-4 strides are exact), a signed compare that sends any ACTIVE lane above 0xFFFFFFFC back to the element loop BEFORE the chunk stores (RV32 wraps modulo 2^32; a gather would read past the 4 GiB reservation into rvdbt's own heap), one vpgatherdd with the guest base biased by 2^31 so the SIGNED VSIB index addresses the whole unsigned guest space, and one masked vmovdqu32 so inactive and tail elements stay undisturbed. A nonzero vstart also keeps the element loop, which is the restart-exact path; the accepted cost is that a host fault under this route reports restart index 0, which no guest can observe because rvdbt terminates on guest memory faults and delivers no signals. Every other strided load -- every other EEW, masked, segment, VLEN 128/256 -- and every other memory opcode keep byte-identical emitted code. Neither runtime exit increments guard_fallbacks. Requires --rvv-direct 1, --rvv-qcg-typed-chunk 1, a non-Ref --rvv-lowering, and a host with AVX-512F+BMI2. Own switch, independent of every sibling route. Default off")
    ("rvv-qcg-typed-chunk-vlse-gather-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_vlse_gather_force_emit)->default_value(false), "AUDIT ONLY: bypass the host AVX-512F/BMI2 feature test for the vlse32.v gather path so its emitted shape can be disassembled on a host that cannot execute it. Such code will SIGILL if run. Does not relax the architectural guard, does not widen the admitted shape, and does not remove the vstart or address-space-top runtime conditions")
    ("rvv-qcg-typed-chunk-vlse-gather-census", bpo::value(&o.rvv_qcg_typed_chunk_vlse_gather_census)->default_value(false), "Z4B DIAGNOSTIC (default off), not a lowering and not an admission change: make the vlse32.v AVX-512 gather body count its own two outcomes, and print them as one RVV_VLSE_GATHER line at exit. One `inc` at the fast path's completion join (every chunk gathered and stored) and one at the `scalar` label, which is the only edge into the retained element loop while the fast path is emitted, so it covers BOTH runtime exits -- the vstart!=0 precheck and every chunk's address-space-top guard -- together. This edge is internal to one node, so it crosses no frame fallback arm: `guard_fallbacks`, `RVV_DIRECT inline_hits` and `RVV_ROUTE handler_calls` are all blind to it, which is why Z4 could show the gather was EMITTED but had no direct count of whether it was TAKEN. ARMING IT CHANGES EMITTED BYTES (two instructions per admitted vlse32.v site), so it must NEVER be set on an arm that is being timed. With it off, and with --rvv-qcg-typed-chunk-vlse-gather either off or on, the emitted bytes are the pre-Z4B bytes exactly. Requires --rvv-qcg-typed-chunk-vlse-gather=1 to have anything to count. Default off")
    ("rvv-qcg-active-chunk-census", bpo::value(&o.rvv_qcg_active_chunk_census)->default_value(false), "P2a DIAGNOSTIC (default off), not a lowering, not an admission change and not a policy change: make every PLANNER-ELIGIBLE native QCG typed-chunk frame count its own host work units, and print them as one RVV_ACTIVE_CHUNKS line at exit. TWO DISTINCT QUANTITIES over executions of the frame's NATIVE fast body. chunks_available: the work units that frame would execute with active-suffix skipping OFF -- the unit count the common frame finalizer derived from the emitted QIR body, added once at the native join. chunks_executed: how many of those units were actually REACHED -- the frame's always-executed prefix (the units carrying no bound) added at the same join, plus one per `vchunkactive` bound that fell through. NEITHER IS A COUNT OF USEFUL WORK: with the active-VL policy switches off no frame carries a bound, every unit is reached, and executed == available by construction, tail units included. That equality is the switch-off invariant. THE POPULATION IS THE FINALIZER'S, NOT A LIST: a frame the common close classified ineligible (a vector run, a whole-register transfer, a memory or two-arm frame, a reduction, a cross-lane shape) carries a zero unit count and contributes nothing, and there is no opcode list, guest PC, workload case or VLEN threshold anywhere in the feature. The guard-miss arm contributes nothing either: both join-side adds sit after the fast-arm join label, which the fallback arm never crosses, so `guard_fallbacks` remains the separate count of the other arm. QCG only -- the LLVM/AOT backend emits no census. ARMING IT CHANGES EMITTED BYTES (four instructions at each native join, two after each bound), so it must NEVER be set on an arm that is being timed; with it off the emitted bytes are the pre-P2a bytes exactly. Default off")
    ("rvv-qcg-whole-reg", bpo::value(&o.rvv_qcg_whole_reg)->default_value(false), "Native-2 (default off): PURE-QCG direct lowering for the whole-register transfer pair vl<nf>re<eew>.v / vs<nf>r.v. Clang configures vl at VLMAX and therefore emits these for every strip-mined load and store, so on the QCG path they were the largest remaining helper population in a real vectorised workload. The frame is the existing vle/vse 512-bit chunk frame with a vtype-INDEPENDENT guard (vlenb == VLEN/8 && vstart == 0): RVV 1.0 defines these to move whole registers irrespective of SEW, LMUL and vl and to remain valid under vill, so guarding on vtype would make the route's coverage a property of the surrounding code rather than of the instruction. Chunk count and displacements are derived from nregs and the runtime VLEN. Illegal register groups, masked or non-whole-register encodings, a VLEN that is not a whole number of 16/32/64-byte host chunks (A17: 128/256 use xmm/ymm chunks), a host without AVX-512 (VL for the narrow chunks) and a nonzero vstart all keep the unchanged rv32_vlNre / rv32_vsNr helper. Requires pure QCG: the LLVM/AOT backend keeps its existing typed vector-SSA route for these opcodes, untouched. Default off")
    ("rvv-qcg-vx-mulacc", bpo::value(&o.rvv_qcg_vx_mulacc)->default_value(false), "Native-3 (default off): direct lowering for the SCALAR-operand integer multiply pair vmul.vx and vmacc.vx, unmasked, SEW=32/LMUL=1 from vtype, full VL -- in BOTH backends. In pure QCG (--aot-use-llvm 0) the frame is one vchunkbroadcast of the guest GPR the encoding names (vpbroadcastd from its CPUState slot) plus, per host chunk, vpmulld and for vmacc.vx vpaddd; the chunk width is the shared rule every sibling integer route uses (A21): 64-byte zmm chunks at VLEN >= 512, and with --rvv-qcg-narrow-chunk-width (AVX512VL) one 16-/32-byte xmm/ymm chunk at VLEN 128/256; with --aot-use-llvm 1 AND --rvv-vector-ssa the SAME encoding at VLEN 512/1024 only takes the LLVM route instead, emitting a splat plus mul <16 x i32> and add <16 x i32> per chunk. Exactly one of the two arms can admit for a given compile, so this is a backend selection and not a widening. vmacc.vx reads its destination, and the frame reads every source chunk -- including vd -- before writing any, so the accumulator read-before-write and the legal vd==vs2 overlap are both correct by construction at either width. The whole rest of the OPMVX/OPMVV multiply family keeps the unchanged rv32_vimul helper: vmulh/vmulhu/vmulhsu, vdivu/vdiv/vremu/vrem, vnmsac, vmadd, vnmsub, every .vv form, every masked form, other SEW, LMUL!=1 and fractional LMUL. Guarded at run time on vtype/vl/vstart; ANY mismatch -- including a partial vl or a nonzero vstart -- runs the existing rv32_vimul helper unchanged. Own switch, independent of every sibling route. Same switch name and same envelope as elfaot's. Requires --rvv-direct 1. Default off")
    ("rvv-qcg-typed-chunk-vmv", bpo::value(&o.rvv_qcg_typed_chunk_vmv)->default_value(false), "A2 (default off): pure-QCG direct lowering for vmv.v.x vd, rs1 (OPIVX, funct6 010111, vm=1): the typed-chunk guard, ONE vpbroadcastd of the guest GPR from its CPUState slot (rs1 == x0 splats 0) and one CPUState chunk store per host chunk into vd; width from the shared RvvRouteChunkShape rule, so VLEN 128/256/512/1024 -> xmm/ymm/zmm/2xzmm (128/256 need --rvv-qcg-narrow-chunk-width 1). SEW=32/LMUL=1/unmasked only; vmerge.vxm, vmv.v.v, vmv.v.i, other SEW, LMUL!=1 keep the rv32_vmerge helper. Guarded on vtype/vl/vstart; ANY mismatch (partial vl, nonzero vstart) runs the existing helper unchanged. Requires --rvv-direct 1. Default off")
    ("rvv-qcg-typed-chunk-mem-e64", bpo::value(&o.rvv_qcg_typed_chunk_mem_e64)->default_value(false), "A13 (default off, QCG only, needs --rvv-qcg-typed-chunk-vle/vse): admit unit-stride unmasked vle64.v/vse64.v at SEW=64 LMUL=1 (EMUL=1), vstart=0, vl=VLMAX through the same width-derived chunk frame as vle32.v/vse32.v at VLEN 128/256/512/1024 (the base-range guard base <= 2^32 - VLEN/8 is on every QCG unit-stride frame regardless of this switch; A13-FIX); out-of-range bases, partial/zero vl, masked, EEW!=SEW, LMUL!=1 and nonzero vstart keep the helper")
    ("rvv-qcg-fp-shared-mask", bpo::value(&o.rvv_qcg_fp_shared_mask)->default_value(false), "A12 (default off): in every typed FP frame (single vfalu/vfma instruction or FP vector run) with a translation-time SEW and at most 6 host chunks, derive the active-element opmask ONCE per chunk per frame (vchunkmaskset -> k(1+chunk), right after the FP bracket opens) and let every vfalu/vfma lane op of that chunk consume it, with k7 as the NaN/tail scratch; frames outside that range keep the per-op k1 prologue. Same guard, run boundaries, tail (all ones), NaN canonicalisation, fflags and vl==0 helper as before; only the number of vl loads/bzhi/kmovw changes")
    ("rvv-qcg-active-vl-bound", bpo::value(&o.rvv_qcg_active_vl_bound)->default_value(false), "S1-2A/2D (default off): in a single-instruction typed FP frame -- the vfalu route (2A) and the vfma route (2D) -- that already shares its per-chunk active masks, emit the body CHUNK-MAJOR and precede each chunk with one vchunkactive node -- `cmp [vec.vl], chunk*lanes` + `jbe` to the frame's FP epilogue. A chunk whose first element index is at or above the live vl is entirely tail: its lane op would run under an all-zero EVEX opmask (no lane written, no MXCSR flag raised) and its masked store would write no byte, so leaving the body there is the no-op the chunk already was. Chunk indices increase, so inactive chunks are a suffix and one forward branch retires all of them. Requires --rvv-qcg-fp-shared-mask; refuses vector runs (a member's early exit would leave later members' shared masks undefined), run-time-SEW frames and any frame whose guard already proved full VL. UNCHANGED: the admission decision, the guard kind and the guard code it emits, the fallback arm, and each chunk's existing guarded body (mask derivation, load, lane op, masked store) with its tail, mask and architectural vstart semantics. CHANGED, and this is a frame-shape change rather than a no-op: a bounded frame adds one vchunkactive node per bounded chunk (two host instructions each), grows its DECLARED node count by exactly that many, and adds that many forward branches to the frame's existing body-done label, which also shifts the displacement of the guard's own forward branch over the body. On this FP route the vstart=0 write needs no relocation: the branch target is inside the FP bracket, so the fflags/MXCSR epilogue and vstart=0 still run on the early exit. The FMA route reads the old vd, so chunk-major keeps load-major within a chunk and relies between chunks on the equal-EMUL byte-disjointness the batch loop already assumes. MEASURED BOUNDARY: enabling this pays only where the runtime vl leaves a material inactive suffix in the program's hot vector work; where it does not, the never-taken ladder is a measurable retired-instruction cost on full-VL executions, observed on a real application and not merely modelled. Compiled default off, and NOT ready to be defaulted on")
    ("rvv-qcg-active-vl-int-bound", bpo::value(&o.rvv_qcg_active_vl_int_bound)->default_value(false), "S1-3A + W27, the INTEGER ACTIVE-RANGE POLICY switch (default off, QCG only, SEPARATE from --rvv-qcg-active-vl-bound and --rvv-qcg-active-vl-widen-bound so each policy can be ablated alone). SCOPE: both RvvTryIntegerFamily blocks whose emitted units are indexed by DESTINATION element -- (a) the EQUAL-WIDTH SAME-EEW lane route (vchunkpartialalu: vadd/vsub/vmul/vmin/vmax/logical/shift/vmerge/vadc/compare/saturating/averaging/round-shift/vsmul, .vv/.vx/.vi, masked and unmasked), and (b) since W27 the NARROWING route (vnsrl/vnsra via InstVChunkNarrowShift and vnclipu/vnclip via the narrowing vchunkpartialalu arm, .wv/.wx/.wi, masked and unmasked). One switch because they are one policy with the same guard kind, the same vstart ownership and the same 2*(units-1) full-VL cost. WHAT IT EMITS: each unit c >= 1 is preceded by one vchunkactive node -- `cmp [vec.vl], element_base_c` + `jbe` to the frame end. element_base_c is unit c's first ARCHITECTURAL ELEMENT index, computed by the shared planner (dbt/guest/rv32_active_chunk_plan.h) as c * (unit destination bytes / destination EEW): chunk_bytes/SEW on the equal-width route and (chunk_bytes/2)/SEW on the narrowing route, whose unit reads a full host chunk of 2*SEW source elements and writes half a chunk of SEW destination elements. `vl <= it` therefore means every element the unit covers is in the tail set [vl, VLMAX): its body mask is empty, its masked narrowing store (vpmovwb/vpmovdw/vpmovqd {k1}) writes no byte, a compare destination is read-modify-written unchanged, and its sticky vxsat contribution (vsadd/vssub/vsmul, and vnclip) is already AND-ed with that empty mask, so a skipped unit contributes exactly zero. element_base strictly increases, so inactive units are a SUFFIX and one forward branch retires all of them; the test is on vl and NEVER on the mask, because with vstart > 0 a LEADING unit's mask is zero too -- prestart units keep running under their zero mask. Unit 0 is never bounded (its test would be `vl <= 0`), so a single-unit frame -- including every fractional-LMUL narrowing frame -- is byte-identical to before. A bounded frame clears vstart ONCE, at the branch target, instead of in its last body node. Legal overlap is preserved by emission order alone: a narrowing unit writes destination bytes [c*b/2, (c+1)*b/2), strictly below unit c+1's source read at [(c+1)*b, (c+2)*b), and the only overlap narrow_registers_legal admits is the bottom-aligned vd == vs2. Refuses widening (its own switch), mask-logic, reduction, slide/gather, vector memory, whole-register transfers (their EVL is nregs*VLEN/EEW and does not depend on vl at all), multi-member vector runs, frames with a partial arm and frames whose guard already proved full VL -- each refusal is a Panic in QEmit, not a comment. UNCHANGED: the admission decision, the guard kind and the guard code it emits, the fallback arm, and each unit's existing guarded body with its tail, mask and architectural vstart semantics. CHANGED, deliberately: a bounded frame adds one vchunkactive node per bounded unit (two host instructions each), grows its DECLARED node count by exactly that many (a mismatch is an emitter panic), RELOCATES the vstart=0 write from the last body node to the frame epilogue -- which is why unit 0 is never bounded -- and adds that many forward branches to the frame's existing body-done label, shifting the guard's own forward-branch displacement. COSTS 2*(units-1) extra retired instructions on a full-VL execution. MEASURED BOUNDARY: enabling this pays only where the runtime vl leaves a material inactive suffix in the program's hot vector work; where it does not, the never-taken ladder is a measurable retired-instruction cost on full-VL executions, observed on a real application and not merely modelled. Compiled default off, and NOT ready to be defaulted on")
    ("rvv-qcg-active-vl-narrow-bound", bpo::value(&o.rvv_qcg_active_vl_narrow_bound)->default_value(true), "W28 ABLATION CONTROL for --rvv-qcg-active-vl-int-bound, default ON, QCG only. NOT a policy switch and not a fourth family: the integer active-range policy deliberately covers both the equal-width and the narrowing block with ONE switch, and this flag exists only so the NARROWING half can be measured on its own. AND-gated with the policy switch, which is the whole contract: with --rvv-qcg-active-vl-int-bound=0 it is inert at either value; at =1 the default (1) bounds both blocks exactly as the policy switch alone always has, and =0 gives the equal-width-only arm (the pre-narrowing behaviour) while changing nothing else -- same admission, same guard kind, same fallback, same per-unit work, same vstart ownership in the equal-width block. It is NOT an OR-gated sub-flag. It names a route, never a workload, PC, symbol, VLEN or threshold. The only legitimate use is a paired ablation of narrowing's own increment. Its default TRUE is what keeps the policy switch's shipped behaviour unchanged; it does NOT mean narrowing is on by default, because the policy switch it is AND-gated with is compiled default off. When it does take effect it inherits that policy's frame-shape change -- added vchunkactive nodes, a larger declared node count, and the vstart=0 write relocated to the frame epilogue -- and the same measured boundary: useful only where the runtime vl leaves a material inactive suffix, a measurable retired-instruction cost on full-VL executions otherwise")
    ("rvv-qcg-active-vl-widen-bound", bpo::value(&o.rvv_qcg_active_vl_widen_bound)->default_value(false), "S1-3W (default off, QCG only, SEPARATE from --rvv-qcg-active-vl-bound and --rvv-qcg-active-vl-int-bound so each family can be ablated alone): in the WIDENING integer route (RvvTryIntegerFamily's id_rv32_vwint block -- vwaddu/vwadd/vwsubu/vwsub and their .wv/.wx wide-vs2 forms, vwmulu/vwmulsu/vwmul, vwmaccu/vwmacc/vwmaccus/vwmaccsu, .vv and .vx, masked and unmasked), precede each host chunk c >= 1 with one vchunkactive node: `cmp [vec.vl], element_base_c` + `jbe` to the frame end. element_base_c = c * chunk_bytes / (2*SEW) is chunk c's first ARCHITECTURAL ELEMENT index: widening changes the element WIDTH, never the element INDEX (destination element i comes from source element i), so source and destination share one active set [vstart, vl) and that index is in vec.vl's own unit. `vl <= it` therefore means every element the chunk covers is in the tail set [vl, VLMAX): its body mask is empty and its masked store writes no byte, including the vwmacc forms, whose accumulate reads and writes only its own chunk window. The immediate is the DESTINATION lane count times c -- the same pair Emit_vchunkwiden hands EmitRvvBodyMask -- not the source lane count, which would double the stride and skip live work. element_base strictly increases, so inactive chunks are a SUFFIX and one forward branch retires all of them; the test is on vl and never on the mask, because with vstart > 0 a LEADING chunk's mask is zero too. Chunk 0 is never bounded (its test would be `vl <= 0`), so a single-chunk frame -- every fractional-LMUL widening frame -- is byte-identical to before. A bounded frame clears vstart ONCE, at the branch target, instead of in its last chunk node. Refuses the equal-width, narrowing, mask-logic, reduction, slide/gather, vector-memory and whole-register routes, multi-member vector runs, frames with a partial arm and frames whose guard already proved full VL -- each refusal is a Panic in QEmit, not a comment. UNCHANGED: the admission decision, the guard kind and the guard code it emits, the fallback arm, and each chunk's existing guarded body with its tail, mask and architectural vstart semantics -- and no NEW emitter is needed, because Emit_vchunkwiden already keeps its vstart write behind a finish flag. CHANGED nonetheless: a bounded frame adds one vchunkactive node per bounded chunk (two host instructions each), grows its DECLARED node count by exactly that many (a mismatch is an emitter panic), CLEARS that finish flag so the frame epilogue performs the vstart=0 write instead -- a relocation of an architectural side effect -- and adds that many forward branches to the frame's existing body-done label, shifting the guard's own forward-branch displacement. COSTS 2*(chunks-1) extra retired instructions on a full-VL execution, and a widening frame has TWICE the chunks of the equal-width frame at the same LMUL. MEASURED BOUNDARY: enabling this pays only where the runtime vl leaves a material inactive suffix in the program's hot vector work; where it does not, the never-taken ladder is a measurable retired-instruction cost on full-VL executions, observed on a real application and not merely modelled. Compiled default off, and NOT ready to be defaulted on")
    ("rvv-qcg-full-vl-fast-body", bpo::value(&o.rvv_qcg_full_vl_fast_body)->default_value(false), "G11-A (default off): in a typed frame whose OWN guard already tests vl with `jne VLMAX` and vstart with `jne 0` (GuardKind VTypeVlVstart / VTypeVlVstartFrmRNE / VTypeVlVstartBaseLimit), the prestart and tail sets are empty, so for an UNMASKED vfalu/vfma lane op the active-element mask is the translation-time constant all-ones. Emit no vl/vstart mask derivation and no `{k}` on the lane op, no tail-agnostic all-ones fill, and no destination seed for the funct6 arms whose host operation writes every lane without reading the destination (vfadd/vfsub/vfmul/vfdiv and the two reversed forms; FMA, vfmin/vfmax and vfsgnj* keep their seed). NaN canonicalisation, the FP flag bracket, fflags, masked (vm=0) members, partial vl, non-zero vstart and the ordered fallback are unchanged. Mutually exclusive with the A12 shared masks for the frames it admits: RvvEmitFpSharedMasks builds none there and Emit_vchunkmaskset Panics if one arrives anyway")
    ("rvv-qcg-partial-vl", bpo::value(&o.rvv_qcg_partial_vl)->default_value(false), "A3 (default off): direct execution of PARTIAL vl (0 <= vl < VLMAX, vstart=0) for typed frames whose members are all integer e32/LMUL=1 unmasked .vv add/sub/mul/xor/or/and. The full-vl arm is unchanged; a partial vl takes a second arm in the same frame: one AVX-512 opmask per host chunk from vec.vl, then per member load-compute-merge-store with vpblendmd so inactive (tail) lanes keep the OLD vd value (tail-undisturbed). vl == 0 leaves vd unchanged. Frames with any other member kind, masked forms, other SEW/LMUL, nonzero vstart keep the existing helper fallback. Requires --rvv-direct 1")
    ("rvv-qcg-typed-chunk-vmv-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_vmv_force_emit)->default_value(false), "AUDIT ONLY: bypass the host AVX-512F feature test for the vmv.v.x QCG path so its emitted shape can be disassembled on a host that cannot execute it. Such code will SIGILL if run")
    ("rvv-qcg-typed-chunk-vadd-scalar", bpo::value(&o.rvv_qcg_typed_chunk_vadd_scalar)->default_value(false), "A6 (default off): pure-QCG direct lowering for vadd.vx vd,vs2,rs1 (OPIVX) and vadd.vi vd,vs2,simm5 (OPIVI), unmasked, e32/LMUL=1: the SAME chunk shape, lane op (vchunkadd) and guard as the vadd.vv route; source 1 is ONE vpbroadcastd per frame of the guest GPR's CPUState word (x0 -> 0) or of the sign-extended imm5. Partial vl uses the A3 bounded arm (needs --rvv-qcg-partial-vl 1); vstart != 0 and every other vtype keep the rv32_vialu helper. Not a vector-run member this round. Requires --rvv-direct 1. Default off")
    ("rvv-qcg-typed-chunk-vadd-scalar-force-emit", bpo::value(&o.rvv_qcg_typed_chunk_vadd_scalar_force_emit)->default_value(false), "AUDIT ONLY: bypass the host AVX-512F feature test for the vadd.vx/vadd.vi QCG path so its emitted shape can be disassembled on a host that cannot execute it. Such code will SIGILL if run")
    ("rvv-qcg-vx-mulacc-force-emit", bpo::value(&o.rvv_qcg_vx_mulacc_force_emit)->default_value(false), "AUDIT ONLY: bypass the host AVX-512F feature test for the Native-3 vmul.vx/vmacc.vx QCG path so its emitted shape can be disassembled on a host that cannot execute it. Such code will SIGILL if run. Does not relax the architectural guard, does not widen the admitted case, and has no effect on the LLVM arm, which has no host-feature probe")
    ("rvv-qcg-direct-setvl", bpo::value(&o.rvv_qcg_direct_setvl)->default_value(false), "T7S general direct-QCG lowering for legal immediate-vtype vsetvli and vsetivli at VLEN512/1024: field-derived VLMAX, unsigned min over register/immediate AVL, architectural rd/rs1 x0 handling including reserved keep-VL, exact state writes, and helper fallback for illegal/reserved vtype. Requires --rvv-direct 1 and pure QCG. Default off")
	    ("rvv-state-hash", bpo::value(&o.rvv_state_hash)->default_value(false), "print a deterministic hash of active vector architectural state plus vl/vtype/vstart/fcsr at guest exit")
	    ("rvv-run-scan-fast-reject", bpo::value(&o.rvv_run_scan_fast_reject)->default_value(true), "F1 (default on): with --rvv-vector-run=1, skip the run scan's descriptor work at an instruction that cannot start a run, recording identical run statistics, and refuse a pending descriptor with fewer than two members without copying it. Admission and emitted code are unchanged; 0 reproduces the F0 scan path.")
	    ("rvv-run-fp-store-masked-partial-vl", bpo::value(&o.rvv_run_fp_store_masked_partial_vl)->default_value(true), "F1 guard (default on): a QCG FP-bracket vector run whose other members are lane-local, non-trapping, vector-state-only routes (moves/broadcasts, logical shift immediates, integer .vv/.vx) is guarded with vl <= VLMAX instead of vl == VLMAX, and every live-out store of that frame is masked by the live vl, so its tail and inactive lanes are left undisturbed. Refused for the LLVM backend, runs with scalar or memory members, and the materialize, live-range-split, chunk-major, component-separable, grouped and dependency-probe bodies. 0 reproduces the F1 scan-only frame.")
	    ("rvv-run-fp-store-mask-reuse-shared", bpo::value(&o.rvv_run_fp_store_mask_reuse_shared)->default_value(true), "F1 guard (default on): in a frame admitted by --rvv-run-fp-store-masked-partial-vl that holds the A12 shared active masks (--rvv-qcg-fp-shared-mask), each masked live-out store of chunk c uses the resident k(1+c) instead of re-deriving the vl/vstart mask per store. 0 keeps the per-store derivation. Inert without shared masks.")
	    ("rvv-vector-run", bpo::value(&o.rvv_vector_run)->default_value(false), "R1A.3b/R1A.3d: form the vector-run (VRUN) descriptor at translation time and record it in the run counters. Scans forward from each instruction and applies the R1A.2 A1-A5 semantic membership predicates -- A1 by calling each operation's OWN typed-chunk admission predicate -- cutting at memory, helper-only, mask/cross-lane, branch/block boundary, vset{i}vl{i}, unsupported shape and the host vector-register pressure bound. With it on, a run of two or more admitted members is lowered as ONE guarded frame (R1A.3b); every other instruction is still translated by exactly the route it would take with this off. See --rvv-run-body for which body that frame emits. Default off")
	    ("rvv-run-scalar-passthrough", bpo::value(&o.rvv_run_scalar_passthrough)->default_value(false), "Pure ablation factor for the vector run's MEMBERSHIP rule: whether the three non-trapping RV32 integer ALU forms (add, addi, sub) may be carried through a run to BRIDGE two vector members, so that address/counter maintenance sitting between them does not cut the vector island. 0 (default) makes them ordinary non-members that cut the run with ScalarInsn, exactly as every other scalar instruction does -- no descriptor carries a RunOp::Scalar member, no frame emits an `rvvrunscalar` op and n_scalar_members is zero everywhere. 1 applies the bridging rule. Unlike --rvv-run-body, --rvv-run-order, --rvv-run-live-range-split and --rvv-run-dep-probe-depth, which are BODY selectors that must never reach admission, this switch is read on the ADMISSION side only (rvvrun::Classify) and in no body, no emitter and no execution path: its subject IS which instructions are members, so its two arms are expected to form different runs. Requires --rvv-vector-run=1")
	    ("rvv-run-component-separable", bpo::value(&o.rvv_run_component_separable)->default_value(false), "P7O-1 component-separable vector runs. A run whose members are all provably lane-local can be executed one host component at a time -- pass-1 loads, the member body and pass-3 stores inside one component loop -- in which case only ONE component is live at a time and the admission liveness bound loses its nchunks factor. 0 (default) makes RunDescriptor::component_separable false on EVERY descriptor, so the predicate's answer is absent rather than merely unused, and no bound, body, host byte or counter differs from a build without this switch. 1 lets a run take the component-resident bound ONLY IF every member satisfies the conservative P1-P11 predicate AND that bound is not larger than the existing one for that run, so it can never cut a run the default arm admits; such a run is then emitted with the component-major load/body/store order selected by the SAME descriptor decision that chose the bound, while every other run keeps the existing bound and body. The frame-scope broadcasts and the single FP bracket stay outside the component loop and the typed-op accounting is unchanged. Like --rvv-run-scalar-passthrough and unlike the body selectors, this is an ADMISSION-side switch: its two arms are EXPECTED to form different runs, so any ablation using it must report runs_formed/multi_member_runs/members_admitted and the register_pressure cut alongside any timing. Requires --rvv-vector-run=1; refused with --rvv-run-body=materialize, --rvv-run-live-range-split=1 or --rvv-run-order=chunk, each of which manages pass 1/2/3 residency itself")
	    ("rvv-run-grouped-component-major", bpo::value(&o.rvv_run_grouped_component_major)->default_value(false), "C4e grouped component-major vector-run body, the ARM an active-suffix bound can be placed on and the CONTROL for it. 0 (default) leaves every run body exactly as it is -- not one node, host byte or counter differs from a build without this switch. 1 emits a run whose guard both bounds vec.vl by vlmax and does NOT prove vl == VLMAX (on the run path that is exactly the all-FP partial-vl kind) as nchunks contiguous COMPONENT SLICES: per component, its own active-lane mask node, pass-1 loads, every member's work for that component, pass-3 stores. That order is what makes a frame's entirely-inactive components a contiguous TAIL of the body for every member at once -- a run has ONE vtype and therefore ONE element-to-component map shared by all its members -- which the member-major order does not have. It is an EMISSION-side switch: the same runs are formed from the same descriptors under the same admission bound, so unlike --rvv-run-component-separable its arms do not have to report run-shape counters. A run is refused and keeps the existing body unless it has at least two components, one mask node per component, the P1-P11 lane-locality predicate holds, and the component-resident liveness bound fits the host pool. This switch does NOT insert any bound; --rvv-qcg-active-vl-run-bound does. Requires --rvv-vector-run=1; refused with --rvv-run-body=materialize, --rvv-run-live-range-split=1, --rvv-run-order=chunk, --rvv-run-component-separable=1 or --rvv-run-dep-probe-depth > 0")
	    ("rvv-qcg-active-vl-run-bound", bpo::value(&o.rvv_qcg_active_vl_run_bound)->default_value(false), "C4e active-VL bound on a grouped component-major run frame: the fourth member of the --rvv-qcg-active-vl-* policy family and the ONLY factor separating a bounded run arm from its control. 0 (default) emits the grouped body with no bound node in it. 1 lets the shared planner place one active-VL bound before each boundable component slice, so a runtime vl that leaves a component entirely in the tail set skips that component and every later one -- for every member of the run at once. The planner's own conjuncts decide which frames qualify (guard bounds vl by vlmax and does not prove vl == VLMAX, one mask node per unit, no partial arm, no forbidding per-unit effect, at most 64 components); nothing here names an opcode, a guest pc, a VLEN or a threshold. The two arms' bodies are identical node for node except for the bound nodes. Requires --rvv-run-grouped-component-major=1: on a member-major body the early exit would jump past LATER MEMBERS, which QEmit::Emit_vchunkactive Panics on")
	    ("rvv-qcg-active-vl-bound-placebo", bpo::value(&o.rvv_qcg_active_vl_bound_placebo)->default_value(false), "C4h EVALUATION-ONLY MEASUREMENT CONTROL (default off, QCG only). NOT a lowering, NOT a policy, NOT a method, and it must never be defaulted on or cited in any performance claim. It exists so a bounded arm can be compared against an arm carrying the SAME emitted code shape that never skips: it weakens the immediate each vchunkactive node compares vec.vl against, from that unit's own first element index to 0. The node is still created, by the same finalizer, at the same position, with the same chunk index, and QEmit emits the same `cmp [vec.vl], imm` + `jbe` to the same body-done label. `vl <= 0` is true only for the architecturally empty vector, which the real bound's own unit-0 immediate is already true for, so this arm skips a SUBSET of what the real arm skips and its results are correct on every path -- a smaller comparison value can only skip less, never more. It does NOT touch the planner's element_base, which the guarded unit's own lane mask also uses. Requires --rvv-qcg-active-vl-run-bound=1: with no bound node to weaken it would name an arm identical to its control")
	    ("rvv-run-component-demand-placement", bpo::value(&o.rvv_run_component_demand_placement)->default_value(false), "P7O-2 demand-driven CPUState placement inside the component-major body. 0 (default) emits the accepted P7O-1 body: per component, pass 1 loads every live-in chunk, the members run, pass 3 stores every live-out chunk -- not one node differs from a build without this switch. 1 keeps EXACTLY those nodes and moves only where the CPUState accesses sit: a live-in's chunk load is emitted immediately before the first member of that component that reads it (Rule L), and a live-out's chunk store immediately after the member RunDescriptor::last_def names has finished that component (Rule S, the earliest safe point -- before it the value is not final, after it it never changes). The arithmetic is untouched: same lane ops, same linear order, same SSA operands, same declared n_typed; the state accesses are untouched in COUNT (popcount(live_in_mask) loads and popcount(live_out_mask) stores per component, asserted per component), so only their POSITION differs. Register ASSIGNMENT is not claimed identical -- the allocator sees a different value order -- the same caveat --rvv-run-order carries. Unlike --rvv-run-component-separable this is an EMISSION-side switch read after admission, so both arms form the SAME runs from the SAME descriptors under the SAME bound; it cannot raise the peak, because Rule L only moves a birth later and Rule S only moves a last use earlier, making the live set at every arithmetic anchor a subset of the default arm's. A strict no-op at VLEN 512, where P1 (nchunks >= 2) admits no component-separable run at all. Requires --rvv-run-component-separable=1 and inherits its exclusions; additionally refused with --rvv-run-dep-probe-depth > 0, whose vchunkdep nodes would make Rule S anchor a store before the stored value stops changing")
    ("rvv-lane-census-out", bpo::value(&o.rvv_lane_census_out)->default_value(""), "T7g analysis-only: write maximal non-overlapping real RVV lane-candidate rows and T7f certificate/rejection results here. Candidates come from the translator's actual guest PC/raw decode, per-route admission, typed-QIR shape/dataflow facts and QIR basic-block boundary. Empty means fully off. Never changes lowering, code generation or execution choice")
	    ("fault-snapshot-plan", bpo::value(&o.fault_snapshot_plan)->default_value(""), "Default-off runtime observation plan: selected guest entry PC plus absolute/SP-relative ranges to query")
	    ("fault-snapshot-out", bpo::value(&o.fault_snapshot_out)->default_value(""), "Write the one-shot live CPUState and mapping snapshot selected by --fault-snapshot-plan")
	    ("ccrf-certificate", bpo::value(&o.ccrf_certificate)->default_value(""), "T7m exact-join certificate to validate against the running ELF (default off)")
	    ("ccrf-affine-facts", bpo::value(&o.ccrf_affine_facts)->default_value(""), "Accepted affine facts bound by --ccrf-certificate")
	    ("ccrf-exact-qir", bpo::value(&o.ccrf_exact_qir)->default_value(""), "Accepted exact-QIR file used to materialize certified whole-function component images")
	    ("ccrf-result-out", bpo::value(&o.ccrf_result_out)->default_value(""), "Boundary architectural/memory digest output for the CCRF differential")
	    ("ccrf-sequential", bpo::value(&o.ccrf_sequential)->default_value(false), "Execute certified chunk components sequentially and apply the certified join")
	    ("ccrf-concurrent", bpo::value(&o.ccrf_concurrent)->default_value(false), "Execute pre-materialized certified component images on two persistent pinned workers")
	    ("ccrf-precompiled-sequential", bpo::value(&o.ccrf_precompiled_sequential)->default_value(false), "Execute the same pre-materialized images sequentially as the T7o mechanism ablation")
	    ("ccrf-worker-cpu0", bpo::value(&o.ccrf_worker_cpu0)->default_value(-1), "Host logical CPU for certified component worker 0")
	    ("ccrf-worker-cpu1", bpo::value(&o.ccrf_worker_cpu1)->default_value(-1), "Host logical CPU for certified component worker 1")
	    ("ccrf-require-avx512", bpo::value(&o.ccrf_require_avx512)->default_value(false), "Require certified CCRF components to select AVX-512/ZMM lowering; fail closed if AVX-512F is absent")
	    ("rvv-run-body", bpo::value(&o.rvv_run_body)->default_value("ssa"), "R1A.3d ablation body selector for a CONSUMED vector run: `ssa` (default) loads each live-in chunk once, runs members over SSA values, then stores final live-outs; `materialize` hands member values through CPUState. With live-range splitting off, both settings form the same run, guard, join and ordered fallback; the body differs in intermediate CPUState writes/reads and reuse of scalar broadcasts. FormRun consults this selector only when choosing a split-cap limit; the CLI refuses split+materialize. Ignored when --rvv-vector-run is 0")
	    ("rvv-run-order", bpo::value(&o.rvv_run_order)->default_value("member"), "P6C/P6A-Estimand-D issue-order selector for the vector-run SSA body: `member` (default) keeps the accepted order -- guest order outside, chunk inside -- so a guest op's sibling chunks are issued adjacently (L1,H1,L2,H2,...); `chunk` swaps the two loops so one whole independent chunk chain is issued before the next begins (L1,L2,...,Ln,H1,H2,...,Hn). The k chunks are k disjoint dataflow components (every read and write of a component value uses one fixed chunk index), so both are legal linear extensions of the SAME SSA value graph. THIS FLAG CHANGES EMISSION ORDER ONLY. Both settings produce the same admission decision, the same descriptor, the same nchunks/chunk_bytes/member list/n_typed, the same RVV_RUN/RVV_RUN_CUT counters, the same single guard, the same join, the same ordered fallback arm, the same pass-1 loads and pass-3 stores and the same emitted host instruction multiset; register ASSIGNMENT is not claimed identical, because the allocator sees a different order. Both orders are emitted by the SAME body (RvvEmitVectorRunGroup's shared per-member emitter, called over the whole chunk range for `member` and one component at a time for `chunk`), so every member kind the run substrate admits -- ALU, FP add/sub/mul/div, FMA, move/broadcast, whole-register load/store and the OPMVX multiply/accumulate -- is lowered identically in both. Read only on the emission side and NEVER by admission: no path reachable from rvvrun::FormRun or its MemberAdmit callback inspects it. Ignored when --rvv-vector-run is 0 or --rvv-run-body is materialize. ONE EXCLUSION REMAINS, and it is empty by default: a run carrying a --rvv-run-scalar-passthrough member is not lowered as a run in `chunk` order, because the scalar member is the one emitter arm that is not per-component and would otherwise execute k times. With that switch at its default 0 no descriptor carries such a member")
	    ("rvv-run-dep-probe-depth", bpo::value(&o.rvv_run_dep_probe_depth)->default_value(0), "P7L-B1 EXPERIMENT INSTRUMENT, not a lowering. 0 (default) = off and every emitted byte is unchanged. N > 0 appends N value-preserving `vchunkdep` ops (one `vpblendmq` each) after every (member, chunk) lane op of the vector-run SSA body. Their only purpose is to carry a data dependency the computation does not need, so that --rvv-run-dep-probe can move ONE register operand and nothing else. Refused unless --rvv-vector-run=1, --rvv-run-body=ssa and --rvv-run-order=member. Never read by admission. P7L-B1-SPLIT: --rvv-run-live-range-split=1 is now supported and is the authorized configuration at depth 1. The split body appends the same chain to each member's k published components AFTER its chunk loop -- the only point at which a CROSS-component chain is expressible -- and counts it in both of its passes, so planning and emission agree; previously the split arm declared these ops and never emitted them, which made the combination a translation Panic. The k chain temporaries are charged to the split planner's residency budget rather than left to the allocator. This is an INSTRUMENT and it changes emitted bytes: never set it on a timing arm that is supposed to represent production.")
	    ("rvv-run-dep-probe", bpo::value(&o.rvv_run_dep_probe)->default_value("indep"), "P7L-B1 ablation arm, the SINGLE factor: `indep` (default) makes each probe read the chunk's OWN running value, so the k chunk chains stay independent; `serial` makes it read chunk (c+1)%k's running value, so they are chained together. Everything else -- admission, descriptor, member list, n_typed, frame, guard, join, ordered fallback, CPUState traffic and the emitted instruction multiset -- is identical between the two, and at k == 1 (VLEN 512) `(c+1)%1 == c` makes them byte-identical. Ignored when --rvv-run-dep-probe-depth is 0.")
	    ("rvv-qcg-hit-counter", bpo::value(&o.rvv_qcg_hit_counter)->default_value(true), "R1A.3d: emit the QCG research hit counter (CPUState::rvv_direct_hits), one `inc` at the join of every typed frame, on the timed fast path. Default 1, which keeps every accepted pinned golden byte-identical. Set 0 for a counter-free timing arm: the frozen R1A.3c microkernel executes six typed frames per strip step with --rvv-vector-run 0 and five with it on, so this removes six and five instructions per strip step respectively. The guard-miss rvv_direct_fallbacks counter is deliberately NOT gated -- it is on the cold arm, costs a guard-hit arm nothing, and keeps guard_fallbacks==0 usable as a validity gate")
	    ("rvv-vector-ssa", bpo::value(&o.rvv_vector_ssa)->default_value(false), "enable typed RVV chunk/mask/EVL QIR for LLVM AOT; unsupported states use counted helper fallback")
	    ("rvv-llvm-wide-vadd", bpo::value(&o.rvv_llvm_wide_vadd)->default_value(false), "T7a experimental LLVM-AOT representation for exact unmasked e32/m1/full-VL vadd.vv; independently selectable from the default chunked representation and ignored outside LLVM AOT")
	    ("rvv-llvm-wide-vadd-ssa", bpo::value(&o.rvv_llvm_wide_vadd_ssa)->default_value(false), "T7b fair LLVM-AOT representation for exact unmasked e32/m1/full-VL vadd.vv using the accepted V512 SSA inputs and outputs; independently selectable and default off")
	    ("rvv-vector-ssa-counters", bpo::value(&o.rvv_vector_ssa_counters)->default_value(false), "S3.7: diagnostic artifacts count typed RVV direct and runtime-guard fallback executions. Mirrors elfaot's option of the same name, and exists here because the same-run builder inherits this value through the route contract (dbt/aot/aot_boot.cpp kRvvRouteContract) -- without it a background-built artifact can never report whether its typed frames were entered, which is the only child-side evidence that the contract arrived. Changes no admission and no lowering shape. Default off")
	    ("rvv-inject-fault", bpo::value(&o.rvv_inject_fault)->default_value(0), "VERIFIER SELF-TEST ONLY: corrupt the fixed-width result of the Nth vector op, so --rvv-verify can be shown to actually catch a divergence. 0 = off")
	    ("rvv-census", bpo::value(&o.rvv_census)->default_value(0), "P13 dynamic RVV cost census: 0=off, 1=invocation/element counts, 2=counts+rdtsc cycles per vector instruction (mode 2 distorts timing; its own overhead is calibrated and printed)")
	    ("rvv-census-out", bpo::value(&o.rvv_census_out)->default_value(""), "write the --rvv-census CSV here instead of stderr")
	    ("rvv-pc-census", bpo::value(&o.rvv_pc_census)->default_value(false), "T5b-1 DIAGNOSTIC: count, PER GUEST PC, every vector instruction that ran in the C++ handler instead of as emitted host code, with its raw encoding, rvdbt handler family and the elements covered. --rvv-route-census is limited to T1's nine opcodes and --rvv-census is process-wide, so neither can say whether a fallback came from the timed kernel or from the adapter; adding the PC makes that a range test against the ELF symbol table. A count here is NOT a total execution count -- an instruction that took a direct or typed route never reaches this hook -- so totals come from a control run with every direct and typed route disabled. Cold path only, nothing emitted changes. Default off")
	    ("rvv-pc-census-out", bpo::value(&o.rvv_pc_census_out)->default_value(""), "write the --rvv-pc-census CSV here")
	    ("rvv-fixed-copy", bpo::value(&o.rvv_fixed_copy)->default_value(false), "N2b candidate 5: dispatch whole-register vector load/store copies on a compile-time constant size so the compiler inlines them, instead of calling libc memmove with a runtime size")
	    ("rvv-scalar-fround-rcmirror", bpo::value(&o.rvv_scalar_fround_rcmirror)->default_value(false), "G7 cycle 3: on a continued FP run compare the mirrored rounding-control field instead of re-reading MXCSR, removing an STMXCSR from every FP instruction. Same semantics -- the A/B control")
	    ("rvv-scalar-fround-run", bpo::value(&o.rvv_scalar_fround_run)->default_value(false), "P14 cycle 4: keep the FP rounding-mode bracket open across consecutive scalar FP instructions instead of one STMXCSR+LDMXCSR pair per guest op. Closed at every TB exit and before any fcsr/fflags access. Default off = the A/B control")
	    ("rvv-gather", bpo::value(&o.rvv_gather)->default_value(false), "C-beta substrate: host AVX2 gather for unordered indexed loads (vluxei). Default off; A/B control")
    ("rvv-preadmit-extent", bpo::value(&o.rvv_preadmit_extent)->default_value(false), "refuse fast-path admission when the extent cannot reach the narrowest host chunk")
    ("rvv-tail-round", bpo::value(&o.rvv_tail_round)->default_value(false), "M1: round the executed extent up to a whole host chunk when the guest tail policy is agnostic (vta=1). Default off; A/B control")
    ("rvv-fuse-pairs", bpo::value(&o.rvv_fuse_pairs)->default_value(false), "P15 candidate 7: fuse an adjacent pair of unmasked integer element-wise .vv ops so the intermediate stays in a host vector register. Default off; A/B control")
    ("rvv-fast", bpo::value(&o.rvv_fast)->default_value(false), "P13 method: semantic-class chunk lowering with discharged obligations. Default off so every measurement has an in-binary A/B control")
	    ("rvv-fast-classes", bpo::value(&o.rvv_fast_classes)->default_value(15), "P13 method class mask for the operation-class ablation: 1=integer element-wise, 2=FP add/sub/mul/div, 4=FP fused multiply-add, 8=FP compare (mask-producing). Default 15 = all")
	    ("rvv-fround-batch", bpo::value(&o.rvv_fround_batch)->default_value(true), "P13 B3-narrow: share one FRound bracket across immediately-adjacent same-block eligible falu/fma/vfcmp calls. Default on; 0 is the A/B control isolating batching's own marginal effect")
	    ("rvv-fround-mxcsr-mode", bpo::value(&o.rvv_fround_mxcsr_mode)->default_value(0), "P13 Ceiling-P4: how much of the MXCSR bracket save/restore pair to elide. 0 = shipped behaviour (read old value, restore exactly it; the A/B control). 1 = drop the save, using the process-lifetime-constant resting bits (provably equivalent as the source stands). 2 = additionally drop the restore (requires the stated no-host-FP-between-brackets invariant). See dbt/config.h")
	    ("rvv-vfcmp-batch-mask", bpo::value(&o.rvv_vfcmp_batch_mask)->default_value(false), "P13 Ceiling-P5: write a whole chunk of vfcmp mask bits in one read-modify-write instead of one per element. Default off (A/B control). See dbt/config.h")
	    ("rvv-fred-specialize", bpo::value(&o.rvv_fred_specialize)->default_value(0), "P13: reduction loop specialisation, staged for ablation: 0=off, 1=invariant hoisting only, 2=+native accumulator, 3=+canonicalise at end (full method), 5=stage 3 + hoisted element addressing (measurement arm for the remaining per-element gap), 4=measurement arm completing the accumulator x canonicalisation 2x2 (bits accumulator, canon at end; dominated by 3, never a shipping candidate). Ordering unchanged in every stage. Default 0. See dbt/config.h")
	    ("rvv-fround-oracle-mode", bpo::value(&o.rvv_fround_oracle_mode)->default_value(0), "BOUND_DEFINITION.md executable oracle: 0=off, 1=RECORD the real peek's decisions to --rvv-fround-oracle-file, 2=REPLAY them (O(1) lookup, no guest-memory decode) as To. Requires --rvv-fround-batch 1")
	    ("rvv-fround-oracle-file", bpo::value(&o.rvv_fround_oracle_file)->default_value(""), "trace file path for --rvv-fround-oracle-mode 1/2")
	    ("rvv-width-policy", bpo::value(&o.rvv_width_policy)->default_value(0), "P13 U2 host width policy: 0 = off (compile-time fixed width, the control), 1 = fixed16, 2 = fixed64, 3 = cascade (widest CPUID-supported width fitting the remaining active extent, then narrower, then scalar residue)")
	    ("rvv-probe", bpo::value(&o.rvv_probe)->default_value(0), "P13 phase-B probes (bitmask, behaviour-preserving): 1 = per-PC vector census, 2 = evaluate B1's FP no-NaN precondition without acting on it")
	    ("rvv-probe-out", bpo::value(&o.rvv_probe_out)->default_value(""), "write the --rvv-probe CSV here instead of stderr")
	    ("rvv-seqtrace-out", bpo::value(&o.rvv_seqtrace_out)->default_value(""), "P13 phase-A dynamic sequence collector: write the ordered vector-instruction trace CSV here. Requires a binary built with RVDBT_SEQTRACE=1 (compile-time gated, zero cost otherwise) -- requesting it on a binary built without that flag is a hard error at startup, not a silent no-op")
	    ("tier0-lazy", bpo::value(&o.tier0_lazy)->default_value(false), "2026-06-16 tier-0 lazy translation: interpret a block until per-entry count reaches K*, then JIT (skip translating cold handlers)")
	    ("tier0-threshold", bpo::value(&o.tier0_threshold)->default_value(0), "tier-0 break-even K* (executions interpreted before JIT). 0 = JIT on first touch (legacy)")
	    ("update-profile-on-aot", bpo::value(&o.update_profile_on_aot)->default_value(false), "R47 closed-loop: record THIS aot run's realized hotness into the cache profile (accumulates coverage across the input stream -> next compile admits the convergent union working set). Wendell disables this; default off")
	    ("inrun-tier", bpo::value(&o.inrun_tier)->default_value(false), "Round-17 BCT: start on QCG and promote to a concurrently-built AOT artifact mid-run via the brind slowpath channel")
	    ("inrun-artifact", bpo::value(&o.inrun_artifact)->default_value(""), "Round-17 BCT: explicit artifact path to poll for (staging dir; avoids cache-lock collision with the builder)")
	    ("inrun-artifact-seq", bpo::value(&o.inrun_artifact_seq)->default_value(""), "Round-40 single-core tiering: comma-separated SEQUENCE of armed artifacts; boots each in order as it lands (small-hot then full, or per-shard chunks). Implies inrun-tier.")
	    ("inrun-flush-ms", bpo::value(&o.inrun_flush_ms)->default_value(50), "Round-19: channel-keeper flush cadence in ms (sensitivity)")
	    ("inrun-auto-escalate", bpo::value(&o.inrun_auto_escalate)->default_value(false), "2026-07-05 B-line closed loop: after the first staged artifact boots, evaluate the v2 majority sign test in-process (census delta since swap) and fork a background full build if QCG is still the majority tier")
	    ("escalate-elfaot", bpo::value(&o.escalate_elfaot)->default_value(""), "auto-escalate: elfaot binary path")
	    ("escalate-cache", bpo::value(&o.escalate_cache)->default_value(""), "auto-escalate: staging dir pre-populated with the guest elf (+ profile); the forked build writes its artifact here")
	    ("escalate-elf", bpo::value(&o.escalate_elf)->default_value(""), "auto-escalate: guest elf path inside the staging dir")
	    ("escalate-ski-full", bpo::value(&o.esc_ski_full)->default_value(false), "2026-07-14: gate the FULL build by online ski-rental -- fire only when elapsed >= online-calibrated price (first-build wall x profile growth ratio); self-abstains on compile-heavy runs")
	    ("inrun-observe-only", bpo::value(&o.inrun_observe_only)->default_value(false), "2026-08-17 CAUSAL CONTROL: run the full single-run observation/evaluator path but refuse to spawn any builder (fail-closed, logged as INRUN_EVENT BUILD_SUPPRESSED). Isolates observation overhead from AOT execution benefit. Control arm only.")
	    ("aot-loop-entry", bpo::value(&o.aot_loop_entry)->default_value(false), "T5c-0 (default off): give every natural-loop header inside an admitted region its own entry symbol, via the existing multi-entry wrapper mechanism. Region formation, region membership and generated region code are unchanged; the artifact gains one entry wrapper and one _aot_tab slot per exposed header. This is what makes a region LATE-ENTERABLE: rvdbt seeds region entries only from segment entries and indirect-branch targets, so a loop header reached by direct branches has no entry symbol and BootOneArtifact's RelinkTo cannot redirect a loop that is already running. THERE IS NO PER-LOOP HOTNESS GATE: the candidates are the natural-loop headers of regions the compiler already selected, and selection is the only hotness filter applied. A --threshold gate was deliberately not added because it would be inert on the path this exists for -- sr_builder.sh runs admission separately and then invokes elfaot with --threshold=999999999 --dispatch-admit-list -- so cost scales with the number of natural loops in an admitted region (8 wrappers, +1.45% artifact size on the frozen T5c-0 guest; unmeasured on loop-dense code). Set on elfrun so the value is forwarded to the background builder through the route contract.")
	    ("inrun-escape-unlink", bpo::value(&o.inrun_escape_unlink)->default_value(false), "T5c-0 LIFECYCLE PLUMBING (default off): let the keeper return recently linked DIRECT branch slots to the lazy-JIT stub, so control reaches the Execute() loop and the tier's ALREADY-EXISTING evaluator/boot call site runs. Without it the only path back is the indirect-branch slowpath, and a pure-compute leaf loop (PolyBench gemm: one indirect transfer in the whole kernel, its closing ret) executes none -- so the tier degenerates to QCG-only however long the run is, and the escape count is a property of the program's call structure rather than of its duration. Changes no admission bar, evidence gate, threshold, region choice or cadence; armed only while --inrun-tier is set and not yet booted, and stops at boot. Reports ESC_UNLINK ticks/slots.")
	    ("qcg-backedge-safepoint", bpo::value(&o.qcg_backedge_safepoint)->default_value(false), "T5d-0 (default off): emit a runtime-service safepoint on QCG direct BACKWARD region exits. A direct branch slot self-patches into a `jmp rel32` on its first traversal and from then on never re-enters Execute(), which is the only place the runtime services its asynchronous requests -- so a long pure-compute loop stops asking for service no matter how long it runs. With this on, a gbr whose guest edge goes backward (decided in the translator from the branch instruction's own PC and its architectural target; forward edges, indirect edges and returns are untouched) tests config::service_request ahead of its slot and, only when a request the Execute() loop already consumes is pending, stores that edge's target guest PC into CPUState::ip and leaves through the SAME escape_link stub the lazy-link path's not-found case uses. Fall-through cost is a load, a compare and a not-taken branch. It scans nothing, rewrites no linked slot, shares no state with --inrun-escape-unlink, and makes NO admission, hotness, region or promotion decision -- it is service plumbing only. JIT-mode QCG only; offline AOT output is byte-identical either way. Reports BACKEDGE_SAFEPOINT sites/gbr_total/escapes.")
	    ("loop-tier", bpo::value(&o.loop_tier)->default_value(false), "T5d2a (default off): the LOOP TIER -- start on QCG and, once THIS run's own profile reaches the compiler's admission bar, snapshot that profile and launch exactly one background `elfaot --aot-loop-regions` (T5d1b) on a distinct allowed CPU. It PRODUCES an artifact and nothing else: nothing is dlopened, announced, relinked, promoted or timed in this process, which is what keeps its claim about publication rather than execution. The bar is sr_chunk_threshold, the same number handed to the child as --threshold; a below-bar service opportunity does not consume the one allowed build, and a workload that never gets hot never fires. Requires --qcg-backedge-safepoint (a direct-branch loop otherwise never returns to the service point) and refuses to arm alongside any other SIGALRM keeper. Shares no state with --inrun-tier / --single-run: no sr_builder.sh, no threshold descent, no ski gate, no census, no rung sequence, no --inrun-escape-unlink and no --aot-loop-entry. Needs --loop-tier-elfaot, --loop-tier-elf and --loop-tier-stage. Emits LOOPTIER_EVENT/LOOPTIER_BUILD/LOOPTIER_SUMMARY; an off run emits none of them.")
	    ("loop-tier-side-exit", bpo::value(&o.loop_tier_side_exit)->default_value(false), "T5d2a3 (default off): service an INTRA-REGION direct backedge's loop-tier notification on that same edge, instead of waiting for a later, unrelated region-exit `gbr` to reach T5d0's safepoint. A tight loop's latch stays inside its QCG region (see MakeGBr), so with T5d2a2 alone the request is carried until the guest happens to leave the region -- on the frozen GEMM a few instructions later, on a loop wholly contained in one region possibly not before the loop ends. With this on, the notification path -- which is behind T5d2a2's four guards and therefore runs at most once per guest target -- jumps to an OUT-OF-LINE block that commits the pinned guest globals `QRegAlloc::BlockBoundary` left resident (every other global is already in CPUState), undoes the region's frame, stores that edge's own target guest PC into CPUState::ip, and leaves through the SAME escape_link stub carrying a real BranchSlot for that target, so Execute() takes its direct-edge arm. The no-event path is unchanged: still an in-region direct branch, no host helper on any iteration, no permanent region split. Requires --loop-tier and REFUSES TO ARM without it (reason=side_exit_requires_loop_tier, exit 2): the exit block is emitted only inside Emit_Cache's loop_tier block, so with the tier off this switch does nothing and the run would report a zero side-exit row that is indistinguishable from a loop that never got hot. Also refuses to arm alongside --trace or --rvv-vector-ssa. JIT-mode QCG only; offline AOT output is byte-identical either way. Reports LOOPTIER_SIDEEXIT sites/exits and the guest PCs the exits resumed at.")
	    ("loop-tier-completion-exit", bpo::value(&o.loop_tier_completion_exit)->default_value(false), "T5d2b0 (default off): wake the parent when its loop-tier BUILDER TERMINATES, so the child is reaped and the artifact's disposition reached WHILE THE GUEST IS STILL RUNNING. After T5d2a3 the tier sits in BUILDING with the guest inside the same pure-compute region: the notification is spent by design (T5d2a2's ARMED guard makes the generated code silent), a second hotness event is deliberately impossible, and ReportAtExit only collects the child after GUEST_EXIT. With this on, SIGCHLD -- raised by the child's own termination, not by any timer -- sets the SAME loop-tier service bit the notification uses, from a handler that does two lock-free atomic writes and NOTHING else; an intra-region backedge whose target already passed the bar tests that word and takes T5d2a3's existing exit block; and Execute() reaps the one recorded pid with WNOHANG on the host stack, reaching PUBLISHED or FAILED during the run. No timer, cadence, directory poll, blocking wait, second threshold crossing or second workload event takes part. NOTHING is dlopened, relinked or entered -- that is T5d2b. Requires --loop-tier and --loop-tier-side-exit, and refuses to arm if SIGCHLD is already owned. Reports LOOPTIER_SIDEEXIT completion_sites/completion_exits and LOOPTIER_EVENT CHILD_EXITED.")
	    ("loop-tier-load", bpo::value(&o.loop_tier_load)->default_value(false), "T5d2b1 (default off): after the in-run reap reaches PUBLISHED, LOAD AND VALIDATE the artifact this run published -- and stop there. The parent dlopens the exact PublishPath() it renamed onto, puts it through the SAME CPUState-ABI and RVV-VLEN gate BootAOTFile/BootOneArtifact/BootReuseArtifact use (one shared implementation, not a fourth copy), and validates the artifact's own table: present, non-empty, bounded by its section headers, every entry backed by a defined symbol at the address it records, no duplicate guest ip, and the header this run spent its build on actually present. On success the tier reaches a NEW state, LOADED, and holds an immutable validated view; every failure closes the handle, keeps the state at PUBLISHED and reports a stable reason. NOTHING is installed: no TBlock is allocated or replaced, no CacheBr/CacheBrind, no RelinkTo, no entry into compiled code, and no speedup is claimed -- that is the next checkpoint. Requires --loop-tier and --loop-tier-completion-exit, because an in-run PUBLISHED is what the completion wakeup produces. Emits LOOPTIER_EVENT LOADED / LOAD_REFUSED and a LOOPTIER_LOAD summary line.")
	    ("loop-tier-exit-cancel", bpo::value(&o.loop_tier_exit_cancel)->default_value(true), "2026-09-17, DEFAULT ON: at guest exit, CANCEL a builder that is still running instead of blocking until it finishes. An artifact that lands after the guest has stopped can never be installed -- the install gate is in-run only -- so the previous blocking wait charged the whole remaining compile to cold elapsed for code the process would never enter (measured: GUEST_EXIT 2603 ms, BUILD_END 45253 ms). The tier signals ONLY the process group it created for this run (pgid == the builder pid, established by a checked setpgid on both sides of the fork), SIGTERM then SIGKILL, reaps the exact child, and restores SIGCHLD after that wait. A cancelled build enters state CANCELED: it is never reported as PUBLISHED, never loaded and never installed, and if the child renamed the artifact before the signal landed that file is recorded as a stale publication instead. If the group is not provably owned the tier refuses to signal and falls back to waiting. Set 0 for the previous behaviour.")
    ("loop-tier-install", bpo::value(&o.loop_tier_install)->default_value(false), "T5d2b2 (default off): after the in-run load reaches LOADED, INSTALL the ONE table entry naming this run's own spawn header -- and stop there. The validated view's `base + aot_vaddr` for that exact guest ip becomes an AOT TBlock (tcode.size == 0, the announce-created shape) and REPLACES that ip in the translation cache via the existing mid-run-boot InsertOrReplace, so both the map and the L1 block cache name the artifact. Every OTHER symbol the artifact carries is left uninstalled, and this path calls no RelinkTo, no CacheBr, no CacheBrind and no RevokeTarget: entering the artifact is Execute()'s own direct-edge arm, because the install happens on the host stack BEFORE that loop's tcache::Lookup(state->ip) and the escape that delivered the service carried the exact BranchSlot of the edge whose target is that header. On success the tier reaches a NEW state, INSTALLED; every failure leaves the state at LOADED with a stable reason and changes nothing. Requires --loop-tier and --loop-tier-load. Pair with --aot-region-hit-count and --dump-region-hits to read the artifact's OWN region-entry counter back: that, not the state and not the block count, is what says the installed code EXECUTED. Emits LOOPTIER_EVENT INSTALLED / INSTALL_REFUSED and a LOOPTIER_INSTALL summary line.")
    ("loop-tier-route-census", bpo::value(&o.loop_tier_route_census)->default_value(false), "C5c (default off): PROMOTION-ROUTE CENSUS -- a pure read, printed at two instants the run already passes through (immediately before the installer mutates the translation cache, and again at guest exit), of every structure in this process that can name a host entry for the promoted header: the link index (its fan-in, split by what each slot currently jumps to), the indirect-dispatch L1 cache, the Emit_Cache profiling cache, the inline-cache blobs, and a conservative upper bound on TBs whose emitted code may contain the header as an interior block. It REPOINTS NOTHING and INSTALLS NOTHING -- it exists because C5B proposes repointing those structures and its premise (a non-empty link index at the install) is not recorded by any existing artifact. Emits LOOPTIER_ROUTE_CENSUS; an off run emits none. Changes no generated code and no admission, so a run that sets it is a MECHANISM run whose wall clock must not be quoted.")
	    ("loop-tier-elfaot", bpo::value(&o.loop_tier_elfaot)->default_value(""), "T5d2a: the elfaot binary the loop tier's child executes.")
	    ("loop-tier-elf", bpo::value(&o.loop_tier_elf)->default_value(""), "T5d2a: the guest ELF the child compiles -- must be the one this process is executing. The profile snapshot carries that ELF's checksum, so a mismatched binary is refused by elfaot's own identity check and the VLEN-qualified artifact name the parent expects never appears.")
	    ("loop-tier-stage", bpo::value(&o.loop_tier_stage)->default_value(""), "T5d2a: staging directory. Receives the profile snapshot, the child's build log and command line, and the atomically published loop_tier.v<vlen>.so. Separate from the run cache because the run holds an exclusive lock on its own profile.")
	    ("inrun-evidence-gate", bpo::value(&o.inrun_evidence_gate)->default_value(false), "T3b: gate the single-run first fire on RUNTIME EXECUTION EVIDENCE rather than on the first evaluator tick. Without it the fire happens at the first fixed-cadence SIGALRM (--inrun-flush-ms), which makes the trigger a function of wall time and not of anything the guest did -- real lifecycle plumbing, but not hot-region detection. With it, the fire waits until this run's own accumulated profile shows a region whose exec_count has reached sr_chunk_threshold: the SAME number this process hands the child elfaot as --threshold, i.e. the compiler's own admission bar rather than a new constant. Emits INRUN_EVENT EVIDENCE_WAIT/EVIDENCE_MET; a below-bar evaluation does not consume the one-shot, and a workload that never gets hot never fires. Default off")
	    ("single-run", bpo::value(&o.single_run)->default_value(false), "2026-07-14 TRUE single-run: first selective build fires from the run's OWN mid-run objprof (no run-1); census loop then decides the full rung as usual")
	    ("sr-sampled-edges", bpo::value(&o.sr_sampled_edges)->default_value(false), "A-line: sampled indirect-edge capture (one edge per SIGPROF sample; near-zero overhead vs the catastrophic full recording)")
	    ("shadow-edges", bpo::value(&o.shadow_edges)->default_value(false), "A-line (next cycle after FDRE): SOURCE-indexed shadow cache, logs (src,tgt) only on a miss for THAT source -- unlike sr-sampled-edges (target-indexed via the existing l1_brind_cache, only ever sees the FIRST source per target), this discovers the full multi-source structure per target -- requires --shadow-edges-out")
	    ("shadow-edges-out", bpo::value(&o.shadow_edges_out)->default_value(""), "path to dump the shadow-edge-discovered (src,tgt,count) file (brindedges::Dump format, same as --brind-edges-out)")
	    ("shadow-edges-k", bpo::value(&o.shadow_edges_k)->default_value(0), "H2 (SUPPORT_DISCOVERY_H1_VS_H2.md): per-source K-way history SET instead of H1's single last-target slot -- a hit (target already in the set) is a no-op, a miss unconditionally Records and inserts (evicting round-robin/FIFO if full). 0 or 1 = off (H1's existing single-slot inline fast path is unchanged); >=2 switches to the K-way path (unconditional C++ handler call, not inlined -- first-cut scoping). Requires --shadow-edges=1. Clamped to tcache::ShadowEdgeKSlot::kMaxK (8).")
	    ("shadow-edges-k-out", bpo::value(&o.shadow_edges_k_out)->default_value(""), "A-line round 13: dump ShadowEdgeKCache's per-slot (source,target,hit_count) triples to this path, --aot-multiguard-edges-compatible -- near-zero-marginal-cost multi-target evidence source (one extra counter increment on an already-unconditional per-dispatch call), unlike shadow-majority which only ever certifies a single winner per target.")
	    ("shadow-edges2", bpo::value(&o.shadow_edges2)->default_value(false), "A-line round 14 (TRACK 2): fully-inline, no-out-of-line-call, fixed 2-slot per-source multi-target collector -- see tcache.h ShadowEdge2Slot.")
	    ("shadow-edges2-out", bpo::value(&o.shadow_edges2_out)->default_value(""), "dump ShadowEdge2Cache's per-slot (source,target,hit_count) pairs, --aot-multiguard-edges-compatible.")
	    ("shadow-edges2-all-jalr", bpo::value(&o.shadow_edges2_all_jalr)->default_value(false), "A-line round 15 (TRACK 1): diagnostic-only -- bypass the shadow_track RETURN exclusion so shadow-edges2 becomes a genuine return-inclusive census tool. Requires --shadow-edges2=1.")
	    ("temporal-order-collect", bpo::value(&o.temporal_order_collect)->default_value(false), "A-line 2026-07-27 (Codex 7th audit P1): per-source order-1/order-2 lag-match collector (tcache.h temporal_order_cache) -- fully inline, no slowpath forcing, whole-run coverage (not an early-window sample), same 7-12%-class overhead precedent as shadow-edges2. Collects within the SAME profiling run that produces Wendell's own .prof, no extra full run needed.")
	    ("temporal-order-out", bpo::value(&o.temporal_order_out)->default_value(""), "dump temporal_order_cache's per-slot (source total lag1_match lag2_match) rows.")
	    ("temporal-order-all-jalr", bpo::value(&o.temporal_order_all_jalr)->default_value(false), "include canonical RETURN-idiom sites (shadow_track's default exclusion) -- this cycle's own real findings (expat 0001134c/000121cc) are polymorphic RETURN sites, so real measurement needs this on.")
	    ("gbrind-hitrate-collect", bpo::value(&o.gbrind_hitrate_collect)->default_value(false), "A-line Round 48: per-source L1 gbrind-cache hit/miss counter (tcache.h gbrind_hitrate_cache) -- independent of shadow_edges2 (hit/miss of the existing cache check, not target identity).")
	    ("gbrind-hitrate-out", bpo::value(&o.gbrind_hitrate_out)->default_value(""), "dump gbrind_hitrate_cache's per-slot (src_hash hit miss) triples. Requires --gbrind-hitrate-collect=1.")
	    ("shadow-majority", bpo::value(&o.shadow_majority)->default_value(false), "A-line Design 3 (post-H1/H2 single-run-economics redesign): per-TARGET online Boyer-Moore majority-vote counter piggybacked on the l1_brind_cache HIT path (Emit_gbrind), reusing its already-computed hash offset -- no new hash, no separate cache lookup base beyond one extra table-base load. Answers ApplyFDRE's actual question (which single source, if any, is this target's strict majority) directly with NO reconstruction pass. Requires --shadow-majority-out. Independent of --shadow-edges/-k.")
	    ("shadow-majority-out", bpo::value(&o.shadow_majority_out)->default_value(""), "path to dump the majority-vote table (target,candidate_src,counter,target_exec_count) as a --aot-fdre-edges-compatible (src dst weight) file after conservation-safe filtering")
	    ("sr-edges-all-misses", bpo::value(&o.sr_edges_all_misses)->default_value(false), "A-line 2026-07-23: with --sr-sampled-edges, record EVERY natural L1-miss slowpath visit (no decimation); natural-miss population is tiny (wasm3 350, sqlite 2082 per profiling run)")
	    ("sr-edges-epochs", bpo::value(&o.sr_edges_epochs)->default_value(false), "A-line B-cycle: geometric-epoch edge-set resampling -- flush the brind L1 at doubling-spaced ticks so edges absorbed by the target-keyed cache (poly-B false-exclusivity witness) are re-observed; converges the SET in log-many epochs, provides no weights")
	    ("qcg-leaf-inline", bpo::value(&o.qcg_leaf_inline)->default_value(false), "M-INL: direct-call leaf-return elision at translation -- inline scanned straight-line ret-terminated leaves (<=8 insns, no control/system/ra-clobber) into the call site; removes both transfer edges incl. the alternating return dispatch (the P12 +19.5% mechanism)")
	    ("qcg-jal-closure", bpo::value(&o.qcg_jal_closure)->default_value(false), "2026-07-28: continue QCG translation across a plain jal's statically-known target within the same page-bounded job instead of stopping the job there; amortizes the ~25.2us/job fixed compile cost across the merged blocks")
	    ("qcg-ic-lasttarget", bpo::value(&o.qcg_ic_lasttarget)->default_value(false), "M-IC-LT: with --qcg-dispatch-ic, repatch the site IC to the LAST observed target instead of first-wins")
	    ("sr-record-returns", bpo::value(&o.sr_record_returns)->default_value(false), "12:14 item A: with --brind-edges-out, ALSO record return edges (ret-PC -> continuation, exact counts) for one-shot polymorphic-return distribution measurement")
	    ("sr-web-repack", bpo::value(&o.sr_web_repack)->default_value(false), "A-line 9th cycle: SAME-RUN dispatch-web co-location -- when the epoch edge SET first goes dry, revoke every observed web member; the hot web burst-retranslates into consecutive pool space (adjacency by construction); counts carried; no indirect edges => never fires. Requires --sr-cheap-edges-out --sr-sampled-edges --sr-edges-all-misses --sr-edges-epochs")
	    ("qcg-dispatch-ic", bpo::value(&o.qcg_dispatch_ic)->default_value(false), "A-line 2026-07-23: self-patching per-site dispatch inline cache at the QCG tier -- the site's first natural slowpath miss patches a guarded direct jump (first-wins mono IC); no profile pass, no thresholds; exec-count attribution preserved")
	    ("qcg-dispatch-ic-site", bpo::value(&o.qcg_dispatch_ic_site)->default_value(""), "PM round-10 attribution instrumentation: with --qcg-dispatch-ic, restrict IC blob emission to this ONE guest TB entry IP (hex, e.g. 17ae4, no 0x prefix) for site-selective causal isolation; empty (default) = apply to every site, unchanged behavior")
	    ("qcg-dispatch-ic-regret", bpo::value(&o.qcg_ic_regret)->default_value(false), "PM round-10 P3: online, same-run, no-oracle self-verifying guard -- tracks each patched site's own hit/miss; the instant cumulative miss exceeds cumulative hit, permanently reverts that site's blob to the safe unpatched fallback. Implies --qcg-dispatch-ic. Prints QCG_IC_REGRET_REVERTED=<n> at exit.")
	    ("qcg-gbrind-outline", bpo::value(&o.qcg_gbrind_outline)->default_value(false), "A-line Round 60: move the QCG tier's inlined l1_brind_cache hit-check out-of-line into a single shared stub, trading a per-dispatch call for a smaller per-site compile footprint")
	    ("qcg-freq-scratch", bpo::value(&o.qcg_freq_scratch)->default_value(false), "WITNESS ONLY: replace Emit_Cache's hash-chain counting with a single scratch inc (wrong .prof, timing decomposition only)")
	    ("qcg-freq-sat", bpo::value(&o.qcg_freq_sat)->default_value(false), "A-line 2026-07-23: SATURATING frequency collection -- skip the count RMW once a TB's counter reaches T; provably preserves every d312b122 admission/region decision (all consumers are boolean/threshold/max/monotone-sum vs T, see config.h)")
	    ("qcg-freq-sat-t", bpo::value(&o.qcg_freq_sat_t)->default_value(262144), "saturation cap; MUST equal the elfaot --threshold of the same pipeline (Wendell's own admission constant)")
	    ("qcg-freq-edge", bpo::value(&o.qcg_freq_edge)->default_value(false), "A-line 2026-07-23: per-edge inline counters -- ONE RIP-relative inc per control transfer to a slot embedded after the TB's code, folded into per-TB counts at every profile write; exact-or-better than the shared-hash chain (collision undercount eliminated), edge-level direct/conditional counts become available")
	    ("qcg-ic-edges-out", bpo::value(&o.qcg_ic_edges_out)->default_value(""), "B-DIST probe: with --qcg-dispatch-ic, IC hit counters become exact per-(site,target) edge weights for each site's resident edge; dump 'site tgt count' here at exit (PROBE ONLY: diverts exec attribution on IC hits)")
	    ("qcg-freq-shadow-out", bpo::value(&o.qcg_freq_shadow_out)->default_value(""), "A-line shadow-equivalence probe: keep STOCK counting fully active AND an independent per-TB entry-arrival shadow counter in the SAME run; dump 'ip stock entry delta brind seg' lines to this path at exit")
	    ("qcg-freq-entry", bpo::value(&o.qcg_freq_entry)->default_value(false), "A-line 2026-07-23 v3: ENTRY-SIDE arrival counters -- one 13-byte counter at each TB entry replaces every source-side counting channel (same per-TB totals, collision undercount eliminated); slots fold into counts at profile writes; pair with --qcg-freq-retire for compact post-saturation retranslation")
	    ("qcg-freq-retire", bpo::value(&o.qcg_freq_retire)->default_value(false), "A-line 2026-07-23: SELF-RETIRING counters (SAT-1b) -- once a TB's counter reaches --qcg-freq-sat-t, every counting sequence targeting it is patched to a jmp over itself from a periodic host-stack sweep; provably preserves every d312b122 admission/region decision (frozen counts are >= T; all consumers are boolean/threshold/max/monotone-sum vs T); never-saturating programs run byte-identical stock code")
	    ("sr-gate-ms", bpo::value(&o.sr_gate_ms)->default_value(0L), "measured per-machine floor sum in ms (first fire waits for it); derived input, not a constant")
	    ("sr-descent", bpo::value(&o.sr_descent)->default_value(true), "ablation: geometric descent (0 = single build at T0)")
	    ("sr-census", bpo::value(&o.sr_census)->default_value(true), "ablation: decision layer (0 = descent-only)")
	    ("sr-ablate-realized", bpo::value(&o.sr_ablate_realized)->default_value(false), "B-line ablation: disable realized-benefit builder idling")
	    ("sr-ablate-promote", bpo::value(&o.sr_ablate_promote)->default_value(false), "B-line ablation: disable promote-evidence-doubling swap gate")
	    ("sr-ablate-updprof", bpo::value(&o.sr_ablate_updprof)->default_value(false), "attribution probe: skip per-tick UpdateProfile + growth dumps")
	    ("sr-ablate-regime-reset-parent", bpo::value(&o.sr_ablate_regime_reset_parent)->default_value(false), "B-line reset-necessity ablation: skip parent-side promo-window reset on regime flip")
	    ("sr-ablate-regime-reset-builder", bpo::value(&o.sr_ablate_regime_reset_builder)->default_value(false), "B-line reset-necessity ablation: skip builder-side regime-file propagation (DRY-head + built_mass reset)")
	    ("sr-realized-pend-check", bpo::value(&o.sr_realized_pend_check)->default_value(false), "R6-prime: realized no-gain idle consults builder pending-mass evidence; realized gain un-idles")
	    ("sr-census-flip-check", bpo::value(&o.sr_census_flip_check)->default_value(false), "R7-doubleprime: starvation-proof regime-flip detection via exec-count census (doubling-paced walks)")
	    ("sr-oracle-flip-at-ms", bpo::value(&o.sr_oracle_flip_at_ms)->default_value(0), "B-line round 10: fire the SAME CensusFlipWalk actions once at this wall-clock instant (ms since process start), bypassing detection -- an oracle/upper-bound arm, 0=disabled")
	    ("sr-unconditional-poll", bpo::value(&o.sr_unconditional_poll)->default_value(false), "V151 diag: consume the boot-pending poll at an unconditional Execute-loop heartbeat too, not just the brind slowpath")
	    ("sr-activation-invariant", bpo::value(&o.sr_activation_invariant)->default_value(false), "Line-B: gate census/override activation on exec_instr_seen * kDeltaMachineNsPerInstr > kCMachineNs (pay-after-evidence, zero workload knobs)")
	    ("sr-cf-no-override", bpo::value(&o.sr_cf_no_override)->default_value(false), "ABLATION: disable promotion override")
	    ("sr-cf-no-regime", bpo::value(&o.sr_cf_no_regime)->default_value(false), "ABLATION: disable regime write")
	    ("sr-cf-no-wake", bpo::value(&o.sr_cf_no_wake)->default_value(false), "ABLATION: disable builder wake")
	    ("sr-cf-no-reboot", bpo::value(&o.sr_cf_no_reboot)->default_value(false), "ABLATION: disable channel/top-slot reopen")
	    ("sr-cf-once", bpo::value(&o.sr_cf_once)->default_value(false), "ABLATION: flip actions once per episode (round-3 semantics)")
	    ("sr-cf-site", bpo::value(&o.sr_cf_site)->default_value(0), "ABLATION: 0=both walk sites 1=slowpath-only 2=keeper-only")
	    ("sr-cf-reset-gap-us", bpo::value(&o.sr_cf_reset_gap_us)->default_value(1), "V151 ablation: post-boot-reset CensusFlipWalk gap floor in us (default 1 = current behavior; a larger value avoids guaranteeing an immediate real scan on the very next tick after a boot)")
	    ("dvet", bpo::value(&o.dvet_enable)->default_value(false), "DVET: dual-variant epoch trial when the builder publishes trial_P.so/trial_S.so")
	    ("escalate-contradiction", bpo::value(&o.esc_contra)->default_value(true), "ablation: contradiction monitor (0 = decide-once)")
	    ("sr-chunk-threshold", bpo::value(&o.sr_chunk_threshold)->default_value(262144L), "single-run first-build admission threshold (default = Wendell's own)")
	    ("escalate-quality-proxy", bpo::value(&o.escalate_quality_proxy)->default_value(false), "2026-07-07: ALSO escalate when post-swap AOT samples-per-entry >= pre-swap QCG samples-per-entry (chunk code no faster than QCG => quality deficit); zero constants, needs time-census")
	    ("escalate-time-census", bpo::value(&o.escalate_time_census)->default_value(false), "2026-07-07: escalate decision uses SIGPROF TIME samples (AOT-range vs QCG-range) instead of TB-entry counts -- fixes the mediocre-keep boundary (entries != cycles); same sign test, zero constants")
	    ("sr-log-ratecontrol", bpo::value(&o.sr_log_ratecontrol)->default_value(false), "B-line round 7: log every coarsen/refine transition of the existing verdict-stability sampling-rate controller with a wall-clock timestamp (diagnostic-only, no behavior change)")
	    ("p1-promote", bpo::value(&o.p1_promote)->default_value(false), "P1 2026-07-23: in-run indirect-target promotion (self-healing exile). Pair with --aot=1. Re-enables QCG counting in the aot run (DC-1 undo), keeper-flushes the brind L1, and when the exiled-hot set (in-run count >= --p1-threshold) goes dry, ONE synchronous mid-run rebuild+boot fires (wall counted in-run). Without --p1-staging/--p1-elf/--p1-elfaot: observation-only (counters).")
	    ("p1-staging", bpo::value(&o.p1_staging)->default_value(""), "P1: builder workspace dir (receives the .prof copy, build log, p1.so)")
	    ("p1-elf", bpo::value(&o.p1_elf)->default_value(""), "P1: guest elf path for the mid-run elfaot build")
	    ("p1-elfaot", bpo::value(&o.p1_elfaot)->default_value(""), "P1: elfaot binary path")
	    ("p1-flush-ms", bpo::value(&o.p1_flush_ms)->default_value(50), "P1: keeper flush/scan-tick cadence in ms (bounds detection latency only, never a decision input)")
	    ("p1-threshold", bpo::value(&o.p1_threshold)->default_value(262144), "P1: promotion bar; MUST equal this pipeline's elfaot --threshold (Wendell's own admission constant, not a new knob)");
	// clang-format on

	try {
		bpo::variables_map vmap;
		bpo::store(bpo::parse_command_line(dbt_args.size(), dbt_args.data(), adesc), vmap);
		if (vmap.count("help")) {
			PrintHelp(adesc);
			return false;
		}
		if (guest_args.empty()) {
			std::cout << "Invalid arguments\n";
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

static void SetupConfig(ElfRunOptions &opts)
{
	dbt::config::merge_ls = opts.merge_ls;
	dbt::config::trace = opts.trace;
	dbt::config::use_aot = opts.use_aot;
	dbt::config::aot_reuse_path = opts.aot_reuse.empty() ? nullptr : opts.aot_reuse.c_str();
	dbt::config::aot_reuse_elf = opts.aot_reuse_elf.empty() ? nullptr : opts.aot_reuse_elf.c_str();
	dbt::config::not_freq = opts.not_freq;
	dbt::config::no_tb_clip = opts.no_tb_clip;
	dbt::config::tb_through_brind = opts.tb_through_brind;
	dbt::config::code_pad = opts.code_pad;
	dbt::config::count_brind = opts.count_brind;
	dbt::config::dump_region_hits = opts.dump_region_hits;
	dbt::config::aot_region_hit_count = opts.aot_region_hit_count;
	dbt::config::aot_count_gbrind = opts.aot_count_gbrind;
	dbt::config::aot_link_multientry_trace = opts.aot_link_multientry_trace;
	dbt::config::qcg_resident = opts.qcg_resident;
	dbt::config::qcg_pin = opts.qcg_pin;
	dbt::config::qcg_pin_k = opts.qcg_pin_k;
	dbt::config::profile_brind_edges = !opts.brind_edges_out.empty();
	dbt::config::sr_bounded_exhaustive_limit = opts.sr_bounded_exhaustive;
	dbt::config::sr_live_edges_dump = opts.sr_live_edges_dump;
	if (!opts.brind_edges_out.empty())
		dbt::config::brind_edges_out_path = strdup(opts.brind_edges_out.c_str());
	// CHEAP-OBSERVER FIX (2026-07-22): --brind-edges-out ALWAYS sets profile_brind_edges, which
	// forces EVERY indirect dispatch to skip the L1 cache and hit the full slowpath forever --
	// measured 25-30x wall-time inflation (0.95-1.39s -> 29.97-31.69s on dist_reversal3, 3 trials
	// each), which would destroy any candidate benefit if used as a live evidence source. New,
	// INDEPENDENT --sr-cheap-edges-out=<path> sets ONLY the dump path (does NOT touch
	// profile_brind_edges at all) -- pair with --sr-sampled-edges=1 (doubling-decimated, NATURAL-
	// slowpath-visit-only recording, already measured elsewhere this campaign at 0.16-1.6% of wall
	// time even at extreme scale) for a cheap live evidence source.
	if (!opts.sr_cheap_edges_out.empty())
		dbt::config::brind_edges_out_path = strdup(opts.sr_cheap_edges_out.c_str());
	dbt::config::inrun_revoke_watch = !opts.sr_revoke_watch.empty();
	if (!opts.sr_revoke_watch.empty()) {
		dbt::config::revoke_request_path = strdup(opts.sr_revoke_watch.c_str());
		// PollRevokeRequest() opens this with "r+" (never creates); pre-create it empty so the very
		// first poll tick doesn't just silently no-op before the controller has written anything.
		FILE *tf = fopen(opts.sr_revoke_watch.c_str(), "w");
		if (tf)
			fclose(tf);
	}
	dbt::config::tier_census = opts.tier_census;
	dbt::config::qcg_code_bytes = opts.qcg_code_bytes;
	dbt::config::measure_translation = opts.measure_translation;
	static std::string translate_ip_out_storage = opts.translate_ip_out;
	dbt::config::translate_ip_out = translate_ip_out_storage.empty() ? nullptr : translate_ip_out_storage.c_str();
	dbt::config::ngr = opts.ngr;
	dbt::config::ngr_verify = opts.ngr_verify;
	dbt::config::ngr_loops = opts.ngr_loops;
	dbt::config::fast_boot = opts.fast_boot;
	dbt::config::qcg_code_huge_pages = opts.qcg_code_huge_pages;
	// Accept only widths this implementation can actually honour: the legality bound is derived
	// from the implemented ELEN (the widest SEW the reference semantics compute on), not from an
	// independently chosen number, so --vlen can never select a vtype space we cannot execute.
	if (!dbt::rv32::vlen_supported(opts.vlen)) {
		std::cerr << "invalid --vlen=" << opts.vlen << " (must be a power of two in ["
			  << dbt::rv32::VLEN_MIN_BITS << ", " << dbt::rv32::VLEN_MAX_BITS
			  << "]; ELEN=" << dbt::rv32::ELEN_BITS << ")\n";
		std::exit(1);
	}
	dbt::config::vlen_bits = opts.vlen;
	if (opts.rvv_lowering > 1) {
		std::cerr << "invalid --rvv-lowering=" << opts.rvv_lowering << " (0=reference, 1=fixed-width)\n";
		std::exit(1);
	}
	dbt::config::rvv_lowering = opts.rvv_lowering;
	dbt::config::rvv_verify = opts.rvv_verify;
	dbt::config::rvv_stats = opts.rvv_stats;
	dbt::config::rvv_route_census = opts.rvv_route_census;
	dbt::config::rvv_direct = opts.rvv_direct;
	dbt::config::rvv_qcg_diag_chunk = opts.rvv_qcg_diag_chunk;
	dbt::config::rvv_qcg_diag_chunk_force_emit = opts.rvv_qcg_diag_chunk_force_emit;
	dbt::config::aot_use_llvm = opts.aot_use_llvm;
	dbt::config::rvv_qcg_typed_chunk = opts.rvv_qcg_typed_chunk;
	dbt::config::rvv_qcg_typed_chunk_force_emit = opts.rvv_qcg_typed_chunk_force_emit;
	dbt::config::rvv_qcg_typed_chunk_falu = opts.rvv_qcg_typed_chunk_falu;
	dbt::config::rvv_qcg_typed_chunk_falu_force_emit = opts.rvv_qcg_typed_chunk_falu_force_emit;
	dbt::config::rvv_qcg_typed_chunk_fma = opts.rvv_qcg_typed_chunk_fma;
	dbt::config::rvv_qcg_typed_chunk_fma_force_emit = opts.rvv_qcg_typed_chunk_fma_force_emit;
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
	dbt::config::rvv_qcg_typed_chunk_fsqrt_force_emit = opts.rvv_qcg_typed_chunk_fsqrt_force_emit;
	dbt::config::rvv_qcg_typed_chunk_fcmp = opts.rvv_qcg_typed_chunk_fcmp;
	dbt::config::rvv_qcg_typed_chunk_fcmp_force_emit = opts.rvv_qcg_typed_chunk_fcmp_force_emit;
	dbt::config::rvv_qcg_typed_chunk_fwiden = opts.rvv_qcg_typed_chunk_fwiden;
	dbt::config::rvv_qcg_typed_chunk_fwiden_fma = opts.rvv_qcg_typed_chunk_fwiden_fma;
	dbt::config::rvv_qcg_typed_chunk_fwiden_force_emit = opts.rvv_qcg_typed_chunk_fwiden_force_emit;
	dbt::config::rvv_qcg_typed_chunk_mul = opts.rvv_qcg_typed_chunk_mul;
	dbt::config::rvv_qcg_typed_chunk_mul_force_emit = opts.rvv_qcg_typed_chunk_mul_force_emit;
	dbt::config::rvv_qcg_typed_chunk_sub = opts.rvv_qcg_typed_chunk_sub;
	dbt::config::rvv_qcg_typed_chunk_sub_force_emit = opts.rvv_qcg_typed_chunk_sub_force_emit;
	dbt::config::rvv_qcg_typed_chunk_xor = opts.rvv_qcg_typed_chunk_xor;
	dbt::config::rvv_qcg_typed_chunk_shift = opts.rvv_qcg_typed_chunk_shift;
	dbt::config::rvv_qcg_typed_chunk_shift_force_emit = opts.rvv_qcg_typed_chunk_shift_force_emit;
	dbt::config::rvv_qcg_narrow_chunk_width = opts.rvv_qcg_narrow_chunk_width;
	dbt::config::rvv_qcg_narrow_chunk_width_force_emit = opts.rvv_qcg_narrow_chunk_width_force_emit;
	dbt::config::rvv_qcg_typed_chunk_xor_force_emit = opts.rvv_qcg_typed_chunk_xor_force_emit;
	dbt::config::rvv_qcg_typed_chunk_or = opts.rvv_qcg_typed_chunk_or;
	dbt::config::rvv_qcg_typed_chunk_or_force_emit = opts.rvv_qcg_typed_chunk_or_force_emit;
	dbt::config::rvv_qcg_typed_chunk_and = opts.rvv_qcg_typed_chunk_and;
	dbt::config::rvv_qcg_typed_chunk_and_force_emit = opts.rvv_qcg_typed_chunk_and_force_emit;
	dbt::config::rvv_qcg_typed_chunk_vle = opts.rvv_qcg_typed_chunk_vle;
	dbt::config::rvv_qcg_typed_chunk_vle_force_emit = opts.rvv_qcg_typed_chunk_vle_force_emit;
	dbt::config::rvv_qcg_typed_chunk_vse = opts.rvv_qcg_typed_chunk_vse;
	dbt::config::rvv_qcg_typed_chunk_vse_force_emit = opts.rvv_qcg_typed_chunk_vse_force_emit;
	dbt::config::rvv_qcg_typed_chunk_vlse_gather = opts.rvv_qcg_typed_chunk_vlse_gather;
	dbt::config::rvv_qcg_typed_chunk_vlse_gather_force_emit = opts.rvv_qcg_typed_chunk_vlse_gather_force_emit;
	dbt::config::rvv_qcg_typed_chunk_vlse_gather_census = opts.rvv_qcg_typed_chunk_vlse_gather_census;
	dbt::config::rvv_qcg_active_chunk_census = opts.rvv_qcg_active_chunk_census;
	dbt::config::rvv_qcg_direct_setvl = opts.rvv_qcg_direct_setvl;
	dbt::config::rvv_qcg_whole_reg = opts.rvv_qcg_whole_reg;
	dbt::config::rvv_qcg_vx_mulacc = opts.rvv_qcg_vx_mulacc;
	dbt::config::rvv_qcg_typed_chunk_vmv = opts.rvv_qcg_typed_chunk_vmv;
	dbt::config::rvv_qcg_typed_chunk_vmv_force_emit = opts.rvv_qcg_typed_chunk_vmv_force_emit;
	dbt::config::rvv_qcg_typed_chunk_vadd_scalar = opts.rvv_qcg_typed_chunk_vadd_scalar;
	dbt::config::rvv_qcg_typed_chunk_vadd_scalar_force_emit = opts.rvv_qcg_typed_chunk_vadd_scalar_force_emit;
	dbt::config::rvv_qcg_partial_vl = opts.rvv_qcg_partial_vl;
	dbt::config::rvv_qcg_fp_shared_mask = opts.rvv_qcg_fp_shared_mask;
	dbt::config::rvv_qcg_active_vl_bound = opts.rvv_qcg_active_vl_bound;
	dbt::config::rvv_qcg_active_vl_mask_fusion = opts.rvv_qcg_active_vl_mask_fusion;
	dbt::config::rvv_qcg_active_vl_int_bound = opts.rvv_qcg_active_vl_int_bound;
	dbt::config::rvv_qcg_active_mask_memory = opts.rvv_qcg_active_mask_memory;
	dbt::config::rvv_qcg_active_vl_narrow_bound = opts.rvv_qcg_active_vl_narrow_bound;
	dbt::config::rvv_qcg_active_vl_widen_bound = opts.rvv_qcg_active_vl_widen_bound;
	dbt::config::rvv_qcg_full_vl_fast_body = opts.rvv_qcg_full_vl_fast_body;
	dbt::config::rvv_qcg_typed_chunk_mem_e64 = opts.rvv_qcg_typed_chunk_mem_e64;
	dbt::config::rvv_qcg_vx_mulacc_force_emit = opts.rvv_qcg_vx_mulacc_force_emit;
	dbt::config::rvv_vector_run = opts.rvv_vector_run;
	dbt::config::rvv_run_scan_fast_reject = opts.rvv_run_scan_fast_reject;
	dbt::config::rvv_run_fp_store_masked_partial_vl = opts.rvv_run_fp_store_masked_partial_vl;
	dbt::config::rvv_run_fp_store_mask_reuse_shared = opts.rvv_run_fp_store_mask_reuse_shared;
	static std::string rvv_lane_census_out_storage = opts.rvv_lane_census_out;
	dbt::config::rvv_lane_census = !rvv_lane_census_out_storage.empty();
	dbt::config::rvv_lane_census_out = rvv_lane_census_out_storage.c_str();
	dbt::fault_snapshot::Configure(opts.fault_snapshot_plan.c_str(), opts.fault_snapshot_out.c_str());
	std::string ccrf_guest_elf = opts.guest_args.empty() ? "" : opts.fsroot + "/" + opts.guest_args[0];
	dbt::ccrf::Configure(opts.ccrf_certificate.c_str(), opts.ccrf_affine_facts.c_str(), ccrf_guest_elf.c_str(),
			     opts.ccrf_exact_qir.c_str(), opts.ccrf_result_out.c_str(), opts.ccrf_sequential,
			     opts.ccrf_concurrent, opts.ccrf_precompiled_sequential, opts.ccrf_require_avx512,
			     opts.ccrf_worker_cpu0, opts.ccrf_worker_cpu1);
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
	// P7L-B1. Same fail-closed discipline again, and one step stricter: the probe is an
	// instrument, so a configuration in which it cannot mean what it says must ABORT rather
	// than silently emit something else. `serial` needs a member-major SSA body inside a real
	// vector run -- in chunk-major order the sibling chunk of THIS member has not been computed
	// when the probe would read it, and with the materialize body or with runs off there is no
	// cross-operation chain for the probe to be about at all.
	if (opts.rvv_run_dep_probe == "indep") {
		dbt::config::rvv_run_dep_probe_cross = false;
	} else if (opts.rvv_run_dep_probe == "serial") {
		dbt::config::rvv_run_dep_probe_cross = true;
	} else {
		std::cerr << "--rvv-run-dep-probe must be 'indep' or 'serial', got '"
			  << opts.rvv_run_dep_probe << "'\n";
		std::exit(1);
	}
	// The membership-rule ablation factor. Fail closed on the one combination in which it cannot
	// mean anything: with --rvv-vector-run=0 no run is scanned at all, so an arm that asked for
	// scalar passthrough would silently be the same arm as one that did not.
	dbt::config::rvv_run_scalar_passthrough = opts.rvv_run_scalar_passthrough;
	if (dbt::config::rvv_run_scalar_passthrough && !dbt::config::rvv_vector_run) {
		std::cerr << "--rvv-run-scalar-passthrough requires --rvv-vector-run=1\n";
		std::exit(1);
	}
	// P7N-G. Fail closed on a combination in which the body cannot mean what the switch says.
	// Splitting rewrites the SSA body's load/store placement, so it needs that body; and it
	// deliberately keeps the member-major issue order, because turning the run chunk-major
	// dissolves the sibling-independence question this line exists to ask rather than answering
	// it. Refusing loudly is what keeps "splitting is on" from silently meaning something else.
	dbt::config::rvv_run_live_range_split = opts.rvv_run_live_range_split;
	if (dbt::config::rvv_run_live_range_split) {
		if (!dbt::config::rvv_vector_run || dbt::config::rvv_run_body_materialize ||
		    dbt::config::rvv_run_order_chunk_major) {
			std::cerr << "--rvv-run-live-range-split requires --rvv-vector-run=1, "
				     "--rvv-run-body=ssa and --rvv-run-order=member\n";
			std::exit(1);
		}
	}
	// P7M-E. Resolved AFTER the run/body switches above so it can refuse the combinations in
	// which it would silently report nothing. Without runs there is no multi-member frame to
	// register; under the LLVM backend the node's slot is simply ignored, so the switch would
	// produce an all-zero table that reads as "these frames never executed" rather than "this
	// backend does not carry the instrument" -- the exact failure mode `--rvv-qcg-hit-counter`
	// documents for `inline_hits=0`.
	dbt::config::rvv_run_frame_census = opts.rvv_run_frame_census;
	if (dbt::config::rvv_run_frame_census) {
		if (!dbt::config::rvv_vector_run || dbt::config::aot_use_llvm) {
			std::cerr << "--rvv-run-frame-census requires --rvv-vector-run=1 and "
				     "--aot-use-llvm 0\n";
			std::exit(1);
		}
	}
	// P7N-J. The value-epoch/cost-weighted surrogate is a rule INSIDE the splitting body, so the
	// one combination in which it cannot mean anything is the one where that body is not emitted:
	// with the split off the frame takes the fixed placement and this switch would silently be a
	// no-op arm rather than a factor. Checked AFTER the split's own validation so it reads the
	// resolved value and inherits every exclusion the split already refuses.
	dbt::config::rvv_run_split_value_weighted = opts.rvv_run_split_value_weighted;
	if (dbt::config::rvv_run_split_value_weighted && !dbt::config::rvv_run_live_range_split) {
		std::cerr << "--rvv-run-split-value-weighted requires --rvv-run-live-range-split=1\n";
		std::exit(1);
	}
	// P7O-1. The component-separable classifier switch, refused loudly in every combination in
	// which it cannot mean what it says. Without runs there is no descriptor to classify. The
	// materialize body and the live-range-splitting body each rewrite pass 1/2/3 with their own
	// residency model, so "one component at a time" would be a claim about a body that is not
	// emitted; and inside a single component's sub-body member-major and chunk-major are the
	// same order, so keeping both knobs would stop the ablation being one-factor. Checked after
	// --rvv-run-body, --rvv-run-order and --rvv-run-live-range-split have been resolved, so the
	// test reads their final values rather than the raw option strings.
	dbt::config::rvv_run_bounded_batches = opts.rvv_run_bounded_batches;
	if (opts.rvv_run_bounded_batches &&
	    (!dbt::config::rvv_vector_run || dbt::config::rvv_run_body_materialize ||
	     opts.rvv_run_component_separable || dbt::config::rvv_run_live_range_split ||
	     dbt::config::rvv_run_order_chunk_major || opts.rvv_run_dep_probe_depth)) {
		std::cerr << "--rvv-run-bounded-batches requires vector runs with the default SSA body\n";
		std::exit(1);
	}
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
	dbt::config::rvv_run_dep_probe_depth = opts.rvv_run_dep_probe_depth;
	if (dbt::config::rvv_run_dep_probe_depth) {
		if (!dbt::config::rvv_vector_run || dbt::config::rvv_run_body_materialize ||
		    dbt::config::rvv_run_order_chunk_major) {
			std::cerr << "--rvv-run-dep-probe-depth requires --rvv-vector-run=1, "
				     "--rvv-run-body=ssa and --rvv-run-order=member\n";
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
	// Rule S's anchor -- "the point after which this value never changes" -- would be wrong.
	// Checked last, so every switch it names has its final value.
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
	dbt::config::rvv_inject_fault = opts.rvv_inject_fault;
	dbt::config::rvv_census = opts.rvv_census;
	if (dbt::config::rvv_census > 2) {
		std::cerr << "invalid --rvv-census=" << dbt::config::rvv_census << " (0=off, 1=counts, 2=counts+cycles)\n";
		std::exit(1);
	}
	static std::string rvv_census_out_storage = opts.rvv_census_out;
	dbt::config::rvv_census_out = rvv_census_out_storage.c_str();
	dbt::config::rvv_pc_census = opts.rvv_pc_census;
	static std::string rvv_pc_census_out_storage = opts.rvv_pc_census_out;
	dbt::config::rvv_pc_census_out = rvv_pc_census_out_storage.c_str();
	// RVDBT_RVV_FAST lets the existing P11 correctness gates exercise the method without every
	// script growing a flag. The command-line option still wins when it is given.
	dbt::config::rvv_fast = opts.rvv_fast;
	dbt::config::rvv_fuse_pairs = opts.rvv_fuse_pairs;
	dbt::config::rvv_tail_round = opts.rvv_tail_round;
	dbt::config::rvv_preadmit_extent = opts.rvv_preadmit_extent;
	dbt::config::rvv_gather = opts.rvv_gather;
	dbt::config::rvv_fast_classes = opts.rvv_fast_classes;
	dbt::config::rvv_fround_batch = opts.rvv_fround_batch;
	dbt::config::rvv_fround_mxcsr_mode = opts.rvv_fround_mxcsr_mode;
	dbt::config::rvv_vfcmp_batch_mask = opts.rvv_vfcmp_batch_mask;
	dbt::config::rvv_fred_specialize = opts.rvv_fred_specialize;
	// Capture the process's own MXCSR bits outside RC/FLAGS exactly once, before any guest
	// instruction executes. Nothing in rvdbt ever writes FTZ/DAZ/exception-mask bits, so this
	// is the constant that modes 1 and 2 substitute for the per-run STMXCSR read.
	dbt::config::g_mxcsr_resting =
	    dbt::rv32::rvdbt_mxcsr_get() &
	    ~(dbt::rv32::FRound::MXCSR_RC | dbt::rv32::FRound::MXCSR_FLAGS);
	dbt::config::rvv_fround_oracle_mode = opts.rvv_fround_oracle_mode;
	static std::string rvv_fround_oracle_file_storage = opts.rvv_fround_oracle_file;
	dbt::config::rvv_fround_oracle_file = rvv_fround_oracle_file_storage.c_str();
	if (dbt::config::rvv_fround_oracle_mode > 2) {
		std::cerr << "invalid --rvv-fround-oracle-mode=" << dbt::config::rvv_fround_oracle_mode
			  << " (0=off, 1=record, 2=replay)\n";
		std::exit(1);
	}
	if (dbt::config::rvv_fround_oracle_mode && rvv_fround_oracle_file_storage.empty()) {
		std::cerr << "--rvv-fround-oracle-mode requires --rvv-fround-oracle-file\n";
		std::exit(1);
	}
	if (dbt::config::rvv_fround_oracle_mode == 2)
		dbt::rv32::rvv_fast::fround_oracle_load(dbt::config::rvv_fround_oracle_file);
	dbt::config::rvv_width_policy = opts.rvv_width_policy;
	dbt::config::rvv_scalar_fround_run = opts.rvv_scalar_fround_run;
	dbt::config::rvv_scalar_fround_rcmirror = opts.rvv_scalar_fround_rcmirror;
	dbt::config::rvv_fixed_copy = opts.rvv_fixed_copy;
#ifdef RVDBT_ASYNC_SIGNAL_PROBE
	async_probe_start();
#endif
	if (!opts.rvv_fast) {
		char const *e = getenv("RVDBT_RVV_FAST");
		if (e && e[0] == '1')
			dbt::config::rvv_fast = true;
	}
	dbt::config::rvv_probe = opts.rvv_probe;
	static std::string rvv_probe_out_storage = opts.rvv_probe_out;
	dbt::config::rvv_probe_out = rvv_probe_out_storage.c_str();
	rvv_run_hoist = opts.rvv_run_hoist ? 1u : 0u;
	rvv_run_unroll2 = opts.rvv_run_unroll2 ? 1u : 0u;
	dbt::config::rvv_seqtrace = opts.rvv_seqtrace_out.empty() ? 0 : 1;
	if (dbt::config::rvv_seqtrace && !dbt::rv32::seqtrace::kEnabled) {
		// Fail at startup, not after a possibly long run: a binary built with
		// RVDBT_SEQTRACE=0 has literally no recording code (verified by disassembly), so
		// honouring this flag silently would produce an empty or absent trace that looks
		// identical to "nothing interesting happened" instead of "wrong binary".
		std::cerr << "--rvv-seqtrace-out requires a binary built with RVDBT_SEQTRACE=1; this "
			     "one was built without it\n";
		std::exit(1);
	}
	static std::string rvv_seqtrace_out_storage = opts.rvv_seqtrace_out;
	dbt::config::rvv_seqtrace_out = rvv_seqtrace_out_storage.c_str();
	if (dbt::config::rvv_census)
		dbt::rv32::rvv_census::start();
	dbt::config::tier0_lazy = opts.tier0_lazy;
	dbt::config::tier0_threshold = opts.tier0_threshold;
	dbt::config::profile_load_values = !opts.load_values_out.empty();
	dbt::config::phase_window = !opts.phase_windows_out.empty() && opts.phase_window_insns > 0;
	dbt::config::phase_window_insns = opts.phase_window_insns;
	dbt::config::phase_window_max = opts.phase_window_max;
	static std::string phase_out_storage = opts.phase_windows_out;
	dbt::config::phase_window_out_path = phase_out_storage.empty() ? nullptr : phase_out_storage.c_str();
	dbt::config::aot_profile_merge = opts.update_profile_on_aot;
	// A-line 2026-07-23: this assignment used to sit inside the `if (opts.inrun_auto_escalate)` block,
	// making --sr-sampled-edges silently inert without the whole escalation machinery. The observer is
	// independent of escalation; hoist it (default false, so default behavior is unchanged).
	dbt::config::sr_sampled_edges = opts.sr_sampled_edges;
	dbt::config::shadow_edges = opts.shadow_edges;
	dbt::config::shadow_edges_k =
	    std::min(opts.shadow_edges_k, (unsigned)dbt::tcache::ShadowEdgeKSlot::kMaxK); // H2: CLI-side clamp
	dbt::config::shadow_majority = opts.shadow_majority;
	dbt::config::shadow_edges2 = opts.shadow_edges2;
	dbt::config::shadow_edges2_all_jalr = opts.shadow_edges2_all_jalr;
	dbt::config::gbrind_hitrate_collect = opts.gbrind_hitrate_collect;
	dbt::config::temporal_order_collect = opts.temporal_order_collect;
	dbt::config::temporal_order_all_jalr = opts.temporal_order_all_jalr;
	dbt::config::sr_edges_all_misses = opts.sr_edges_all_misses;
	dbt::config::qcg_dispatch_ic = opts.qcg_dispatch_ic || opts.qcg_ic_regret;
	dbt::config::qcg_dispatch_ic_site =
		opts.qcg_dispatch_ic_site.empty() ? 0u : (unsigned)strtoul(opts.qcg_dispatch_ic_site.c_str(), nullptr, 16);
	dbt::config::qcg_ic_regret = opts.qcg_ic_regret;
	dbt::config::qcg_gbrind_outline = opts.qcg_gbrind_outline;
	dbt::config::qcg_freq_scratch = opts.qcg_freq_scratch;
	dbt::config::qcg_freq_sat = opts.qcg_freq_sat;
	dbt::config::qcg_freq_sat_t = opts.qcg_freq_sat_t;
	dbt::config::qcg_freq_edge = opts.qcg_freq_edge;
	dbt::config::qcg_freq_retire = opts.qcg_freq_retire;
	dbt::config::qcg_freq_entry = opts.qcg_freq_entry;
	dbt::config::sr_edges_epochs = opts.sr_edges_epochs;
	dbt::config::sr_web_repack = opts.sr_web_repack;
	dbt::config::qcg_leaf_inline = opts.qcg_leaf_inline;
	dbt::config::qcg_jal_closure = opts.qcg_jal_closure;
	dbt::config::qcg_ic_lasttarget = opts.qcg_ic_lasttarget;
	dbt::config::sr_record_returns = opts.sr_record_returns;
	// T5d-0: set unconditionally, NOT inside the --inrun-auto-escalate block below. The safepoint
	// is a property of QCG code generation and has to be settable on a run with no tier at all --
	// that is exactly how its own focused evidence (emitted shape, forward-edge invariance, and
	// the flag-off byte-identity check) is collected.
	dbt::config::qcg_backedge_safepoint = opts.qcg_backedge_safepoint;
	// THE ADMISSION BAR, set unconditionally. It used to be assigned only inside the
	// --inrun-auto-escalate block, which was harmless while that tier was its only reader: a run
	// that passed --sr-chunk-threshold without it simply had the option ignored. T5d2a adds a
	// SECOND reader, and leaving the assignment there would have made the loop tier silently use
	// the 262144 default no matter what the command line said -- so its below-bar control would
	// have "waited" for the right reason by accident and for the wrong one in fact. Moving it here
	// changes nothing for any existing arm (nothing else reads this field, and the escalate block
	// assigned the same value) and makes the option mean what it says for both readers.
	dbt::config::sr_chunk_threshold = opts.sr_chunk_threshold;
	// T5d2a. Set here, next to the safepoint it depends on and outside every tier block, for the
	// same reason: the loop tier is its own path and must not be reachable only through some other
	// mode's configuration. The strings are held in statics because config keeps `char const *`.
	dbt::config::loop_tier = opts.loop_tier;
	dbt::config::loop_tier_side_exit = opts.loop_tier_side_exit; // T5d2a3
	dbt::config::loop_tier_completion_exit = opts.loop_tier_completion_exit; // T5d2b0
	dbt::config::loop_tier_load = opts.loop_tier_load; // T5d2b1
	dbt::config::loop_tier_install = opts.loop_tier_install; // T5d2b2
	dbt::config::loop_tier_exit_cancel = opts.loop_tier_exit_cancel;
	dbt::config::loop_tier_route_census = opts.loop_tier_route_census; // C5c (read-only diagnostic)
	{
		static std::string lt_elfaot = opts.loop_tier_elfaot;
		static std::string lt_elf = opts.loop_tier_elf;
		static std::string lt_stage = opts.loop_tier_stage;
		if (!lt_elfaot.empty())
			dbt::config::loop_tier_elfaot = lt_elfaot.c_str();
		if (!lt_elf.empty())
			dbt::config::loop_tier_elf = lt_elf.c_str();
		if (!lt_stage.empty())
			dbt::config::loop_tier_stage = lt_stage.c_str();
	}
	if (!opts.qcg_ic_edges_out.empty()) {
		static std::string ic_edges_storage = opts.qcg_ic_edges_out;
		dbt::config::qcg_ic_edges_out = ic_edges_storage.c_str();
		dbt::config::qcg_ic_edge_count = true;
		dbt::config::qcg_dispatch_ic = true;
	}
	if (!opts.qcg_freq_shadow_out.empty()) {
		static std::string shadow_out_storage = opts.qcg_freq_shadow_out;
		dbt::config::qcg_freq_shadow_out = shadow_out_storage.c_str();
	}
	dbt::config::inrun_tier = opts.inrun_tier;
	static std::string inrun_artifact_storage = opts.inrun_artifact;
	if (!inrun_artifact_storage.empty())
		dbt::config::inrun_artifact_path = inrun_artifact_storage.c_str();
	// Round-40: parse the armed-artifact sequence (comma-separated). Stable static storage backs the
	// config char* array. Presence implies inrun-tier (QCG start + poll channel).
	static std::vector<std::string> inrun_seq_storage;
	if (opts.inrun_auto_escalate) {
		dbt::config::inrun_auto_escalate = true;
		dbt::config::escalate_time_census = opts.escalate_time_census;
		dbt::config::sr_log_ratecontrol = opts.sr_log_ratecontrol;
		dbt::config::escalate_quality_proxy = opts.escalate_quality_proxy;
		dbt::config::inrun_single_run = opts.single_run;
		dbt::config::inrun_evidence_gate = opts.inrun_evidence_gate;
		dbt::config::inrun_escape_unlink = opts.inrun_escape_unlink;
		dbt::config::aot_loop_entry = opts.aot_loop_entry;
		dbt::config::inrun_observe_only = opts.inrun_observe_only;
		dbt::config::esc_full_ski_gate = opts.esc_ski_full;
		dbt::config::sr_descent = opts.sr_descent;
		dbt::config::sr_gate_ms = opts.sr_gate_ms;
		dbt::config::sr_census = opts.sr_census;
		dbt::config::sr_ablate_realized = opts.sr_ablate_realized;
		dbt::config::sr_ablate_promote = opts.sr_ablate_promote;
		dbt::config::sr_ablate_updprof = opts.sr_ablate_updprof;
		dbt::config::sr_ablate_regime_reset_parent = opts.sr_ablate_regime_reset_parent;
		dbt::config::sr_ablate_regime_reset_builder = opts.sr_ablate_regime_reset_builder;
		dbt::config::sr_realized_pend_check = opts.sr_realized_pend_check;
		dbt::config::sr_census_flip_check = opts.sr_census_flip_check;
		dbt::config::sr_oracle_flip_at_ms = opts.sr_oracle_flip_at_ms;
		dbt::config::sr_unconditional_poll = opts.sr_unconditional_poll;
		dbt::config::sr_activation_invariant = opts.sr_activation_invariant;
		dbt::config::sr_cf_no_override = opts.sr_cf_no_override;
		dbt::config::sr_cf_no_regime = opts.sr_cf_no_regime;
		dbt::config::sr_cf_no_wake = opts.sr_cf_no_wake;
		dbt::config::sr_cf_no_reboot = opts.sr_cf_no_reboot;
		dbt::config::sr_cf_once = opts.sr_cf_once;
		dbt::config::sr_cf_site = opts.sr_cf_site;
		dbt::config::sr_cf_reset_gap_us = opts.sr_cf_reset_gap_us;
		dbt::config::dvet_enable = opts.dvet_enable;
		dbt::config::escalate_contradiction = opts.esc_contra;
		dbt::config::escalate_run_cache = strdup(opts.cache.c_str());
		dbt::config::aot_profile_merge = true; // F3: chunk-promoted blocks report exec=0; MAX-merge keeps
						       // their true hotness so the full build optimizes them properly
		if (!opts.escalate_elfaot.empty())
			dbt::config::escalate_elfaot = strdup(opts.escalate_elfaot.c_str());
		if (!opts.escalate_cache.empty())
			dbt::config::escalate_cache = strdup(opts.escalate_cache.c_str());
		if (!opts.escalate_elf.empty())
			dbt::config::escalate_elf = strdup(opts.escalate_elf.c_str());
	}
	if (!opts.inrun_artifact_seq.empty()) {
		std::stringstream ss(opts.inrun_artifact_seq);
		std::string item;
		while (std::getline(ss, item, ',')) {
			if (!item.empty() && inrun_seq_storage.size() < (size_t)dbt::config::kInrunSeqMax)
				inrun_seq_storage.push_back(item);
		}
		for (size_t i = 0; i < inrun_seq_storage.size(); ++i)
			dbt::config::inrun_seq_paths[i] = inrun_seq_storage[i].c_str();
		dbt::config::inrun_seq_n = (int)inrun_seq_storage.size();
		if (dbt::config::inrun_seq_n > 0)
			dbt::config::inrun_tier = true;
	}
	dbt::config::inrun_flush_ms = opts.inrun_flush_ms;
	// P1 (2026-07-23): in-run indirect-target promotion. Path storages are static (config keeps
	// raw char*); the run cache doubles as the live .prof source for the staging copy.
	dbt::config::p1_promote = opts.p1_promote;
	if (opts.p1_promote) {
		static std::string p1_staging_storage = opts.p1_staging;
		static std::string p1_elf_storage = opts.p1_elf;
		static std::string p1_elfaot_storage = opts.p1_elfaot;
		static std::string p1_run_cache_storage = opts.cache;
		if (!p1_staging_storage.empty())
			dbt::config::p1_staging = p1_staging_storage.c_str();
		if (!p1_elf_storage.empty())
			dbt::config::p1_elf = p1_elf_storage.c_str();
		if (!p1_elfaot_storage.empty())
			dbt::config::p1_elfaot = p1_elfaot_storage.c_str();
		dbt::config::p1_run_cache = p1_run_cache_storage.c_str();
		dbt::config::p1_flush_ms = opts.p1_flush_ms;
		dbt::config::p1_threshold = opts.p1_threshold;
	}
}

// Round-17 BCT: while un-booted, periodically clear the l1 brind cache so indirect transfers (incl returns)
// revisit the slowpath -- the promotion channel stays open even after QCG warms up. Same-thread signal: safe.
static void bct_alarm_handler(int)
{
	// FLUSH ACTOR (8th evidence-doubling actor): flushing the brind L1 cache every tick forces slowpath
	// escapes for poll/eval, but the REFILL cost scales with the dispatch working set (sqlite 10k TBs:
	// the measured +6~8pp floor; switch/dispatch tiny sets: ~0). Geometric schedule for the baseline
	// census escape + IMMEDIATE flush when there is real work (artifact file present / builder request
	// pending) -- both access() checks are async-signal-safe. Decision latency now doubles like every
	// other actor; responsiveness to actual events is unchanged.
	// FLUSH v2 -- starvation-only rule (FLUSHFIX raw): flush COST scales with the dispatch working set
	// while flush NEED scales inversely. sqlite (10k TBs, abundant natural escapes): flushes cost +7pp
	// and buy nothing -> never flush. aes (compute-tight, no natural escapes): flushes are its ONLY
	// evaluator/boot channel and its refill is nearly free -> flush every starved tick (v1's geometric
	// decay starved it: -54~-66 -> -36.3, ESC 1000->2600ms). Rule: flush iff the evaluator did not run
	// since the previous tick. Zero constants, self-adapting per phase.
	static unsigned long bct_tick = 0, last_eval_seen = 0;
	bct_tick++;
	bool starved = (dbt::config::esc_eval_count == last_eval_seen);
	last_eval_seen = dbt::config::esc_eval_count;
	bool flush_now = starved;
	if (!flush_now && dbt::config::escalate_cache) {
		char wp[4096];
		snprintf(wp, sizeof wp, "%s/wantprof", dbt::config::escalate_cache);
		if (access(wp, F_OK) == 0)
			flush_now = true; // builder freshness request pending: ack next escape
	}
	if (!flush_now && dbt::config::inrun_seq_n > 0 && dbt::config::inrun_seq_idx < dbt::config::inrun_seq_n) {
		char const *np = dbt::config::inrun_seq_paths[dbt::config::inrun_seq_idx];
		if (np && access(np, F_OK) == 0)
			flush_now = true; // next artifact landed: boot next escape
	}
	// R-FAMILY-7 (2026-07-19, perwalk xalan_1: 12 small boots exhausted the seq window by t=33s, the
	// k=13 big build landed on rung_11 at t=117.8s, and the TOP-SLOT RE-BOOT never fired because this
	// flush gate stops checking once idx>=n -- the poll pause's release (a re-boot candidate) was
	// starved by the pause itself. With census-flip on, the top slot is re-bootable at any time: keep
	// checking its mtime after the window is exhausted.)
	if (!flush_now && dbt::config::sr_census_flip_check && dbt::config::inrun_seq_n > 0 &&
	    dbt::config::inrun_seq_idx >= dbt::config::inrun_seq_n) {
		char const *tp = dbt::config::inrun_seq_paths[dbt::config::inrun_seq_n - 1];
		if (tp && access(tp, F_OK) == 0)
			flush_now = true; // top-slot re-boot candidate: let the presence check judge mtime
	}
	if (dbt::config::inrun_tier && !dbt::config::inrun_booted) {
		if (flush_now) {
			dbt::tcache::FlushBrindCache();
			dbt::config::inrun_flush_count++;
		}
		dbt::config::inrun_poll_due = true; // time-based poll: next slowpath visit checks for the artifact
	}
	// auto-escalate: after the first artifact booted (seq idx advanced) and not yet escalated, tick the
	// host-stack evaluator. Flag only -- census walks a std::map and must NOT run in a signal handler.
	// ALSO flush the brind cache: pure-compute loops never syscall, so the slowpath escape (below, jitabi)
	// is the only reliable path back to the Execute loop where the evaluation may run.
	if (dbt::config::inrun_auto_escalate &&
	    true && // re-opens unlimited under the no-rebuild-on-unchanged-evidence invariant
	    (dbt::config::inrun_seq_idx > 0 || (dbt::config::inrun_single_run && !dbt::config::sr_first_fired) ||
	     // wantprof handshake liveness: between first fire and first boot the evaluator used to be
	     // dormant -- the builder's freshness request then stalled into its 2000ms timeout (SQFIX raw:
	     // deterministic boot at 2250ms / decision at 2350ms on EVERY workload, switch -72.8 -> -58.0).
	     // Keep the evaluator ticking while the builder lives; pre-boot decision paths self-gate.
	     (dbt::config::inrun_single_run && dbt::config::inrun_builder_pid > 0))) {
		if (flush_now)
			dbt::tcache::FlushBrindCache();
		dbt::config::inrun_escalate_due = true;
	}
	// T5c-0 DIRECT-LINK ESCAPE (--inrun-escape-unlink, default off). The flush above only helps a
	// loop that executes an indirect transfer the L1 was absorbing. A pure-compute leaf loop executes
	// none, so nothing above can bring control back to Execute() and the pending escalate/boot flags
	// are never consumed -- measured on PolyBench gemm: 113 ticks, 17 escapes, all outside the timed
	// kernel. Returning a bounded set of recently linked DIRECT slots to the lazy-JIT stub reopens
	// the SAME existing channel. Armed only while the tier still has something to do; once booted,
	// the escape stops and the run is back to unmodified behaviour.
	if (dbt::config::inrun_escape_unlink && dbt::config::inrun_tier && !dbt::config::inrun_booted &&
	    (dbt::config::inrun_escalate_due || dbt::config::inrun_poll_due)) {
		unsigned n = dbt::tcache::UnlinkRecorded();
		if (n) {
			dbt::config::esc_unlink_ticks++;
			dbt::config::esc_unlink_slots += n;
		}
	}
}

// Round-26 self-profiler: ITIMER_PROF fires SIGPROF in process CPU time; the handler records the
// interrupted host RIP (async-signal-safe store into a preallocated ring). Resolved offline
// against --dump-tbmap ranges -> per-guest-region QCG time attribution.
static constexpr size_t kSelfProfMax = 1u << 22;
static unsigned long long *g_selfprof_buf;
static volatile size_t g_selfprof_n = 0;
static void selfprof_handler(int, siginfo_t *, void *uc)
{
	if (g_selfprof_n < kSelfProfMax) {
		auto *ctx = (ucontext_t *)uc;
		g_selfprof_buf[g_selfprof_n] = (unsigned long long)ctx->uc_mcontext.gregs[REG_RIP];
		g_selfprof_n = g_selfprof_n + 1;
	}
}

// A-line Round 40: independent (RIP,RAX) sampler, same substrate as selfprof_handler above but a
// separate buffer/handler so --selfprof-out's existing single-column output format is untouched.
static constexpr size_t kDispatchSelfProfMax = 1u << 22;
static unsigned long long *g_dispatch_selfprof_rip;
static unsigned long long *g_dispatch_selfprof_rax;
static volatile size_t g_dispatch_selfprof_n = 0;
static void dispatch_selfprof_handler(int, siginfo_t *, void *uc)
{
	if (g_dispatch_selfprof_n < kDispatchSelfProfMax) {
		auto *ctx = (ucontext_t *)uc;
		g_dispatch_selfprof_rip[g_dispatch_selfprof_n] = (unsigned long long)ctx->uc_mcontext.gregs[REG_RIP];
		g_dispatch_selfprof_rax[g_dispatch_selfprof_n] = (unsigned long long)ctx->uc_mcontext.gregs[REG_RAX];
		g_dispatch_selfprof_n = g_dispatch_selfprof_n + 1;
	}
}

// A-line SAT-1b tick: request a sweep and open the escape channel (flush the brind L1 so even
// compute-tight guests reach the slowpath within the tick). Same-thread flag store + dirty-list
// poison, following the bct/wmax handler precedents. The period bounds only the DETECTION LATENCY
// of an already-decision-irrelevant saturation, never any admission decision.
static void sat_alarm_handler(int)
{
	// geometric-epoch edge resampling: every eval tick opens one observation window (see config.h).
	// Composes with the retirement sweep (ablation caught the early-return making full-mode
	// retirement inert): the flush serves both channels; sweep_due lets the Execute loop sweep.
	if (dbt::config::sr_edges_epochs) {
		dbt::config::sat_tick = dbt::config::sat_tick + 1;
		// web-repack probe trigger: PER-TICK stagnation check (read-only). The set can only grow
		// at flushes or organic misses; one full tick with zero growth after at least one flush
		// epoch = earliest stability event. Fires once.
		if (dbt::config::sr_web_repack && !dbt::config::web_repacked &&
		    dbt::config::epochs_flushes > 0) {
			unsigned long ec_now = dbt::brindedges::Count();
			static unsigned long last_tick_count = 0;
			if (ec_now == last_tick_count && ec_now > 0)
				dbt::config::web_repack_due = true;
			last_tick_count = ec_now;
		}
		if (!dbt::config::epochs_done && dbt::config::sat_tick >= dbt::config::sat_next_eval_tick) {
			// dry-stop audit (see config.h): converged set => stop paying for flushes
			unsigned long ec = dbt::brindedges::Count();
			if (ec == dbt::config::epochs_last_edge_count) {
				// web-repack fires at the FIRST dry observation (earliest event
				// indicating set stability; flushing continues until k=2)
				if (dbt::config::sr_web_repack && !dbt::config::web_repacked)
					dbt::config::web_repack_due = true;
				if (++dbt::config::epochs_dry >= 2)
					dbt::config::epochs_done = true;
			} else {
				dbt::config::epochs_dry = 0;
				dbt::config::epochs_last_edge_count = ec;
			}
			if (!dbt::config::epochs_done) {
				dbt::tcache::FlushBrindCache();
				dbt::config::epochs_flushes++;
			} else if (dbt::config::sr_web_repack && !dbt::config::web_repacked) {
				// web-repack trigger: the edge SET just went dry (converged) --
				// event-driven, no added constant
				dbt::config::web_repack_due = true;
			}
			dbt::config::sat_backoff *= 2;
			dbt::config::sat_next_eval_tick = dbt::config::sat_tick + dbt::config::sat_backoff;
		}
		if (dbt::config::qcg_freq_retire && !dbt::config::sat_all_retired)
			dbt::config::sat_sweep_due = true;
		return;
	}
	if (!dbt::config::sat_all_retired) {
		// doubling backoff: sweeps that retire nothing get exponentially rarer (reset on any
		// retirement or new site registration) -- bounds the long-run channel cost to O(log)
		// events per phase instead of one per tick for the whole run.
		dbt::config::sat_tick = dbt::config::sat_tick + 1;
		if (dbt::config::sat_tick < dbt::config::sat_next_eval_tick)
			return;
		// starvation rule (bct precedent, zero constants): flush the brind L1 ONLY if the
		// previous request was never consumed -- i.e. no natural slowpath visit reached the
		// Execute loop since then. Dispatch-dense guests never pay the flush.
		if (dbt::config::sat_sweep_due)
			dbt::tcache::FlushBrindCache();
		dbt::config::sat_sweep_due = true;
	}
}

// Round-23 W_max sampler: 50ms windows; the handler records the cumulative slowpath-visit counter and
// re-poisons the dirty list (keeper-like channel). Preallocated; async-signal-safe (stores only).
static constexpr size_t kWmaxMaxWindows = 1u << 20;
static unsigned long long *g_wmax_samples;
static volatile size_t g_wmax_n = 0;
static void wmax_alarm_handler(int)
{
	if (g_wmax_n < kWmaxMaxWindows) {
		g_wmax_samples[g_wmax_n] = dbt::config::wmax_visit_count;
		g_wmax_n = g_wmax_n + 1;
	}
	dbt::tcache::FlushBrindCache(); // keep the channel open exactly like the deployment keeper
}

// P1 keeper tick (BCT bounce-channel precedent): the targeted brind-L1 flush forces indirect
// transfers back through the slowpath, which is both the evidence channel (re-enabled counting
// accumulates while dispatch keeps moving) and the escape channel for the host-stack scan/fire.
// Same-thread signal, flag stores + dirty-list poison only (async-signal-safe by the bct/wmax
// precedents). Stops itself once the one-shot promotion fired.
static void p1_alarm_handler(int)
{
	if (!dbt::config::p1_fired) {
		dbt::tcache::FlushBrindCache();
		dbt::config::p1_scan_due = true;
	}
}

// T5d2a1 REMOVED THE LOOP TIER'S KEEPER. There was a `loop_tier_alarm_handler` here that set the
// service bit on a fixed cadence; the request is now raised by the guest's own execution -- the
// crossing test QEmit::Emit_Cache appends to a direct backward edge's counter update (qemit.cpp).
// The loop tier installs no signal handler and arms no interval timer, which
// scripts/loop_tier_timer_audit.py checks against this file rather than against a claim.

int main(int argc, char **argv)
{
	ElfRunOptions opts;
	if (!ParseOptions(opts, argc, argv)) {
		return 1;
	}
	auto gargs = opts.guest_args;

	SetupConfig(opts);
	SetupLogger(opts.logs);

	dbt::fsmanager::Init(opts.cache.c_str());
	dbt::objprof::Init(opts.cache.c_str(), opts.use_aot);
	dbt::mmu::Init();
	dbt::tcache::Init();

	if (!opts.selfprof_out.empty()) {
		g_selfprof_buf = new unsigned long long[kSelfProfMax];
		struct sigaction sa{};
		sa.sa_sigaction = selfprof_handler;
		sa.sa_flags = SA_RESTART | SA_SIGINFO;
		sigaction(SIGPROF, &sa, nullptr);
		struct itimerval tv{};
		tv.it_interval.tv_usec = 1000;
		tv.it_value.tv_usec = 1000;
		setitimer(ITIMER_PROF, &tv, nullptr);
	}
	if (!opts.dispatch_selfprof_out.empty()) {
		g_dispatch_selfprof_rip = new unsigned long long[kDispatchSelfProfMax];
		g_dispatch_selfprof_rax = new unsigned long long[kDispatchSelfProfMax];
		struct sigaction sa{};
		sa.sa_sigaction = dispatch_selfprof_handler;
		sa.sa_flags = SA_RESTART | SA_SIGINFO;
		sigaction(SIGPROF, &sa, nullptr);
		struct itimerval tv{};
		tv.it_interval.tv_usec = 1000;
		tv.it_value.tv_usec = 1000;
		setitimer(ITIMER_PROF, &tv, nullptr);
	}
	if (!opts.wmax_sample_out.empty()) {
		dbt::config::wmax_sample = true;
		g_wmax_samples = new unsigned long long[kWmaxMaxWindows];
		struct sigaction sa{};
		sa.sa_handler = wmax_alarm_handler;
		sa.sa_flags = SA_RESTART;
		sigaction(SIGALRM, &sa, nullptr);
		struct itimerval tv{};
		tv.it_interval.tv_usec = 50 * 1000;
		tv.it_value.tv_usec = 50 * 1000;
		setitimer(ITIMER_REAL, &tv, nullptr);
	}
	if (dbt::config::qcg_freq_retire || dbt::config::sr_edges_epochs) {
		struct sigaction sa{};
		sa.sa_handler = sat_alarm_handler;
		sa.sa_flags = SA_RESTART; // guest syscalls must not see EINTR
		sigaction(SIGALRM, &sa, nullptr);
		struct itimerval tv{};
		tv.it_interval.tv_usec = 50 * 1000;
		tv.it_value.tv_usec = 50 * 1000;
		setitimer(ITIMER_REAL, &tv, nullptr);
	}
	if (dbt::config::inrun_tier) {
		struct timespec ts0;
		clock_gettime(CLOCK_MONOTONIC, &ts0);
		dbt::config::inrun_start_ms = ts0.tv_sec * 1000L + ts0.tv_nsec / 1000000L;
		struct sigaction sa{};
		sa.sa_handler = bct_alarm_handler;
		sa.sa_flags = SA_RESTART; // guest syscalls must not see EINTR
		sigaction(SIGALRM, &sa, nullptr);
		struct itimerval tv{};
		tv.it_interval.tv_usec = dbt::config::inrun_flush_ms * 1000;
		tv.it_value.tv_usec = dbt::config::inrun_flush_ms * 1000;
		setitimer(ITIMER_REAL, &tv, nullptr);
	}
	if (dbt::config::p1_promote) {
		// P1: dedicated SIGALRM keeper (do not combine with --inrun-tier / --wmax-sample-out /
		// --qcg-freq-retire / --sr-edges-epochs, which own the same timer+handler slot).
		struct timespec ts0;
		clock_gettime(CLOCK_MONOTONIC, &ts0);
		dbt::config::p1_start_ms = ts0.tv_sec * 1000L + ts0.tv_nsec / 1000000L;
		struct sigaction sa{};
		sa.sa_handler = p1_alarm_handler;
		sa.sa_flags = SA_RESTART; // guest syscalls must not see EINTR
		sigaction(SIGALRM, &sa, nullptr);
		struct itimerval tv{};
		tv.it_interval.tv_usec = dbt::config::p1_flush_ms * 1000;
		tv.it_value.tv_usec = dbt::config::p1_flush_ms * 1000;
		setitimer(ITIMER_REAL, &tv, nullptr);
	}
	dbt::ukernel::SetFSRoot(opts.fsroot.c_str());
	dbt::ukernel::MainThreadBoot(static_cast<int>(gargs.size()), gargs.data());
	// T5d2a: arm AFTER the boot, because the artifact and profile names the tier expects are
	// derived from the guest ELF's checksum, which objprof::Announce establishes during it. A
	// refusal here is fatal on purpose: every reason Arm() can refuse for makes the tier unable to
	// fire at all, and a run that silently could not fire is indistinguishable from a workload that
	// was not hot enough -- which is exactly the confusion this checkpoint's evidence must not have.
	if (!dbt::looptier::Arm()) {
		// fsmanager owns a worker thread parked on a condition variable; returning from main
		// without this leaves __run_exit_handlers destroying it underneath that thread and the
		// process never exits (the same defect T5d1a's dry-run exit had to fix).
		dbt::fsmanager::Destroy();
		return 2;
	}
	// T5d2a1: nothing is armed here. The loop tier's request comes from the guest's own execution.
	int guest_rc = dbt::ukernel::MainThreadExecute();

	// DISARM THE INTERVAL TIMERS. The guest has finished; from here on the process only reports and
	// tears down, and every remaining SIGALRM/SIGPROF tick would run a handler that is not safe on
	// this path. `bct_alarm_handler` dereferences `config::escalate_cache`, a pointer into a static
	// std::string, and calls snprintf; after main returns, __run_exit_handlers destroys those
	// statics and the libc allocator arena is mid-free while `tcache::link_map`'s destructor runs.
	// A tick landing there faults.
	//
	// FOUND, not anticipated: 30/30 crashes on a pilot run with the T5d-0 safepoint armed and its
	// poll consumer disabled, against 0/30 with the safepoint off. The safepoint was not the defect
	// -- the duplicate `link_map` entries it exposed (fixed in tcache.h's RecordLink) made the exit
	// path long enough for a 1 ms tick to hit a window that was always there. Both are fixed: the
	// growth at its source, and the window itself here, so no future long exit path can reopen it.
	// Nothing before this point changes, because the guest has already stopped.
	{
		struct itimerval off {};
		setitimer(ITIMER_REAL, &off, nullptr);
		setitimer(ITIMER_PROF, &off, nullptr);
	}

	// T5d2a: the guest has stopped and the keeper is disarmed, so this is where the lifecycle is
	// closed out -- the guest-exit instant, a final collection of a child that may still be
	// compiling, and the summary. An off run prints nothing here.
	dbt::looptier::ReportAtExit();

	// S3.1 RUNTIME-LAYOUT DIAGNOSTIC. Default off, env-gated, exit-time, print-only.
	//
	// S3.0 measured a semantically-null command-line perturbation moving whole-process cycles by
	// 2.5-3.3x at constant retired instructions. That defect is a measurement-validity problem,
	// so it needs the process's own runtime addresses -- and it must be observed WITHOUT changing
	// the thing under test. Hence an environment variable and not a CLI option: adding an option
	// would lengthen the very argv whose length is the suspected nuisance parameter. S3.0's own
	// preflight separately showed that environment string length (0-32 bytes) and environment
	// variable count (0-5) do not move the effect, and this variable is set identically in every
	// compared arm, so it cancels out of the comparison it serves.
	//
	// It runs after the guest has finished, reads existing state, writes one file, and changes no
	// generated code, no translation decision, no guest semantics and no counter.
	if (char const *s31 = getenv("RVDBT_S31_LAYOUT_OUT")) {
		if (FILE *f = fopen(s31, "w")) {
			auto const *st = dbt::CPUState::Current();
			unsigned long long lo = 0, hi = 0;
			dbt::tcache::CodePoolBounds(&lo, &hi);
			fprintf(f, "S31 cpustate 0x%llx\n", (unsigned long long)(uintptr_t)st);
			fprintf(f, "S31 cpustate_vec 0x%llx\n",
				(unsigned long long)(uintptr_t)(st ? &st->vec : nullptr));
			fprintf(f, "S31 cpustate_vreg0 0x%llx\n",
				(unsigned long long)(uintptr_t)(st ? st->vec.vreg[0].data() : nullptr));
			fprintf(f, "S31 cpustate_size %zu\n", sizeof(dbt::CPUState));
			fprintf(f, "S31 vec_offset %zu\n", offsetof(dbt::rv32::CPUStateImpl, vec));
			fprintf(f, "S31 membase 0x%llx\n", (unsigned long long)(uintptr_t)dbt::mmu::base);
			fprintf(f, "S31 codepool_lo 0x%llx\n", lo);
			fprintf(f, "S31 codepool_hi 0x%llx\n", hi);
			fprintf(f, "S31 frame 0x%llx\n",
				(unsigned long long)(uintptr_t)__builtin_frame_address(0));
			fprintf(f, "S31 brk 0x%llx\n", (unsigned long long)(uintptr_t)sbrk(0));
			fclose(f);
		}
		// The hot TB's host address is only knowable after translation, so the existing TB map
		// dumper is reused here rather than duplicated. Same env var, same one-shot discipline.
		std::string s31_tbmap = std::string(s31) + ".tbmap";
		dbt::tcache::DumpTBMap(s31_tbmap.c_str());
	}
	if (opts.rvv_state_hash) {
		auto const *st = dbt::CPUState::Current();
		u64 h = 1469598103934665603ull;
		auto mix_bytes = [&h](void const *p, size_t n) {
			auto const *b = static_cast<unsigned char const *>(p);
			for (size_t i = 0; i < n; ++i) {
				h ^= b[i];
				h *= 1099511628211ull;
			}
		};
		u32 const active_bytes = st->vec.vlenb;
		for (auto const &reg : st->vec.vreg)
			mix_bytes(reg.data(), active_bytes);
		mix_bytes(&st->vec.vl, sizeof(st->vec.vl));
		mix_bytes(&st->vec.vtype, sizeof(st->vec.vtype));
		mix_bytes(&st->vec.vstart, sizeof(st->vec.vstart));
		mix_bytes(&st->vec.vlenb, sizeof(st->vec.vlenb));
		mix_bytes(&st->fpu.fcsr, sizeof(st->fpu.fcsr));
		fprintf(stderr, "RVV_STATE_HASH=%016llx FCSR=%08x VL=%u VTYPE=%08x VSTART=%u\n",
			(unsigned long long)h, st->fpu.fcsr, st->vec.vl, st->vec.vtype, st->vec.vstart);
	}
	if (dbt::config::inrun_builder_pid > 0) {
		kill(-dbt::config::inrun_builder_pid, SIGKILL); // kill-on-exit: builder never outlives the run
		int bst = 0;
		waitpid(dbt::config::inrun_builder_pid, &bst, 0); // reap -> child rusage folds into RUSAGE_CHILDREN
		// 2026-08-17 substrate fix: a successful posix_spawn of a shell is NOT a successful builder.
		// Report the builder's real disposition so a dead builder can never be read as an abstention.
		if (WIFEXITED(bst))
			fprintf(stderr, "INRUN_EVENT BUILDER_EXIT status=exited rc=%d\n", WEXITSTATUS(bst));
		else if (WIFSIGNALED(bst))
			fprintf(stderr, "INRUN_EVENT BUILDER_EXIT status=signalled sig=%d\n", WTERMSIG(bst));
		else
			fprintf(stderr, "INRUN_EVENT BUILDER_EXIT status=unknown raw=%d\n", bst);
		struct rusage cru{};
		getrusage(RUSAGE_CHILDREN, &cru);
		fprintf(stderr, "CHILD_RUSAGE user_s=%ld.%06ld sys_s=%ld.%06ld maxrss_kb=%ld\n",
			(long)cru.ru_utime.tv_sec, (long)cru.ru_utime.tv_usec,
			(long)cru.ru_stime.tv_sec, (long)cru.ru_stime.tv_usec, cru.ru_maxrss);
	}

	if (dbt::config::count_brind) {
		std::cerr << "BRIND_SLOWPATH_COUNT=" << dbt::config::brind_count << "\n";
		std::cerr << "BRIND_SLOWPATH_CYCLES=" << dbt::config::brind_slowpath_cycles << "\n";
		if (dbt::config::brind_count) {
			std::cerr << "BRIND_SLOWPATH_CYCLES_PER_EVENT="
				  << (double)dbt::config::brind_slowpath_cycles / dbt::config::brind_count << "\n";
		}
	}
	if (dbt::config::dump_region_hits) {
		auto *st = dbt::CPUState::Current();
		u64 sum = 0;
		for (u32 slot = 0; slot < dbt::CPUState::REGION_HIT_SLOTS; ++slot) {
			if (st->region_entry_hits[slot]) {
				fprintf(stderr, "REGION_HIT slot=%u hits=%llu\n", slot,
					(unsigned long long)st->region_entry_hits[slot]);
				sum += st->region_entry_hits[slot];
			}
		}
		// Cross-check: sum of all per-region slots should equal the independent global
		// region-entry counter (--aot-work-counter, if also compiled in) exactly -- any gap means
		// an entry path increments one counter but not the other (an instrumentation completeness
		// bug), not a real phenomenon.
		fprintf(stderr, "REGION_HIT_SUM=%llu WORK_COUNTER=%llu\n", (unsigned long long)sum,
			(unsigned long long)st->work_counter);
	}
	if (dbt::config::aot_count_gbrind && !dbt::config::aot_link_multientry_trace) {
		// A-line round 18: standalone dump (aot_link_multientry_trace's own block below already
		// prints this counter when BOTH flags are set -- avoid a duplicate line).
		auto *st = dbt::CPUState::Current();
		fprintf(stderr, "AOT_GBRIND_COUNT=%llu\n", (unsigned long long)st->gbrind_counter);
	}
	{
		// A-line round 28 Gate 1: order-1 oracle reachability counters. Always dumped (zero when
		// unused -- the compiled-in increments only exist at all if elfaot's
		// --aot-order1-context-oracle was set; harmless either way).
		auto *st = dbt::CPUState::Current();
		if (st->gbrind_order1_covered || st->gbrind_order1_hits)
			fprintf(stderr, "GBRIND_ORDER1_COVERED=%llu GBRIND_ORDER1_HITS=%llu GBRIND_ORDER1_MISSES=%llu\n",
				(unsigned long long)st->gbrind_order1_covered, (unsigned long long)st->gbrind_order1_hits,
				(unsigned long long)(st->gbrind_order1_covered - st->gbrind_order1_hits));
	}
	{
		// A-line round 29 Gate 1: marginal (context-free) oracle reachability counters, same pattern.
		auto *st = dbt::CPUState::Current();
		if (st->gbrind_marginal_covered || st->gbrind_marginal_hits)
			fprintf(stderr,
				"GBRIND_MARGINAL_COVERED=%llu GBRIND_MARGINAL_HITS=%llu GBRIND_MARGINAL_MISSES=%llu\n",
				(unsigned long long)st->gbrind_marginal_covered,
				(unsigned long long)st->gbrind_marginal_hits,
				(unsigned long long)(st->gbrind_marginal_covered - st->gbrind_marginal_hits));
	}
	{
		// A-line round 32 Gate 2: static jump-table oracle reachability counters, same pattern.
		auto *st = dbt::CPUState::Current();
		if (st->gbrind_statictable_covered || st->gbrind_statictable_hits)
			fprintf(stderr,
				"GBRIND_STATICTABLE_COVERED=%llu GBRIND_STATICTABLE_HITS=%llu GBRIND_STATICTABLE_MISSES=%llu\n",
				(unsigned long long)st->gbrind_statictable_covered,
				(unsigned long long)st->gbrind_statictable_hits,
				(unsigned long long)(st->gbrind_statictable_covered - st->gbrind_statictable_hits));
	}
	{
		// A-line Round 33: vtable-narrowing oracle reachability counters, same pattern. A "miss"
		// here (covered but not hit) is an expected, non-exhaustive outcome, NOT a bug -- see
		// qir.h's InstGBrind::vtable_narrow_targets comment.
		auto *st = dbt::CPUState::Current();
		if (st->gbrind_vtablenarrow_covered || st->gbrind_vtablenarrow_hits)
			fprintf(stderr,
				"GBRIND_VTABLENARROW_COVERED=%llu GBRIND_VTABLENARROW_HITS=%llu GBRIND_VTABLENARROW_MISSES=%llu\n",
				(unsigned long long)st->gbrind_vtablenarrow_covered,
				(unsigned long long)st->gbrind_vtablenarrow_hits,
				(unsigned long long)(st->gbrind_vtablenarrow_covered - st->gbrind_vtablenarrow_hits));
	}
	{
		// A-line Round 44: index-preserving compact dispatch reachability counters, same pattern.
		auto *st = dbt::CPUState::Current();
		if (st->gbrind_indexeddispatch_covered || st->gbrind_indexeddispatch_hits)
			fprintf(stderr,
				"GBRIND_INDEXEDDISPATCH_COVERED=%llu GBRIND_INDEXEDDISPATCH_HITS=%llu GBRIND_INDEXEDDISPATCH_MISSES=%llu\n",
				(unsigned long long)st->gbrind_indexeddispatch_covered,
				(unsigned long long)st->gbrind_indexeddispatch_hits,
				(unsigned long long)(st->gbrind_indexeddispatch_covered - st->gbrind_indexeddispatch_hits));
	}
	if (dbt::config::aot_link_multientry_trace) {
		auto *st = dbt::CPUState::Current();
		fprintf(stderr,
			"MULTIENTRY_TRACE switch_hits=%llu default_hits=%llu wrapper_calls=%llu "
			"generic_gbrind=%llu brind_slowpath=%lu\n",
			(unsigned long long)st->dbg_multientry_switch_hits,
			(unsigned long long)st->dbg_multientry_default_hits,
			(unsigned long long)st->dbg_wrapper_calls, (unsigned long long)st->gbrind_counter,
			dbt::config::brind_slowpath_visits);
	}
	if (dbt::config::p1_promote) {
		// P1 exit counters: crossed = exiled-hot TBs at the last scan; fire/land offsets give the
		// measured in-run compile+boot cost (the B numerator the evaluation computes with).
		fprintf(stderr,
			"P1_PROMOTE scans=%lu crossed=%lu fired=%d crossed_at_fire=%lu boots=%lu fire_ms=%ld land_ms=%ld build_ms=%ld\n",
			dbt::config::p1_scans, dbt::config::p1_crossed, dbt::config::p1_fired ? 1 : 0,
			dbt::config::p1_crossed_at_fire, dbt::config::p1_boots, dbt::config::p1_fire_ms,
			dbt::config::p1_land_ms,
			(dbt::config::p1_fire_ms >= 0 && dbt::config::p1_land_ms >= 0)
			    ? dbt::config::p1_land_ms - dbt::config::p1_fire_ms
			    : -1);
	}
	if (!opts.selfprof_out.empty()) {
		setitimer(ITIMER_PROF, nullptr, nullptr);
		FILE *f = fopen(opts.selfprof_out.c_str(), "w");
		if (f) {
			for (size_t i = 0; i < g_selfprof_n; ++i)
				fprintf(f, "%llx\n", g_selfprof_buf[i]);
			fclose(f);
		}
	}
	if (!opts.dispatch_selfprof_out.empty()) {
		setitimer(ITIMER_PROF, nullptr, nullptr);
		FILE *f = fopen(opts.dispatch_selfprof_out.c_str(), "w");
		if (f) {
			// A-line Round 40: resolve each raw sample through the standard dynamic linker's own
			// symbol table (dladdr, glibc/libc -- not a workload-specific mechanism) so the output
			// is directly in terms of `_x<guest_ip>` AOT symbol names/offsets, with no separate
			// base-address bookkeeping required by any consumer of this file.
			for (size_t i = 0; i < g_dispatch_selfprof_n; ++i) {
				// dladdr only resolves symbols in a loaded ELF (e.g. the AOT .so during --aot=1);
				// during --aot=0 the QCG tier JIT-compiles into anonymous memory with no symbol
				// table, so dladdr legitimately returns nothing there -- the raw hex is ALSO
				// printed so an offline consumer can reverse-map via --dump-tbmap's
				// guest_ip/host_start/host_size table for that case instead.
				Dl_info rip_info{}, rax_info{};
				dladdr((void *)g_dispatch_selfprof_rip[i], &rip_info);
				dladdr((void *)g_dispatch_selfprof_rax[i], &rax_info);
				fprintf(f, "%llx:%s+%lx %llx:%s+%lx\n", g_dispatch_selfprof_rip[i],
					rip_info.dli_sname ? rip_info.dli_sname : "?",
					rip_info.dli_saddr
					    ? (unsigned long)((uptr)g_dispatch_selfprof_rip[i] - (uptr)rip_info.dli_saddr)
					    : 0ul,
					g_dispatch_selfprof_rax[i], rax_info.dli_sname ? rax_info.dli_sname : "?",
					rax_info.dli_saddr
					    ? (unsigned long)((uptr)g_dispatch_selfprof_rax[i] - (uptr)rax_info.dli_saddr)
					    : 0ul);
			}
			fclose(f);
		}
	}
	if (!opts.load_values_out.empty())
		dbt::dump_load_values(opts.load_values_out.c_str());
	if (dbt::config::phase_window) {
		dbt::phase_window_flush_final();
		dbt::phase_window_dump(opts.phase_windows_out.c_str());
	}
	if (!opts.dump_tbmap.empty())
		dbt::tcache::DumpTBMap(opts.dump_tbmap.c_str());
	if (!opts.dump_tbcode.empty())
		dbt::tcache::DumpTBCode(opts.dump_tbcode.c_str());
	if (dbt::config::measure_translation)
		std::cerr << "TRANSLATE_NS=" << dbt::config::g_translate_ns
			  << " TRANSLATE_COUNT=" << dbt::config::g_translate_count
			  << " INTERP_BLOCKS=" << dbt::config::g_interp_blocks
			  << " QSEL_NS=" << dbt::config::g_qsel_ns
			  << " QRA_NS=" << dbt::config::g_qra_ns
			  << " EMIT_NS=" << dbt::config::g_emit_ns << "\n";
	if (dbt::config::qcg_resident)
		std::cerr << "RESIDENT_INHERIT=" << dbt::config::g_resident_inherit
			  << " RESIDENT_RESET=" << dbt::config::g_resident_reset << "\n";
	if (dbt::config::qcg_pin)
		std::cerr << "PIN_REGIONS=" << dbt::config::g_pin_regions
			  << " PIN_GLOBALS=" << dbt::config::g_pin_globals << "\n";
	if (dbt::config::wmax_sample) {
		setitimer(ITIMER_REAL, nullptr, nullptr);
		FILE *f = fopen(opts.wmax_sample_out.c_str(), "w");
		if (f) {
			fprintf(f, "window visits\n");
			unsigned long long prev = 0;
			for (size_t i = 0; i < g_wmax_n; ++i) {
				fprintf(f, "%zu %llu\n", i, g_wmax_samples[i] - prev);
				prev = g_wmax_samples[i];
			}
			fclose(f);
		}
	}
	if (dbt::config::qcg_dispatch_ic) {
		fprintf(stderr, "QCG_IC_PATCHED=%lu\n", dbt::config::qcg_ic_patched);
	}
	if (dbt::config::qcg_ic_regret) {
		fprintf(stderr, "QCG_IC_REGRET_REVERTED=%lu\n", dbt::config::qcg_ic_regret_reverted);
		if (getenv("QCG_IC_REGRET_DEBUG")) {
			for (u32 gip : {0x16998u, 0x267a8u, 0x20404u, 0x17ae4u, 0x11d14u}) {
				auto &slot = dbt::tcache::qcg_ic_regret_cache[dbt::tcache::gbrind_hitrate_hash(gip)];
				fprintf(stderr, "QCG_IC_REGRET_DEBUG site=%x hit=%lu miss=%lu\n", gip, slot.hit, slot.miss);
			}
		}
	}
	if (dbt::config::qcg_freq_retire) {
		fprintf(stderr, "SAT_RETIRE sweeps=%lu retired=%lu remaining=%zu\n",
			dbt::config::sat_sweeps, dbt::config::sat_retired_sites,
			dbt::tcache::sat_sites.size());
	}
	if (dbt::config::qcg_ic_edges_out) {
		FILE *f = fopen(dbt::config::qcg_ic_edges_out, "w");
		if (f) {
			for (auto const &[site, tgt, slot] : dbt::tcache::ic_edge_counts)
				fprintf(f, "%08x %08x %llu\n", site, tgt, *slot);
			fclose(f);
		}
	}
	if (dbt::config::qcg_freq_entry) {
		fprintf(stderr, "ENTRY_SLOTS n=%zu bytes=%zu\n", dbt::tcache::EdgeSlotCount(),
			dbt::tcache::EdgeSlotCount() * 8);
	}
	if (dbt::config::sr_web_repack) {
		fprintf(stderr, "WEB_REPACK fired=%d members=%lu\n", dbt::config::web_repacked ? 1 : 0,
			dbt::config::web_repack_n);
	}
	if (dbt::config::qcg_leaf_inline) {
		fprintf(stderr, "LEAF_INLINE fires=%lu\n", dbt::config::qcg_leaf_inline_fires);
	}
	if (dbt::config::rvv_probe) {
		dbt::rv32::rvv_census::probe_dump(dbt::config::rvv_probe_out);
	}
	if (dbt::config::rvv_seqtrace) {
		if (!dbt::rv32::seqtrace::dump(dbt::config::rvv_seqtrace_out)) {
			std::cerr << "--rvv-seqtrace-out: dump failed, see the FATAL line above -- "
				     "exiting nonzero so this is never mistaken for a successful run\n";
			std::exit(1);
		}
	}
	if (dbt::config::rvv_pc_census)
		dbt::rv32::pc_census::dump(dbt::config::rvv_pc_census_out);
	if (dbt::config::rvv_lane_census &&
	    !dbt::rv32::lane_region_bridge::Dump(dbt::config::rvv_lane_census_out)) {
		fprintf(stderr, "T7G_CENSUS_ERROR cannot write %s\n", dbt::config::rvv_lane_census_out);
		std::exit(1);
	}
	if (dbt::config::rvv_census) {
		auto *cst = dbt::CPUState::Current();
		dbt::rv32::rvv_census::dump(dbt::config::rvv_census_out, dbt::config::vlen_bits,
					    cst ? (unsigned long long)cst->rvv_direct_hits : 0,
					    cst ? (unsigned long long)cst->rvv_direct_fallbacks : 0);
	}
	if (dbt::config::rvv_fround_oracle_mode == 1)
		dbt::rv32::rvv_fast::fround_oracle_dump(dbt::config::rvv_fround_oracle_file);
#ifdef RVDBT_CHECK_TBEXIT_MXCSR
	fprintf(stderr, "TBEXIT_MXCSR_VIOLATIONS=%llu\n", g_tbexit_mxcsr_violations);
#endif
#ifdef RVDBT_ASYNC_SIGNAL_PROBE
	async_probe_report();
#endif
	if (dbt::config::rvv_stats) {
		auto const &fs = dbt::rv32::rvv_fast::g_fast;
		fprintf(stderr,
			"RVV_FAST enabled=%d classes=%u chunk_bytes=%u admitted=%llu chunks=%llu "
			"residue_elems=%llu refuse_shape=%llu refuse_class=%llu refuse_frm=%llu "
			"fround_run_continued=%llu fround_run_tb_exit_open=%llu "
			"sig_checks=%llu sig_hit=%llu sig_miss_stale=%llu sig_miss_evict=%llu "
			"fuse_scan_attempted=%llu fuse_scan_found=%llu "
			"handler_legality_would_trap=%llu\n",
			(int)dbt::config::rvv_fast, dbt::config::rvv_fast_classes,
			dbt::rv32::HOST_CHUNK_BYTES, fs.ops_admitted,
			fs.chunks, fs.residue_elems, fs.refuse_shape, fs.refuse_class,
			fs.refuse_frm, fs.fround_run_continued, fs.fround_run_tb_exit_open,
			fs.sig_checks, fs.sig_hit, fs.sig_miss_stale, fs.sig_miss_evict,
			fs.fuse_scan_attempted, fs.fuse_scan_found,
			fs.handler_legality_would_trap);
		// Cycle Q: width retention. Which host SIMD width actually processed each byte of
		// guest vector data -- the thesis problem's own estimand, previously unobservable.
		// `chunks` above does NOT answer this: under --rvv-width-policy != 0 the .vv/.vx
		// forms route to walk_extent_cascade*, which never increments it (cycle P defect).
		// Compile-time guard as well as the runtime --rvv-stats gate: without it a binary
		// built -DRVDBT_FAST_STATS=0 would still print RVV_TIER with all-zero counters,
		// which reads as "no tier work" rather than "not instrumented". Cycles O and P both
		// lost time to a counter that was silently not wired into the active path.
		if constexpr (dbt::rv32::rvv_cascade::kTierCensus) {
			auto const &tc = dbt::rv32::rvv_cascade::g_tier;
			unsigned long long const tot = tc.bytes[0] + tc.bytes[1] + tc.bytes[2] +
						       tc.bytes[3];
			fprintf(stderr,
				"RVV_TIER bytes_t64=%llu bytes_t32=%llu bytes_t16=%llu "
				"bytes_other=%llu calls_t64=%llu calls_t32=%llu calls_t16=%llu "
				"calls_other=%llu total_bytes=%llu rho_t64=%.6f\n",
				tc.bytes[0], tc.bytes[1], tc.bytes[2], tc.bytes[3], tc.calls[0],
				tc.calls[1], tc.calls[2], tc.calls[3], tot,
				tot ? (double)tc.bytes[0] / (double)tot : 0.0);
		}
		// G3: scalar FP bracket lifecycle -- is the amortisation actually consumed, and why
		// do runs end? sc_open + sc_continue is the number of host-path scalar FP ops; the
		// three close counters partition sc_open.
		if (auto const *cst = dbt::CPUState::Current()) {
			auto const &fp = cst->fpu;
			unsigned long long const ops = fp.sc_open + fp.sc_continue;
			fprintf(stderr,
				"SC_FROUND open=%llu continue=%llu ops=%llu close_csr=%llu "
				"close_mode=%llu close_tbexit=%llu mean_run=%.3f "
				"hist_1=%llu hist_2=%llu hist_3=%llu hist_4=%llu hist_5_8=%llu "
				"hist_9_16=%llu hist_17_32=%llu hist_33_64=%llu hist_65p=%llu\n",
				fp.sc_open, fp.sc_continue, ops, fp.sc_close_csr, fp.sc_close_mode,
				fp.sc_close_tbexit,
				fp.sc_open ? (double)fp.sc_run_len_sum / (double)fp.sc_open : 0.0,
				fp.sc_hist[0], fp.sc_hist[1], fp.sc_hist[2], fp.sc_hist[3],
				fp.sc_hist[4], fp.sc_hist[5], fp.sc_hist[6], fp.sc_hist[7],
				fp.sc_hist[8]);
		}
	}
	// Z4B. Printed on its own condition, NOT under --rvv-stats, because the cell this counter
	// exists for runs the accepted production flag set and that set does not contain --rvv-stats.
	// Gated on the census switch so that every accepted arm's stderr stays byte-identical.
	if (dbt::config::rvv_qcg_typed_chunk_vlse_gather_census) {
		unsigned long long const fp = dbt::rv32::g_vlse_gather_fast,
				      fb = dbt::rv32::g_vlse_gather_fallback;
		fprintf(stderr,
			"RVV_VLSE_GATHER route=%d census=1 fast_path=%llu fallback=%llu total=%llu\n",
			(int)dbt::config::rvv_qcg_typed_chunk_vlse_gather, fp, fb, fp + fb);
	}
	// P2a. Printed on its own condition, for the same reason the Z4B line above is: the accepted
	// production flag set does not contain --rvv-stats, and every arm that does not arm this
	// census must keep byte-identical stderr.
	//
	// `skipped` is printed as a DERIVED difference, never as a third counter, and it is deliberately
	// not called "useless": with the three active-VL policy switches off it is zero by construction
	// (no frame carries a bound), which is what makes a non-zero value attributable to the policy
	// and to nothing else. The policy switches are echoed on the same line so a reader never has to
	// pair this row with a command line to know which of the two regimes produced it.
	if (dbt::config::rvv_qcg_active_chunk_census) {
		unsigned long long const av = dbt::rv32::g_rvv_chunks_available,
				      ex = dbt::rv32::g_rvv_chunks_executed;
		fprintf(stderr,
			"RVV_ACTIVE_CHUNKS census=1 vlen=%u policy_int=%d policy_fp=%d policy_widen=%d "
			"policy_narrow=%d chunks_available=%llu chunks_executed=%llu skipped=%llu "
			"executed_ratio=%.6f\n",
			dbt::config::vlen_bits, (int)dbt::config::rvv_qcg_active_vl_int_bound,
			(int)dbt::config::rvv_qcg_active_vl_bound,
			(int)dbt::config::rvv_qcg_active_vl_widen_bound,
			(int)dbt::config::rvv_qcg_active_vl_narrow_bound, av, ex,
			av >= ex ? av - ex : 0ull, av ? (double)ex / (double)av : 0.0);
	}
	if (dbt::config::rvv_stats) {
		// How much of the run actually executed on host vectors, how much finished
		// element-wise below a chunk, and how much never reached the fixed-width path at
		// all. `chunks_per_reg` is printed as the derived width-parametric quantity.
		auto const &rs = dbt::rv32::g_rvv_stats;
		fprintf(stderr,
			"RVV_STATS vlen=%u chunk_bytes=%u chunks_per_reg=%u lowering=%s chunk_ops=%llu "
			"tail_elems=%llu ref_fallback=%llu verify_ok=%llu verify_fail=%llu\n",
			dbt::config::vlen_bits, dbt::rv32::HOST_CHUNK_BYTES,
			(dbt::config::vlen_bits / 8) / dbt::rv32::HOST_CHUNK_BYTES,
			dbt::config::rvv_lowering ? "fixed-width" : "reference", rs.chunk_ops,
			rs.tail_elems, rs.ref_fallback, rs.verify_ok, rs.verify_fail);
		// Direct-lowering counters live in CPUState because they are incremented by
		// JIT-EMITTED code, not by a helper -- which is exactly what makes them evidence
		// that the inline path really executed.
		auto *st = dbt::CPUState::Current();
		if (st)
			fprintf(stderr, "RVV_GATHER attempts=%llu calls=%llu elems=%llu unmapped=%llu\n",
			dbt::rv32::rvv_gather::g_gather_attempts, dbt::rv32::rvv_gather::g_gather_calls,
			dbt::rv32::rvv_gather::g_gather_elems, dbt::rv32::rvv_gather::g_gather_unmapped);
		// R1A.3d: `hit_counter` says whether inline_hits was even emitted. Without it,
		// `inline_hits=0` from a counter-free arm is indistinguishable from "the typed route
		// never executed", which is precisely the failure a validity gate has to catch.
		// guard_fallbacks is NEVER gated, so it stays meaningful in every arm.
		fprintf(stderr,
			"RVV_DIRECT enabled=%d hit_counter=%d inline_hits=%llu guard_fallbacks=%llu\n",
				(int)dbt::config::rvv_direct, (int)dbt::config::rvv_qcg_hit_counter,
				(unsigned long long)st->rvv_direct_hits,
				(unsigned long long)st->rvv_direct_fallbacks);
		// P7M-C1: THE VECTOR-RUN SCAN COUNTERS, which had no reporting path at all.
		//
		// `rvvrun::g_stats` has been populated by every `--rvv-vector-run` scan since R1A.3a
		// and read by nothing outside the focused tests, so on a real application there was no
		// way to answer "how many runs formed, how deep were they, and what cut the rest" --
		// the questions a claim about applicability rests on. Re-deriving them offline from a
		// disassembly would be a re-implementation of the admission rule rather than a
		// measurement of it.
		//
		// THIS IS A TRANSLATION-TIME DIAGNOSTIC ON THE EXIT PATH. It reads counters that were
		// already being incremented, emits no code, changes no admission decision and is
		// printed only when --rvv-stats is on and --rvv-vector-run formed at least one scan,
		// so no accepted arm's emitted bytes or existing stderr lines move.
		if (dbt::config::rvv_vector_run) {
			namespace rr = dbt::rv32::rvvrun;
			fprintf(stderr,
				"RVV_RUN scans=%llu runs_formed=%llu multi_member_runs=%llu "
				"members_admitted=%llu\n",
				(unsigned long long)rr::g_stats.scans,
				(unsigned long long)rr::g_stats.runs_formed,
				(unsigned long long)rr::g_stats.multi_member_runs,
				(unsigned long long)rr::g_stats.members_admitted);
			for (unsigned m = 0; m <= rr::kMaxRunMembers; ++m)
				if (rr::g_stats.members_hist[m])
					fprintf(stderr, "RVV_RUN_DEPTH members=%u runs=%llu\n", m,
						(unsigned long long)rr::g_stats.members_hist[m]);
			for (unsigned c = 0; c < rr::kCutReasonCount; ++c)
				if (rr::g_stats.cuts[c])
					fprintf(stderr, "RVV_RUN_CUT %s=%llu\n",
						rr::CutReasonName((rr::CutReason)c),
						(unsigned long long)rr::g_stats.cuts[c]);
			// P7N-G. Printed only when a splitting frame was actually emitted, so no
			// accepted arm's stderr gains a line. `reload` and `spill_live` are the only
			// two that are EXTRA work; the other three replace a fixed-placement op one
			// for one and are printed so the total cannot be read as if it were all new.
			if (rr::g_stats.split_frames)
				fprintf(stderr,
					"RVV_RUN_SPLIT frames=%llu load_first=%llu reload=%llu "
					"store_dead=%llu spill_live=%llu store_final=%llu "
					"peak_resident=%llu\n",
					(unsigned long long)rr::g_stats.split_frames,
					(unsigned long long)rr::g_stats.split_load_first,
					(unsigned long long)rr::g_stats.split_reload,
					(unsigned long long)rr::g_stats.split_store_dead,
					(unsigned long long)rr::g_stats.split_spill_live,
					(unsigned long long)rr::g_stats.split_store_final,
					(unsigned long long)rr::g_stats.split_peak_resident);
		}
	}
	// T3a: per-opcode "ran in C++, not in emitted host code" counts. Printed independently of
	// --rvv-stats so a route claim never depends on another switch being on too.
	if (dbt::config::rvv_route_census) {
		namespace rc = dbt::rv32::route_census;
		for (unsigned r = 0; r < rc::R_COUNT; ++r)
			fprintf(stderr, "RVV_ROUTE %s handler_calls=%llu\n", rc::route_name(r),
				(unsigned long long)rc::g_handler_calls[r]);
	}
	// P7M-E. THE FRAME CENSUS DUMP. Printed independently of --rvv-stats, for the reason the
	// route census above is: a counting claim must not depend on another switch also being on.
	// One CSV row per REGISTERED frame, in translation order, with a header so the file is
	// machine-readable without knowing the field order. A region translated more than once
	// contributes several rows sharing tb_pc/frame_index; the consumer sums them (see
	// rvvrun::FrameCensusEntry). `count` is fast-arm executions only.
	if (dbt::config::rvv_run_frame_census) {
		fprintf(stderr, "RVV_RUN_FRAME_CSV tb_pc,frame_index,n_members,k,count\n");
		dbt::rv32::rvvrun::FrameCensusForEach(
		    [](dbt::rv32::rvvrun::FrameCensusEntry const &e, void *) {
			    fprintf(stderr, "RVV_RUN_FRAME %08x,%u,%u,%u,%llu\n", e.tb_pc,
				    (unsigned)e.frame_index, (unsigned)e.n_members, (unsigned)e.k,
				    (unsigned long long)e.count);
		    },
		    nullptr);
	}
	if (dbt::config::qcg_jal_closure) {
		fprintf(stderr, "JAL_CLOSURE fires=%lu\n", dbt::config::qcg_jal_closure_fires);
	}
	if (dbt::config::sr_edges_epochs) {
		fprintf(stderr, "EDGE_EPOCHS ticks=%lu flushes=%lu dry_stopped=%d edges=%lu\n",
			(unsigned long)dbt::config::sat_tick, dbt::config::epochs_flushes,
			dbt::config::epochs_done ? 1 : 0, dbt::brindedges::Count());
	}
	if (dbt::config::qcg_freq_shadow_out) {
		// shadow-equivalence dump: aggregate per-ip shadow slots (a TB may retranslate), pair
		// with the STOCK count from the live TB. Missing TB (invalidated) -> stock=-1 marker.
		std::map<unsigned, unsigned long long> shadow_by_ip;
		for (auto const &[slot, ip] : dbt::tcache::shadow_slots)
			shadow_by_ip[ip] += *slot;
		FILE *f = fopen(dbt::config::qcg_freq_shadow_out, "w");
		if (f) {
			fprintf(f, "ip stock entry delta brind seg\n");
			for (auto const &[ip, entry] : shadow_by_ip) {
				auto *tb = dbt::tcache::Lookup(ip);
				long long stock = tb ? (long long)tb->flags.exec_count : -1;
				fprintf(f, "%08x %lld %llu %lld %d %d\n", ip, stock, entry,
					(long long)entry - stock, tb ? (int)tb->flags.is_brind_target : -1,
					tb ? (int)tb->flags.is_segment_entry : -1);
			}
			fclose(f);
		}
	}
	if (dbt::config::profile_brind_edges) {
		dbt::brindedges::Dump(opts.brind_edges_out.c_str());
	} else if (dbt::config::sr_sampled_edges && dbt::config::brind_edges_out_path) {
		// A-line 2026-07-23: the cheap natural-miss observer (--sr-cheap-edges-out without
		// --sr-live-edges-dump) previously had NO dump point at all outside the inrun-escalation
		// machinery -- dump whatever the sampler saw at exit, same as the exhaustive recorder.
		dbt::brindedges::Dump(dbt::config::brind_edges_out_path);
	} else if (dbt::config::shadow_edges && !opts.shadow_edges_out.empty()) {
		dbt::brindedges::Dump(opts.shadow_edges_out.c_str());
	}
	if (dbt::config::shadow_edges) {
		// Item-3 required measurement: cost must be reported, not just claimed. dispatches =
		// every inline-checked gbrind reached; slow_calls = how many fell through to the
		// handler (a miss OR collision); collisions = of those, how many were a genuinely
		// different source's slot (hash pressure) rather than this source's own target change.
		fprintf(stderr,
			"shadow_edges: dispatches=%lu slow_calls=%lu collisions=%lu slow_call_rate=%.6f\n",
			(unsigned long)dbt::tcache::shadow_edge_total_dispatches,
			(unsigned long)dbt::tcache::shadow_edge_slow_calls,
			(unsigned long)dbt::tcache::shadow_edge_collisions,
			dbt::tcache::shadow_edge_total_dispatches
			    ? (double)dbt::tcache::shadow_edge_slow_calls / dbt::tcache::shadow_edge_total_dispatches
			    : 0.0);
	}
	if (dbt::config::shadow_edges && dbt::config::shadow_edges_k >= 2) {
		// H2 measurement (SUPPORT_DISCOVERY_H1_VS_H2.md): same discipline as H1's block above --
		// always dumped when active, never asserted-only. hash_collisions is H1-equivalent (a
		// DIFFERENT source landed on this hashed slot); capacity_evictions is the NEW quantity H2
		// introduces (THIS source's own K-way set was already full of K distinct targets) -- kept
		// as two separate counters since they answer different questions (see tcache.h).
		fprintf(stderr,
			"shadow_edges_k: k=%u dispatches=%lu slow_calls=%lu hash_collisions=%lu "
			"capacity_evictions=%lu slow_call_rate=%.6f\n",
			dbt::config::shadow_edges_k,
			(unsigned long)dbt::tcache::shadow_edge_k_total_dispatches,
			(unsigned long)dbt::tcache::shadow_edge_k_slow_calls,
			(unsigned long)dbt::tcache::shadow_edge_k_hash_collisions,
			(unsigned long)dbt::tcache::shadow_edge_k_capacity_evictions,
			dbt::tcache::shadow_edge_k_total_dispatches
			    ? (double)dbt::tcache::shadow_edge_k_slow_calls / dbt::tcache::shadow_edge_k_total_dispatches
			    : 0.0);
		if (!opts.shadow_edges_k_out.empty()) {
			// A-line round 13: dump every (source,target,hit_count) triple this run's K-way sets
			// hold -- unlike shadow-majority (single certified winner per target), this preserves
			// the full observed multi-target distribution per source, feeding --aot-multiguard-edges
			// directly. No certificate/abstention gate here (unlike shadow-majority): the safety
			// invariant is structural (multiguard's own generic-gbrind fallback covers any target
			// NOT in this dump, so an incomplete/undercounted set is a cost -- more fallback traffic
			// -- never a correctness risk, see MULTIGUARD_FANOUT_CEILING_R12.md).
			FILE *f = fopen(opts.shadow_edges_k_out.c_str(), "w");
			if (f) {
				for (auto const &slot : dbt::tcache::shadow_edge_k_cache) {
					for (u8 i = 0; i < slot.n_valid; i++)
						fprintf(f, "%x %x %u\n", slot.src, slot.targets[i], slot.counts[i]);
				}
				fclose(f);
			}
		}
	}
	if (dbt::config::shadow_edges2 && dbt::config::shadow_edges2_all_jalr) {
		unsigned long long rc = dbt::tcache::shadow_edge2_dispatches_call;
		unsigned long long tc = dbt::tcache::shadow_edge2_dispatches_tailcall;
		unsigned long long rt = dbt::tcache::shadow_edge2_dispatches_return;
		unsigned long long tot = rc + tc + rt;
		fprintf(stderr,
			"RETURN_CENSUS call=%llu tailcall=%llu return=%llu total=%llu "
			"call_frac=%.6f tailcall_frac=%.6f return_frac=%.6f\n",
			rc, tc, rt, tot, tot ? (double)rc / tot : 0.0, tot ? (double)tc / tot : 0.0,
			tot ? (double)rt / tot : 0.0);
	}
	if (dbt::config::shadow_edges2 && !opts.shadow_edges2_out.empty()) {
		// A-line round 14 (TRACK 2): dump ShadowEdge2Cache's fixed 2-slot-per-source state.
		// c0/c1==0 means that slot was never populated (a source with <2 distinct targets) --
		// skipped, not emitted as a spurious zero-count edge.
		FILE *f = fopen(opts.shadow_edges2_out.c_str(), "w");
		if (f) {
			for (auto const &slot : dbt::tcache::shadow_edge2_cache) {
				if (slot.c0)
					fprintf(f, "%x %x %u\n", slot.src, slot.t0, slot.c0);
				if (slot.c1)
					fprintf(f, "%x %x %u\n", slot.src, slot.t1, slot.c1);
			}
			fclose(f);
		}
	}
	if (dbt::config::gbrind_hitrate_collect && !opts.gbrind_hitrate_out.empty()) {
		// A-line Round 48: dump gbrind_hitrate_cache's fixed per-slot hit/miss state. hit==0 &&
		// miss==0 means that hashed slot was never touched by any instrumented dispatch -- skipped,
		// not emitted as a spurious zero-count entry. The slot's hash is dumped directly (not a
		// recovered source ip -- the hash is not invertible in general); the AOT-side consumer
		// (elfaot's --aot-gbrind-hitrate-file) re-hashes each site's own real src_ip with the SAME
		// gbrind_hitrate_hash to look its slot up, so this asymmetry is safe and exact modulo the
		// same accepted collision tradeoff shadow_edge2_cache already makes.
		FILE *f = fopen(opts.gbrind_hitrate_out.c_str(), "w");
		if (f) {
			for (size_t i = 0; i < dbt::tcache::gbrind_hitrate_cache.size(); ++i) {
				auto const &slot = dbt::tcache::gbrind_hitrate_cache[i];
				if (slot.hit || slot.miss)
					fprintf(f, "%zx %llu %llu\n", i, (unsigned long long)slot.hit,
						(unsigned long long)slot.miss);
			}
			fclose(f);
		}
	}
	if (dbt::config::temporal_order_collect && !opts.temporal_order_out.empty()) {
		// A-line 2026-07-27 (Codex 7th audit P1): dump temporal_order_cache's fixed per-slot
		// state. src==0 && total==0 means that hashed slot was never touched -- skipped. Format:
		// "src total compared lag1_match lag2_match" (hex src, decimal counts) -- src here is the
		// REAL source ip (not a hash, unlike gbrind_hitrate_cache), since the slot's own `src` tag
		// field is stored precisely for this purpose. `total` is the EXACT real dispatch count;
		// lag1_match/lag2_match must be divided by `compared` (the stride-16-decimated sample
		// count), NOT `total`, to get the correct rate -- dividing by `total` silently deflates by
		// ~16x. Join offline with --shadow-edges2-out (same shadow_edge2_hash key space) for
		// marginal per-target counts / collision-baseline.
		FILE *f = fopen(opts.temporal_order_out.c_str(), "w");
		if (f) {
			for (auto const &slot : dbt::tcache::temporal_order_cache) {
				if (slot.total)
					fprintf(f, "%08x %llu %llu %llu %llu\n", slot.src, (unsigned long long)slot.total,
						(unsigned long long)slot.compared, (unsigned long long)slot.lag1_match,
						(unsigned long long)slot.lag2_match);
			}
			fclose(f);
		}
	}
	if (dbt::config::shadow_majority && !opts.shadow_majority_out.empty()) {
		// A-line Design 3 dump: for each touched target, emit ONE (candidate_src, target,
		// candidate_hits) edge directly in --aot-fdre-edges format ("%x %x %llu"), IFF the
		// candidate_hits*2 > target_exec_count safety certificate holds (see tcache.h comment on
		// MajorityVoteEntry) -- otherwise skip it entirely (abstain, never guess). No separate
		// reconstruction pass: this dump IS the final evidence file.
		FILE *f = fopen(opts.shadow_majority_out.c_str(), "w");
		unsigned long touched = 0, certified = 0, abstained = 0;
		if (f) {
			for (auto const &e : dbt::tcache::majority_cache) {
				if (e.target_gip == 0 && e.candidate_src == 0 && e.counter == 0)
					continue; // never-touched slot
				touched++;
				auto *tb = dbt::tcache::Lookup(e.target_gip);
				unsigned long long target_exec_count = tb ? tb->flags.exec_count : 0;
				if (getenv("SHADOW_MAJORITY_DEBUG"))
					fprintf(stderr, "SM_SLOT target=%08x candidate=%08x counter=%u hits=%u exec_count=%llu\n",
						e.target_gip, e.candidate_src, e.counter, e.candidate_hits, target_exec_count);
				if ((unsigned long long)e.candidate_hits * 2 > target_exec_count && target_exec_count > 0) {
					// Report the TARGET'S OWN exec_count (A), not the raw candidate_hits vote
					// count, as this edge's weight. Two reasons, both safety-driven: (1) Design
					// 3b's online early-stopping (qemit.cpp) freezes candidate_hits once the
					// certificate first fires, so it under-reports the source's true total after
					// that point -- using it as the exported weight would make ApplyFDRE's own
					// conservation gate (resid=A-W<=slack) reject decisions it should accept. (2)
					// W=A makes resid=0 and best_w*2>W trivially hold, exactly matching what the
					// certificate already proved (a real strict majority exists) -- never a false
					// accept, only a coarser weight for Stage 3's per-source tie-break among
					// targets, which is a precision loss, not a correctness one.
					fprintf(f, "%x %x %llu\n", e.candidate_src, e.target_gip, target_exec_count);
					certified++;
				} else {
					abstained++;
				}
			}
			fclose(f);
		}
		fprintf(stderr,
			"shadow_majority: touched_slots=%lu certified=%lu abstained=%lu\n",
			touched, certified, abstained);
	}
	if (dbt::config::ngr) dbt::ngr::PrintStats();
	if (dbt::config::qcg_code_bytes) {
		// Reported in its own line, in bytes, and separately from the AOT artifact's size, which
		// T4 takes from the artifact file itself. Mixing generated host bytes with a .so's file
		// size in one column is exactly the unit confusion this line exists to make impossible.
		unsigned long cb[3];
		dbt::tcache::CodeBytes(cb);
		fprintf(stderr, "QCG_CODE_BYTES bytes=%lu qcg_tbs=%lu aot_tbs=%lu\n", cb[0], cb[1], cb[2]);
	}
	if (dbt::config::tier_census && !dbt::config::inrun_tier) {
		// R47 drift signal: QCG_EXEC = dynamic mass in un-admitted QCG (high => admission stale vs input).
		unsigned long census[4];
		dbt::tcache::TierCensus(census);
		std::cerr << "TIER_CENSUS QCG_TBS=" << census[0] << " AOT_TBS=" << census[1]
			  << " QCG_EXEC=" << census[2] << " AOT_EXEC=" << census[3] << "\n";
	}
	if (dbt::config::inrun_tier) {
		fprintf(stderr,
			"INRUN_COSTS firstfire_ms=%lu eval_us=%lu eval_cpu_us=%lu n_eval=%lu ack_us=%lu n_ack=%lu flushes=%lu brind_slow=%lu\n",
			dbt::config::esc_ms_firstfire, dbt::config::esc_us_eval, dbt::config::esc_us_eval_cpu,
			(unsigned long)dbt::config::esc_eval_count, dbt::config::esc_us_acks, dbt::config::esc_n_acks,
			(unsigned long)dbt::config::inrun_flush_count, dbt::config::brind_slowpath_visits);
		if (dbt::config::inrun_escape_unlink)
			fprintf(stderr, "ESC_UNLINK ticks=%lu slots=%lu\n",
				dbt::config::esc_unlink_ticks, dbt::config::esc_unlink_slots);
		if (dbt::config::sr_census_flip_check)
			fprintf(stderr, "CENSUS_WALK_DIAG calls=%lu calls_postboot=%lu last_dq=%llu last_da=%llu\n",
				dbt::config::esc_census_walk_calls, dbt::config::esc_census_walk_calls_postboot,
				dbt::config::esc_last_dq_c, dbt::config::esc_last_da_c);
		if (dbt::config::sr_census_flip_check || dbt::config::sr_oracle_flip_at_ms > 0)
			fprintf(stderr, "CF_ACTION_FIRES override=%lu regime=%lu wake=%lu oracle_fired=%d\n",
				dbt::config::esc_cf_action_override_fires, dbt::config::esc_cf_action_regime_fires,
				dbt::config::esc_cf_action_wake_fires, (int)dbt::config::esc_oracle_fired);
		if (dbt::config::g_gbrind_exec_mirror)
			fprintf(stderr, "AOT_GBRIND gbrind_exec=%llu\n", dbt::config::g_gbrind_exec_mirror);
		std::cerr << "INRUN_BOOTED=" << (dbt::config::inrun_booted ? 1 : 0)
			  << " FLUSHES=" << dbt::config::inrun_flush_count << " RELINKED=" << dbt::config::inrun_relinked
			  << " BOOT_MS=" << dbt::config::inrun_boot_ms;
		unsigned long census[4];
		dbt::tcache::TierCensus(census);
		std::cerr << " QCG_TBS=" << census[0] << " AOT_TBS=" << census[1]
			  << " QCG_EXEC=" << census[2] << " AOT_EXEC=" << census[3];
		if (dbt::config::inrun_seq_n > 0) {
			std::cerr << " SEQ_N=" << dbt::config::inrun_seq_n << " SEQ_BOOTED=" << dbt::config::inrun_seq_idx
				  << " SEQ_BOOT_MS=";
			for (int i = 0; i < dbt::config::inrun_seq_idx && i < dbt::config::kInrunSeqMax; ++i)
				std::cerr << (i ? "," : "") << dbt::config::inrun_seq_boot_ms[i];
		}
		if (dbt::config::inrun_revoke_watch)
			std::cerr << " REVOKE_APPLIED=" << dbt::config::esc_revoke_applied;
		std::cerr << "\n";
	}

	// T5d-0: printed ONLY when the feature was asked for. An earlier version printed an
	// `on=0 sites=0 escapes=0` line on every run so a verifier could diff it against an on run;
	// independent review rejected that, and correctly -- a switched-off feature that still writes a
	// line to stderr has changed the process's output, which is exactly what "default off" is
	// supposed to rule out, and it makes every unrelated run's stderr depend on this checkpoint.
	// An off run is now recognised by the ABSENCE of these lines, which is a stronger statement
	// than a zero row and needs nothing new in the output. `gbr_total` -- every JIT-mode direct
	// region exit this process emitted -- is the denominator that turns "the safepoint is on the
	// backedges and nothing else" into a measured ratio, and an on run supplies it in full. The
	// emission counts come from Emit_gbr; `escapes` is incremented by the emitted code itself, on
	// its taken path only.
	if (unlikely(dbt::config::qcg_backedge_safepoint)) {
		fprintf(stderr,
			"BACKEDGE_SAFEPOINT on=1 sites=%llu gbr_total=%llu escapes=%llu distinct_ips=%zu\n",
			dbt::config::backedge_safepoint_sites, dbt::config::backedge_safepoint_gbr_total,
			dbt::config::backedge_safepoint_escapes, dbt::config::backedge_safepoint_ips.size());
	}
	if (!dbt::config::backedge_safepoint_ips.empty()) {
		// Every guest PC an escape resumed at, most frequent first. The whole set is printed, not
		// a top-N: which PCs these are IS the evidence that the returns came from inside the timed
		// region, and a truncated list could not support that. The set is bounded by the number of
		// distinct backward edges the run traversed while a request was pending.
		std::vector<std::pair<u32, unsigned long long>> v(dbt::config::backedge_safepoint_ips.begin(),
								  dbt::config::backedge_safepoint_ips.end());
		std::sort(v.begin(), v.end(), [](auto const &a, auto const &b) {
			return a.second != b.second ? a.second > b.second : a.first < b.first;
		});
		for (auto const &[ip, c] : v)
			fprintf(stderr, "BACKEDGE_SAFEPOINT_IP %08x %llu\n", ip, c);
	}

	// T5d2a3, printed under exactly T5d-0's rule: only when the feature was asked for, so an off
	// run is recognised by the ABSENCE of the line rather than by a zero row. `sites` is how many
	// intra-region backward edges this process gave an exit block (every one of them behind
	// T5d2a2's four guards); `exits` is incremented by the emitted code on its taken path only.
	// The IP list is what makes the checkpoint's claim checkable: an exit must resume at the guest
	// PC of the edge that raised the notification, not at some later region exit's target.
	if (unlikely(dbt::config::loop_tier_side_exit)) {
		// T5d2b0 adds the second entry into the same exit block, counted at ITS entry so the two
		// reasons control was handed back can be told apart: `exits` is every traversal of the
		// block, `completion_exits` is how many of them the child-completion poll caused.
		fprintf(stderr,
			"LOOPTIER_SIDEEXIT on=1 sites=%llu exits=%llu distinct_ips=%zu completion_sites=%llu "
			"completion_exits=%llu completion_wakeups=%lu\n",
			dbt::config::loop_tier_side_exit_sites, dbt::config::loop_tier_side_exits,
			dbt::config::loop_tier_side_exit_ips.size(),
			dbt::config::loop_tier_completion_exit_sites, dbt::config::loop_tier_completion_exits,
			dbt::config::loop_tier_completion_wakeups);
		std::vector<std::pair<u32, unsigned long long>> se(dbt::config::loop_tier_side_exit_ips.begin(),
								  dbt::config::loop_tier_side_exit_ips.end());
		std::sort(se.begin(), se.end(), [](auto const &a, auto const &b) {
			return a.second != b.second ? a.second > b.second : a.first < b.first;
		});
		for (auto const &[ip, c] : se)
			fprintf(stderr, "LOOPTIER_SIDEEXIT_IP %08x %llu\n", ip, c);
	}

	if (!opts.use_aot || opts.update_profile_on_aot) { // R47 closed-loop: optionally learn drift during aot runs
		dbt::objprof::UpdateProfile();
	}

	if constexpr (dbt::config::debug) {
		dbt::objprof::Destroy();
		dbt::tcache::Destroy();
		dbt::mmu::Destroy();
	}
	dbt::fsmanager::Destroy();
	return guest_rc;
}
