// Integrated Both-arm boundary test: M1 run -> ordinary M2-eligible instruction -> M1 run.
//
// TEST-ONLY. Nothing here changes translator behaviour; it compiles guest words through the
// production QCG pipeline (CompilerGenRegionIR + qcg::GenerateCode), exactly as
// rvv_vector_run_value_test.cpp does, and executes the emitted host code.
//
// WHAT "Both" MEANS HERE. The formal four-arm campaign's BOTH arm is member-major M1
// (--rvv-vector-run=1) plus per-instruction M2 (--rvv-qcg-active-vl-{bound,int-bound,widen-bound,
// narrow-bound}=1). M2 can never bound a member-major multi-member run (BuildPlan's
// suffix_is_body_tail), so the only place the two methods meet is a SEQUENCE: an M1 frame, then
// an ordinary single-instruction frame the M2 planner may bound, then another M1 frame. That is the
// sequence tested. The translator config of each arm is GENERATED from dbt/elfrun.cpp's option
// plumbing plus the campaign's FLAGS.A/FLAGS.S0 files (rvv_both_boundary_campaign_config.h), so the
// four arms here are the four campaign arms by construction, not a hand-copied approximation.
//
// THE MIDDLE INSTRUCTION is vmaxu.vv. It decodes to `vialu`, which has no M1 route row
// (rv32_vrun.cpp TypedAluRoute<>), so it cuts a run with UnsupportedVector; and with an observed
// vtype it reaches RvvTryIntegerFamily's equal-width builder, whose frame is VTypeInteger-guarded
// and M2-eligible under --rvv-qcg-active-vl-int-bound (FrameGeometry.policy_enabled).
//
// SCENARIOS
//   S1 publication  : vsetvli e32m1; vadd v8=v2+v3; vsub v9=v8-v4 | vmaxu v9=max(v9,v5) |
//                     vadd v10=v9+v8; vxor v11=v10^v9. Run A's final AND intermediate values must
//                     be published before the middle frame reads them; the middle overwrites v9 in
//                     place, so run B must read the middle's v9, never run A's resident copy.
//   S2 masked middle: S1 with vmaxu.vv v9,v9,v5,v0.t (mask-undisturbed) -- M2 skipping and the
//                     per-lane mask must compose.
//   S3 config       : vsetvli(a0,e32) A | vsetvli(a1,e64) vmaxu(e64) | vsetvli(a2,e32) B -- vl and
//                     SEW change at every boundary; the middle reinterprets run A's bytes as e64
//                     and run B reinterprets the middle's bytes as e32.
//   S4 helper/guard : S1 WITHOUT the vsetvli. No vtype is observed, so the middle goes to the C++
//                     helper (rv32_vialu) while the fixed-shape vadd/vsub/vxor routes still form
//                     frames. Runtime state then drives every reachable guard outcome: matching
//                     state (native-helper-native), partial vl, nonzero vstart at entry (the first
//                     instruction restarts at vstart, later ones start at 0), and a runtime vtype
//                     that differs from the compiled one -- by policy bits only, or by SEW -- so
//                     every frame takes its ordered helper fallback (helper-helper-helper).
//
// ORACLES
//   * An element-wise reference over the architectural VectorState (all 32 registers over the full
//     VLEN_MAX_BYTES, vl, vtype, vstart, vlenb, vxrm, vxsat) and the GPRs vsetvli writes. It shares
//     no code with the translator or the helpers.
//   * The expected rvv_direct_fallbacks count is derived per executed frame from the frame's guard
//     KIND read from the QIR and the documented guard predicates in qir.h -- not from observation.
//     An unmodelled guard kind fails the test.
//   * Differential: the four arms must produce byte-identical post-state for every case.
//   * Census pass (separately compiled with --rvv-qcg-active-chunk-census on, which changes emitted
//     bytes and is therefore NOT the timed configuration): per execution, chunks_available and
//     chunks_executed must equal what rv32_active_chunk_plan.h's plan predicts for the middle frame
//     -- the runtime proof that M2 actually skipped suffix chunks between two M1 frames.
//   * Sensitivity: each bug model (stale residency across the middle, unpublished intermediate,
//     M2 over-skip, tail clobber, ignored vstart, ignored mask) is run through the SAME reference
//     and must differ from the correct reference on the generated cases, so each class of defect
//     would be caught by the post-state comparison.
//
// On a host without AVX-512F/BW/VL/DQ + BMI2 the test compiles every case (with the *_force_emit
// switches on, since route admission otherwise asks the host CPU) and checks the QIR structure, but
// executes nothing and says so.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qcg/rvv_both_boundary_campaign_config.h"
#include "dbt/qmc/qir.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <sys/mman.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{
int g_checks = 0;
int g_failures = 0;
FILE *g_csv = nullptr;

// NEGATIVE CONTROLS (test-only, expectation side only; the translator and the emitted code are
// untouched). RVV_BOTH_MUTATE=<name> deliberately corrupts ONE expectation so a run proves that the
// corresponding runtime comparison is live against real emitted output. Each must FAIL; the
// unmutated run must pass. See RESULT.md for the recorded outcomes.
enum class Mut : u8 { None, OracleStale, OracleOverSkip, OracleUnpublished, GuardModel, CensusUnbounded,
		      StructMulti, ArmDiff };
Mut g_mut = Mut::None;

#define CHECK_MSG(cond, ...)                                                                         \
	do {                                                                                         \
		++g_checks;                                                                          \
		if (!(cond)) {                                                                       \
			if (g_failures < 200) {                                                      \
				fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                 \
				fprintf(stderr, __VA_ARGS__);                                        \
				fprintf(stderr, "\n");                                               \
			}                                                                            \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

// ----------------------------------------------------------------------------------------------
// Guest encodings (RVV 1.0).
// ----------------------------------------------------------------------------------------------
constexpr u32 VT(u32 sew_log2_bytes, bool ta = false, bool ma = false)
{
	return (ma ? 1u << 7 : 0u) | (ta ? 1u << 6 : 0u) | (sew_log2_bytes << 3); // LMUL 1
}
constexpr u32 kE16 = VT(1), kE32 = VT(2), kE64 = VT(3);
constexpr u32 Vsetvli(u32 rd, u32 rs1, u32 vtype)
{
	return (vtype << 20) | (rs1 << 15) | (7u << 12) | (rd << 7) | 0x57u;
}
constexpr u32 OpIVV(u32 funct6, u32 vd, u32 vs2, u32 vs1, bool masked = false)
{
	return (funct6 << 26) | ((masked ? 0u : 1u) << 25) | (vs2 << 20) | (vs1 << 15) | (0u << 12) |
	       (vd << 7) | 0x57u;
}
enum class Alu : u8 { Add = 0, Sub = 2, MaxU = 6, Xor = 11 };

// One guest instruction of a scenario: either a vsetvli or an OPIVV element-wise op.
struct GInsn {
	bool setvl = false;
	u32 rd = 0, rs1 = 0, vtype = 0;		 // vsetvli
	Alu op = Alu::Add;			 // OPIVV
	u32 vd = 0, vs2 = 0, vs1 = 0;
	bool masked = false;
	u32 Encode() const
	{
		return setvl ? Vsetvli(rd, rs1, vtype) : OpIVV((u32)op, vd, vs2, vs1, masked);
	}
};
GInsn SetVL(u32 rd, u32 rs1, u32 vtype) { return {.setvl = true, .rd = rd, .rs1 = rs1, .vtype = vtype}; }
GInsn V(Alu op, u32 vd, u32 vs2, u32 vs1, bool masked = false)
{
	return {.op = op, .vd = vd, .vs2 = vs2, .vs1 = vs1, .masked = masked};
}

struct Scenario {
	char const *name;
	std::vector<GInsn> prog;
	u32 middle_raw;	   // the vmaxu encoding
	bool has_setvl;	   // vtype observed in the block
};

Scenario MakeS1()
{
	Scenario s{"S1_publication",
		   {SetVL(10, 10, kE32), V(Alu::Add, 8, 2, 3), V(Alu::Sub, 9, 8, 4), V(Alu::MaxU, 9, 9, 5),
		    V(Alu::Add, 10, 9, 8), V(Alu::Xor, 11, 10, 9)},
		   0, true};
	s.middle_raw = s.prog[3].Encode();
	return s;
}
Scenario MakeS2()
{
	Scenario s{"S2_masked_middle",
		   {SetVL(10, 10, kE32), V(Alu::Add, 8, 2, 3), V(Alu::Sub, 9, 8, 4),
		    V(Alu::MaxU, 9, 9, 5, /*masked=*/true), V(Alu::Add, 10, 9, 8), V(Alu::Xor, 11, 10, 9)},
		   0, true};
	s.middle_raw = s.prog[3].Encode();
	return s;
}
Scenario MakeS3()
{
	Scenario s{"S3_config_boundary",
		   {SetVL(10, 10, kE32), V(Alu::Add, 8, 2, 3), V(Alu::Sub, 9, 8, 4), SetVL(11, 11, kE64),
		    V(Alu::MaxU, 9, 9, 5), SetVL(12, 12, kE32), V(Alu::Add, 10, 9, 8), V(Alu::Xor, 11, 10, 9)},
		   0, true};
	s.middle_raw = s.prog[4].Encode();
	return s;
}
Scenario MakeS4()
{
	Scenario s{"S4_helper_guard",
		   {V(Alu::Add, 8, 2, 3), V(Alu::Sub, 9, 8, 4), V(Alu::MaxU, 9, 9, 5), V(Alu::Add, 10, 9, 8),
		    V(Alu::Xor, 11, 10, 9)},
		   0, false};
	s.middle_raw = s.prog[2].Encode();
	return s;
}

// ----------------------------------------------------------------------------------------------
// Independent reference.
// ----------------------------------------------------------------------------------------------
struct RefState {
	rv32::VectorState vec;
	u32 gpr[32]{};
};

// Bug models: the reference with ONE deliberate defect, used only to prove sensitivity.
enum class Bug : u8 {
	None,
	StaleResidency,	  // instructions after the middle read run A's v9, not the middle's
	UnpublishedInter, // run A's intermediate v8 never reaches architectural state
	M2OverSkip,	  // the middle drops the whole partially-active last unit
	TailClobber,	  // the middle writes every element up to VLMAX
	IgnoreVstart,	  // the first instruction restarts at element 0
	IgnoreMask,	  // the masked middle behaves as unmasked
	Count
};
char const *BugName(Bug b)
{
	static char const *n[] = {"None", "StaleResidency", "UnpublishedInter", "M2OverSkip",
				  "TailClobber", "IgnoreVstart", "IgnoreMask"};
	return n[(int)b];
}

u64 GetElem(rv32::VectorState const &v, u32 reg, u32 i, u32 sew)
{
	u64 x = 0;
	memcpy(&x, v.vreg[reg].data() + i * sew, sew);
	return x;
}
void SetElem(rv32::VectorState &v, u32 reg, u32 i, u32 sew, u64 x)
{
	memcpy(v.vreg[reg].data() + i * sew, &x, sew);
}
u64 AluRef(Alu op, u64 a /*vs2*/, u64 b /*vs1*/, u32 sew)
{
	u64 const m = sew == 8 ? ~0ull : ((1ull << (8 * sew)) - 1);
	switch (op) {
	case Alu::Add: return (a + b) & m;
	case Alu::Sub: return (a - b) & m;
	case Alu::MaxU: return std::max(a & m, b & m);
	case Alu::Xor: return (a ^ b) & m;
	}
	return 0;
}

// The M2 unit size for an e<sew> LMUL-1 equal-width frame: min(VLEN/8, 64) bytes (the builder's
// `bytes` for a non-shift, non-multiply op).
u32 UnitElems(u32 vlen, u32 sew) { return std::min(vlen / 8u, 64u) / sew; }

// Execute the scenario on the reference. `middle_index` is the program index of vmaxu.
void RefRun(Scenario const &sc, u32 vlen, RefState &st, Bug bug)
{
	u32 const vlmax_bytes = vlen / 8u;
	bool first_vector = true;
	std::array<u8, rv32::VLEN_MAX_BYTES> v9_before_middle{};
	bool middle_done = false;
	for (auto const &g : sc.prog) {
		if (g.setvl) {
			u32 const sew = 1u << ((g.vtype >> 3) & 7u);
			u32 const vlmax = vlmax_bytes / sew;
			u32 const avl = st.gpr[g.rs1];
			// Only spec-determined AVLs are generated: avl <= VLMAX or avl >= 2*VLMAX.
			u32 const vl = avl <= vlmax ? avl : vlmax;
			st.vec.vtype = g.vtype;
			st.vec.vl = vl;
			st.vec.vstart = 0;
			if (g.rd)
				st.gpr[g.rd] = vl;
			first_vector = false;
			continue;
		}
		u32 const sew = 1u << ((st.vec.vtype >> 3) & 7u);
		bool const is_middle = g.op == Alu::MaxU;
		u32 start = st.vec.vstart;
		if (bug == Bug::IgnoreVstart && first_vector)
			start = 0;
		u32 end = st.vec.vl;
		if (is_middle && bug == Bug::M2OverSkip) {
			u32 const e = UnitElems(vlen, sew);
			end = std::max(e, (end / e) * e); // unit 0 always runs; drops the partial last unit
			end = std::min(end, st.vec.vl);
		}
		if (is_middle && bug == Bug::TailClobber)
			end = vlmax_bytes / sew;
		bool const masked = g.masked && !(is_middle && bug == Bug::IgnoreMask);
		if (is_middle)
			v9_before_middle = st.vec.vreg[9];
		rv32::VectorState const in = st.vec;
		auto src = [&](u32 reg, u32 i) -> u64 {
			if (bug == Bug::StaleResidency && middle_done && reg == 9) {
				u64 x = 0;
				memcpy(&x, v9_before_middle.data() + i * sew, sew);
				return x;
			}
			return GetElem(in, reg, i, sew);
		};
		for (u32 i = start; i < end; ++i) {
			if (masked && !in.mask_get(0, i))
				continue;
			SetElem(st.vec, g.vd, i, sew, AluRef(g.op, src(g.vs2, i), src(g.vs1, i), sew));
		}
		if (bug == Bug::UnpublishedInter && g.op == Alu::Add && g.vd == 8)
			st.vec.vreg[8] = in.vreg[8];
		st.vec.vstart = 0;
		first_vector = false;
		if (is_middle)
			middle_done = true;
	}
}

// ----------------------------------------------------------------------------------------------
// Build + execute harness (same entry trampoline as rvv_vector_run_value_test.cpp).
// ----------------------------------------------------------------------------------------------
struct Runtime final : CompilerRuntime {
	~Runtime()
	{
		if (mem)
			munmap(mem, size);
	}
	void *AllocateCode(size_t n, uint) override
	{
		size = (n + 64 + 4095) & ~size_t(4095);
		mem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
			   -1, 0);
		if (mem == MAP_FAILED)
			Panic("both-boundary test: code mmap failed");
		last = static_cast<u8 *>(mem);
		return mem;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	void *mem{};
	u8 *last{};
	size_t size{};
};

extern "C" __attribute__((noinline, naked)) void BothEnter(void *, void *, void *);
extern "C" __attribute__((noinline, naked)) void BothEnter(void *, void *, void *)
{
	asm("pushq %rbp\n\tpushq %rbx\n\tpushq %r12\n\tpushq %r13\n\tpushq %r14\n\tpushq %r15\n\t"
	    "movq %rdi,%r13\n\tmovq %rsi,%rbp\n\t");
	asm("sub $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("callq *%rdx\n\t");
	asm("add $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("popq %r15\n\tpopq %r14\n\tpopq %r13\n\tpopq %r12\n\tpopq %rbx\n\tpopq %rbp\n\tretq\n\t");
}

enum Arm { ArmB, ArmM1, ArmM2, ArmBoth, ArmCount };
char const *ArmName(int a) { static char const *n[] = {"B", "M1", "M2", "BOTH"}; return n[a]; }

bool g_execute = false; // host can run the emitted AVX-512 code

void ApplyArm(int arm, u32 vlen, bool census)
{
	switch (arm) {
	case ArmB: campaign_config::ApplyCampaignArm_B(); break;
	case ArmM1: campaign_config::ApplyCampaignArm_M1(); break;
	case ArmM2: campaign_config::ApplyCampaignArm_M2(); break;
	default: campaign_config::ApplyCampaignArm_BOTH(); break;
	}
	if (!g_execute)
		campaign_config::ForceEmitAll();
	config::vlen_bits = vlen;
	config::rvv_qcg_active_chunk_census = census;
	config::trace = false;
}

using GuardKind = InstRVVTypedChunkBegin::GuardKind;

// One compiled frame, in QIR (== execution) order.
struct Frame {
	u32 first_raw = 0;
	u8 n_members = 0;
	GuardKind guard = GuardKind::VTypeVlVstart;
	u32 vtype = 0, vlmax = 0;
	unsigned bound_nodes = 0;
	std::vector<u32> member_raws;
};

struct Built {
	MemArena arena{1u << 22};
	std::vector<u32> words;
	Runtime runtime;
	Region *region{};
	u8 *code{};
	std::vector<Frame> frames;
	std::vector<RuntimeStubId> hcalls;
	unsigned bound_nodes_total = 0;
	unsigned bound_nodes_in_multi = 0;
};

void Build(Built &b, Scenario const &sc)
{
	for (auto const &g : sc.prog)
		b.words.push_back(g.Encode());
	CompilerJob::IpRangesSet ranges = {{0u, static_cast<u32>(b.words.size() * 4u)}};
	CompilerJob job(nullptr, reinterpret_cast<uptr>(b.words.data()), CodeSegment(0u, 0x1000u),
			std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	Frame *open = nullptr;
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin: {
				auto &bi = static_cast<InstRVVTypedChunkBegin &>(ins);
				b.frames.push_back({.first_raw = bi.raw, .n_members = bi.n_members,
						    .guard = bi.guard_kind, .vtype = bi.vtype, .vlmax = bi.vlmax});
				open = &b.frames.back();
				break;
			}
			case Op::_vchunkactive:
				++b.bound_nodes_total;
				if (open) {
					++open->bound_nodes;
					if (open->n_members > 1)
						++b.bound_nodes_in_multi;
				}
				break;
			case Op::_rvvtypedchunkend: {
				auto &ei = static_cast<InstRVVTypedChunkEnd &>(ins);
				if (open)
					for (u32 m = 0; m < ei.n_members; ++m)
						open->member_raws.push_back(ei.members[m].raw);
				open = nullptr;
				break;
			}
			case Op::_hcall:
				b.hcalls.push_back(static_cast<InstHcall &>(ins).stub);
				break;
			default: break;
			}
		}
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.runtime, &segment, b.region, 0);
	CHECK_MSG(!span.empty(), "%s: generated region is empty", sc.name);
	b.code = b.runtime.last;
	size_t n = span.size();
	if (b.code[0] == 0x51)
		b.code[n++] = 0x59;
	b.code[n] = 0xc3;
}

struct Outcome {
	rv32::VectorState vec;
	u32 gpr[32];
	u64 fallbacks;
	u64 census_available, census_executed;
};

void Execute(Built &b, RefState const &init, Outcome &out)
{
	CPUState state(nullptr);
	memset(static_cast<void *>(&state), 0, sizeof state);
	state.vec = init.vec;
	memcpy(state.gpr.data(), init.gpr, sizeof init.gpr);
	u64 const a0 = rv32::g_rvv_chunks_available, e0 = rv32::g_rvv_chunks_executed;
	BothEnter(&state, nullptr, b.code);
	out.vec = state.vec;
	memcpy(out.gpr, state.gpr.data(), sizeof out.gpr);
	out.fallbacks = state.rvv_direct_fallbacks;
	out.census_available = rv32::g_rvv_chunks_available - a0;
	out.census_executed = rv32::g_rvv_chunks_executed - e0;
}

// ----------------------------------------------------------------------------------------------
// Guard model: qir.h's documented predicates, per kind. Returns false for an unmodelled kind.
// ----------------------------------------------------------------------------------------------
bool GuardPasses(Frame const &f, u32 vtype, u32 vl, u32 vstart, bool *modelled)
{
	*modelled = true;
	bool const vt = vtype == f.vtype;
	switch (f.guard) {
	case GuardKind::VTypeVlVstart: return vt && vl == f.vlmax && vstart == 0;
	case GuardKind::VTypeVlOrPartialVstart: return vt && vstart == 0 && vl <= f.vlmax;
	case GuardKind::VTypeInteger: return vt && vl <= f.vlmax;
	case GuardKind::VTypeIntegerTwoArm:
		if (g_mut == Mut::GuardModel)
			return vt && vl == f.vlmax && vstart == 0;
		return vt && vl <= f.vlmax;
	case GuardKind::VTypeIntegerNoRestart: return vt && vl <= f.vlmax && vstart == 0;
	default: *modelled = false; return false;
	}
}

// Architectural (vtype, vl, vstart) seen by each program index, from the reference.
struct PreState {
	u32 vtype, vl, vstart;
};
std::vector<PreState> PreStates(Scenario const &sc, u32 vlen, RefState st)
{
	std::vector<PreState> pre;
	u32 const vlmax_bytes = vlen / 8u;
	for (auto const &g : sc.prog) {
		pre.push_back({st.vec.vtype, st.vec.vl, st.vec.vstart});
		if (g.setvl) {
			u32 const sew = 1u << ((g.vtype >> 3) & 7u), vlmax = vlmax_bytes / sew;
			u32 const avl = st.gpr[g.rs1];
			st.vec.vtype = g.vtype;
			st.vec.vl = avl <= vlmax ? avl : vlmax;
			st.vec.vstart = 0;
			if (g.rd)
				st.gpr[g.rd] = st.vec.vl;
		} else {
			st.vec.vstart = 0;
		}
	}
	return pre;
}

// Expected fallbacks and, for the census pass, expected chunk counts.
struct Expect {
	u64 fallbacks = 0, available = 0, executed = 0;
	bool modelled = true;
};
Expect Predict(Built const &b, Scenario const &sc, u32 vlen, RefState const &init)
{
	Expect e;
	auto const pre = PreStates(sc, vlen, init);
	for (auto const &f : b.frames) {
		// Locate the frame's first member in the program (every word is distinct by construction).
		u32 idx = ~0u;
		for (u32 i = 0; i < sc.prog.size(); ++i)
			if (sc.prog[i].Encode() == f.first_raw)
				idx = i;
		if (idx == ~0u) {
			e.modelled = false;
			continue;
		}
		bool modelled = true;
		bool const pass = GuardPasses(f, pre[idx].vtype, pre[idx].vl, pre[idx].vstart, &modelled);
		e.modelled &= modelled;
		if (!pass) {
			++e.fallbacks;
			continue;
		}
		// Census: only the single-instruction planner-eligible middle frame contributes (run and
		// fixed-shape frames close with census_units == 0). Units and bounds come from the plan.
		if (f.first_raw == sc.middle_raw) {
			u32 const sew = 1u << ((f.vtype >> 3) & 7u);
			u32 const epu = UnitElems(vlen, sew);
			u32 const units = (vlen / 8u + std::min(vlen / 8u, 64u) - 1) / std::min(vlen / 8u, 64u);
			e.available += units;
			if (f.bound_nodes == 0 || g_mut == Mut::CensusUnbounded) {
				e.executed += units;
			} else {
				// first_bounded_unit == 1 (LastChunkNode); unit c >= 1 runs iff vl > c*epu and
				// every earlier bound fell through.
				u32 ex = 1;
				for (u32 c = 1; c < units && pre[idx].vl > c * epu; ++c)
					++ex;
				e.executed += ex;
			}
		}
	}
	return e;
}

// ----------------------------------------------------------------------------------------------
// Seeds and case generation.
// ----------------------------------------------------------------------------------------------
void Seed(RefState &st, u32 vlen, u32 salt)
{
	(void)vlen;
	u64 x = 0x9e3779b97f4a7c15ull ^ salt;
	for (u32 r = 0; r < 32; ++r)
		for (u32 i = 0; i < rv32::VLEN_MAX_BYTES; ++i) {
			x ^= x << 13;
			x ^= x >> 7;
			x ^= x << 17;
			st.vec.vreg[r][i] = (u8)x;
		}
	st.vec.vxrm = 2;
	st.vec.vxsat = 1;
	st.vec.fused_skip_pc = 0;
	st.vec.fused_skip_raw = 0;
	st.vec.fused_skip_valid = false;
}

std::vector<u32> Ladder(u32 vlmax, u32 epu)
{
	std::set<u32> s = {0, 1, 2, vlmax - 1, vlmax, 2 * vlmax, 3 * vlmax + 1};
	for (u32 c = 1; c * epu <= vlmax; ++c)
		for (i32 d : {-1, 0, 1}) {
			i64 const v = (i64)c * epu + d;
			if (v >= 0 && v <= vlmax)
				s.insert((u32)v);
		}
	return {s.begin(), s.end()};
}

struct Case {
	std::string label;
	RefState init;
};

std::vector<Case> Cases(Scenario const &sc, u32 vlen, Built const *b_for_vtype)
{
	std::vector<Case> out;
	u32 const e32max = vlen / 32u, e64max = vlen / 64u;
	u32 const e32u = UnitElems(vlen, 4), e64u = UnitElems(vlen, 8);
	auto base = [&](u32 salt) {
		RefState st{};
		Seed(st, vlen, salt);
		st.vec.vlenb = vlen / 8u;
		st.vec.vtype = rv32::VTYPE_VILL_BIT;
		return st;
	};
	char buf[128];
	if (sc.name[1] == '1' || sc.name[1] == '2') {
		// Dense: every vl from 0..VLMAX plus spec-determined AVLs above 2*VLMAX.
		for (u32 avl = 0; avl <= e32max; ++avl) {
			RefState st = base(avl * 7919u + sc.name[1]);
			st.gpr[10] = avl;
			snprintf(buf, sizeof buf, "avl=%u", avl);
			out.push_back({buf, st});
		}
		for (u32 avl : {2 * e32max, 5 * e32max + 3}) {
			RefState st = base(avl * 31u);
			st.gpr[10] = avl;
			snprintf(buf, sizeof buf, "avl=%u", avl);
			out.push_back({buf, st});
		}
	} else if (sc.name[1] == '3') {
		for (u32 a0 : Ladder(e32max, e32u))
			for (u32 a1 : Ladder(e64max, e64u))
				for (u32 a2 : Ladder(e32max, e32u)) {
					RefState st = base(a0 * 131u + a1 * 17u + a2);
					st.gpr[10] = a0;
					st.gpr[11] = a1;
					st.gpr[12] = a2;
					snprintf(buf, sizeof buf, "avl=%u/%u/%u", a0, a1, a2);
					out.push_back({buf, st});
				}
	} else {
		// S4: no vsetvli in the block. The compiled vtype of the fixed-shape run routes is read
		// from the QIR (it is a translation-time fact of those routes, not of this test).
		u32 compiled_vtype = kE32;
		if (b_for_vtype && !b_for_vtype->frames.empty())
			compiled_vtype = b_for_vtype->frames.front().vtype;
		// The compiled vtype (guards pass), the same SEW with different policy bits, and a
		// different SEW: the last two must fail every frame guard (exact-vtype compare).
		for (u32 vtype : std::set<u32>{compiled_vtype, kE32, kE16}) {
			u32 const sew = 1u << ((vtype >> 3) & 7u), vlmax = vlen / 8u / sew;
			for (u32 vl = 0; vl <= vlmax; ++vl) {
				std::set<u32> starts = {0, 1, 5, vl ? vl - 1 : 0, vl, vl + 1};
				for (u32 vs : starts) {
					if (vs >= vlmax)
						continue;
					RefState st = base(vl * 977u + vs * 13u + vtype);
					st.vec.vtype = vtype;
					st.vec.vl = vl;
					st.vec.vstart = vs;
					snprintf(buf, sizeof buf, "vtype=0x%x vl=%u vstart=%u", vtype, vl, vs);
					out.push_back({buf, st});
				}
			}
		}
	}
	return out;
}

bool SameState(rv32::VectorState const &a, u32 const *ag, rv32::VectorState const &b, u32 const *bg,
	       std::string *why)
{
	char buf[160];
	for (u32 r = 0; r < 32; ++r)
		if (memcmp(a.vreg[r].data(), b.vreg[r].data(), rv32::VLEN_MAX_BYTES) != 0) {
			u32 i = 0;
			while (a.vreg[r][i] == b.vreg[r][i])
				++i;
			snprintf(buf, sizeof buf, "v%u differs first at byte %u", r, i);
			*why = buf;
			return false;
		}
	if (a.vtype != b.vtype || a.vl != b.vl || a.vstart != b.vstart || a.vlenb != b.vlenb ||
	    a.vxrm != b.vxrm || a.vxsat != b.vxsat) {
		snprintf(buf, sizeof buf, "csr vtype=%x/%x vl=%u/%u vstart=%u/%u vlenb=%u/%u", a.vtype, b.vtype,
			 a.vl, b.vl, a.vstart, b.vstart, a.vlenb, b.vlenb);
		*why = buf;
		return false;
	}
	for (u32 r : {10u, 11u, 12u})
		if (ag[r] != bg[r]) {
			snprintf(buf, sizeof buf, "x%u=%u/%u", r, ag[r], bg[r]);
			*why = buf;
			return false;
		}
	return true;
}

// ----------------------------------------------------------------------------------------------
// Structural expectations, derived from source (see the header comment and RESULT.md):
//   * M1/BOTH form exactly two multi-member frames (run A, run B); B/M2 form none.
//   * No _vchunkactive is ever inside a multi-member frame.
//   * S1-S3: the middle is a single-instruction VTypeInteger frame on every arm; it carries
//     units-1 bound nodes on M2/BOTH when units >= 2 (LastChunkNode) and none otherwise.
//   * S4: no frame carries the middle; it is exactly one _hcall(rv32_vialu); no bound nodes.
// ----------------------------------------------------------------------------------------------
void CheckStructure(Built const &b, Scenario const &sc, int arm, u32 vlen)
{
	unsigned multi = 0;
	for (auto const &f : b.frames)
		multi += f.n_members > 1;
	bool const m1 = arm == ArmM1 || arm == ArmBoth, m2 = arm == ArmM2 || arm == ArmBoth;
	unsigned const want_multi = (m1 ? 2u : 0u) + (g_mut == Mut::StructMulti ? 1u : 0u);
	CHECK_MSG(multi == want_multi, "%s VLEN=%u %s: %u multi-member frames", sc.name, vlen,
		  ArmName(arm), multi);
	CHECK_MSG(b.bound_nodes_in_multi == 0, "%s VLEN=%u %s: bound node inside a member-major run",
		  sc.name, vlen, ArmName(arm));
	if (m1)
		for (auto const &f : b.frames)
			if (f.n_members > 1)
				CHECK_MSG(std::find(f.member_raws.begin(), f.member_raws.end(), sc.middle_raw) ==
						  f.member_raws.end(),
					  "%s VLEN=%u %s: middle absorbed into a run", sc.name, vlen, ArmName(arm));
	Frame const *mid = nullptr;
	for (auto const &f : b.frames)
		if (f.first_raw == sc.middle_raw)
			mid = &f;
	unsigned mid_hcalls = (unsigned)std::count(b.hcalls.begin(), b.hcalls.end(), RuntimeStubId::id_rv32_vialu);
	if (sc.has_setvl) {
		CHECK_MSG(mid && mid->n_members == 1 && mid->guard == GuardKind::VTypeInteger,
			  "%s VLEN=%u %s: middle is not a single VTypeInteger frame", sc.name, vlen, ArmName(arm));
		CHECK_MSG(mid_hcalls == 0, "%s VLEN=%u %s: middle also emitted a helper call", sc.name, vlen,
			  ArmName(arm));
		if (mid) {
			u32 const bytes = std::min(vlen / 8u, 64u);
			u32 const units = (vlen / 8u + bytes - 1) / bytes;
			u32 const want = (m2 && units >= 2) ? units - 1 : 0;
			CHECK_MSG(mid->bound_nodes == want, "%s VLEN=%u %s: middle bound nodes %u, expected %u",
				  sc.name, vlen, ArmName(arm), mid->bound_nodes, want);
			CHECK_MSG(b.bound_nodes_total == mid->bound_nodes,
				  "%s VLEN=%u %s: bound nodes outside the middle frame (%u total)", sc.name, vlen,
				  ArmName(arm), b.bound_nodes_total);
		}
	} else {
		CHECK_MSG(mid == nullptr, "%s VLEN=%u %s: middle unexpectedly native without observed vtype",
			  sc.name, vlen, ArmName(arm));
		CHECK_MSG(mid_hcalls == 1, "%s VLEN=%u %s: expected one rv32_vialu helper call, got %u", sc.name,
			  vlen, ArmName(arm), mid_hcalls);
		CHECK_MSG(b.bound_nodes_total == 0, "%s VLEN=%u %s: bound nodes without an observed vtype",
			  sc.name, vlen, ArmName(arm));
	}
}

std::string Signature(Built const &b)
{
	std::string s;
	char buf[96];
	for (auto const &f : b.frames) {
		snprintf(buf, sizeof buf, "[%08x m=%u g=%u vt=%x vlmax=%u bnd=%u]", f.first_raw, f.n_members,
			 (unsigned)f.guard, f.vtype, f.vlmax, f.bound_nodes);
		s += buf;
	}
	for (auto h : b.hcalls) {
		snprintf(buf, sizeof buf, "[hcall %u]", (unsigned)h);
		s += buf;
	}
	return s;
}

struct Totals {
	unsigned executions = 0, fallback_execs = 0, native_mid = 0, skipped_units = 0;
};

void RunScenario(Scenario const &sc, u32 vlen, std::map<std::string, Totals> &tot)
{
	Built built[ArmCount];
	for (int arm = 0; arm < ArmCount; ++arm) {
		ApplyArm(arm, vlen, /*census=*/false);
		Build(built[arm], sc);
		CheckStructure(built[arm], sc, arm, vlen);
		printf("STRUCT %s VLEN=%u %s %s\n", sc.name, vlen, ArmName(arm), Signature(built[arm]).c_str());
	}
	if (!g_execute)
		return;
	// Census builds: same arms, census on. Separate code; never mixed with the timed config.
	Built census[ArmCount];
	for (int arm = 0; arm < ArmCount; ++arm) {
		ApplyArm(arm, vlen, /*census=*/true);
		Build(census[arm], sc);
	}
	auto const cases = Cases(sc, vlen, &built[ArmB]);
	for (auto const &c : cases) {
		RefState want = c.init;
		RefRun(sc, vlen, want,
		       g_mut == Mut::OracleStale	 ? Bug::StaleResidency
		       : g_mut == Mut::OracleOverSkip	 ? Bug::M2OverSkip
		       : g_mut == Mut::OracleUnpublished ? Bug::UnpublishedInter
							 : Bug::None);
		Outcome got[ArmCount];
		for (int arm = 0; arm < ArmCount; ++arm) {
			Execute(built[arm], c.init, got[arm]);
			Expect const ex = Predict(built[arm], sc, vlen, c.init);
			std::string why;
			bool const ok = SameState(got[arm].vec, got[arm].gpr, want.vec, want.gpr, &why);
			CHECK_MSG(ok, "%s VLEN=%u %s %s: post-state != oracle: %s", sc.name, vlen, ArmName(arm),
				  c.label.c_str(), why.c_str());
			CHECK_MSG(ex.modelled, "%s VLEN=%u %s: unmodelled guard kind or frame", sc.name, vlen,
				  ArmName(arm));
			CHECK_MSG(got[arm].fallbacks == ex.fallbacks,
				  "%s VLEN=%u %s %s: fallbacks=%llu expected %llu", sc.name, vlen, ArmName(arm),
				  c.label.c_str(), (unsigned long long)got[arm].fallbacks,
				  (unsigned long long)ex.fallbacks);
			CHECK_MSG(got[arm].census_available == 0 && got[arm].census_executed == 0,
				  "%s VLEN=%u %s: census counters moved in the non-census build", sc.name, vlen,
				  ArmName(arm));
			// Census pass on the same initial state.
			Outcome cg;
			Execute(census[arm], c.init, cg);
			Expect const cx = Predict(census[arm], sc, vlen, c.init);
			std::string cwhy;
			CHECK_MSG(SameState(cg.vec, cg.gpr, want.vec, want.gpr, &cwhy),
				  "%s VLEN=%u %s %s: census build post-state != oracle: %s", sc.name, vlen,
				  ArmName(arm), c.label.c_str(), cwhy.c_str());
			CHECK_MSG(cg.census_available == cx.available && cg.census_executed == cx.executed,
				  "%s VLEN=%u %s %s: census available/executed=%llu/%llu expected %llu/%llu",
				  sc.name, vlen, ArmName(arm), c.label.c_str(),
				  (unsigned long long)cg.census_available, (unsigned long long)cg.census_executed,
				  (unsigned long long)cx.available, (unsigned long long)cx.executed);
			auto &t = tot[std::string(sc.name) + "," + std::to_string(vlen) + "," + ArmName(arm)];
			++t.executions;
			t.fallback_execs += got[arm].fallbacks != 0;
			t.native_mid += cx.available != 0;
			t.skipped_units += (unsigned)(cg.census_available - cg.census_executed);
			if (g_csv)
				fprintf(g_csv, "%s,%u,%s,\"%s\",%s,%llu,%llu,%llu,%llu,%llu,%llu,%s\n", sc.name, vlen,
					ArmName(arm), c.label.c_str(), ok ? "MATCH" : "MISMATCH",
					(unsigned long long)got[arm].fallbacks, (unsigned long long)ex.fallbacks,
					(unsigned long long)cg.census_available, (unsigned long long)cx.available,
					(unsigned long long)cg.census_executed, (unsigned long long)cx.executed,
					got[arm].vec.vl == want.vec.vl ? "vl_ok" : "vl_bad");
		}
		if (g_mut == Mut::ArmDiff)
			got[ArmB].vec.vreg[31][0] ^= 1; // flips only the differential's reference copy
		for (int arm = 1; arm < ArmCount; ++arm) {
			std::string why;
			CHECK_MSG(SameState(got[arm].vec, got[arm].gpr, got[ArmB].vec, got[ArmB].gpr, &why),
				  "%s VLEN=%u %s vs B %s: arms differ: %s", sc.name, vlen, ArmName(arm),
				  c.label.c_str(), why.c_str());
		}
	}
}

// Every bug model must be visible to the post-state comparison on the cases this test generates.
void CheckSensitivity(std::vector<Scenario> const &scs)
{
	for (int bi = 1; bi < (int)Bug::Count; ++bi) {
		Bug const bug = (Bug)bi;
		unsigned detected = 0, cases = 0;
		for (auto const &sc : scs) {
			if (bug == Bug::IgnoreMask && sc.name[1] != '2')
				continue;
			if (bug == Bug::IgnoreVstart && sc.name[1] != '4')
				continue;
			for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u}) {
				// S4 cases need the compiled vtype only to pick the matching runtime vtype; the
				// reference itself is vtype-generic, so kE32 is used here.
				for (auto const &c : Cases(sc, vlen, nullptr)) {
					RefState good = c.init, bad = c.init;
					RefRun(sc, vlen, good, Bug::None);
					RefRun(sc, vlen, bad, bug);
					std::string why;
					++cases;
					detected += !SameState(good.vec, good.gpr, bad.vec, bad.gpr, &why);
				}
			}
		}
		CHECK_MSG(detected > 0, "bug model %s is invisible to the oracle on %u cases", BugName(bug), cases);
		printf("SENSITIVITY bug=%s detected_in=%u/%u cases\n", BugName(bug), detected, cases);
	}
}
} // namespace

int main(int argc, char **argv)
{
	config::rvv_qcg_active_vl_mask_fusion = std::getenv("RVV_MASK_BOUND_FUSION") != nullptr;
#if defined(__x86_64__)
	__builtin_cpu_init();
	g_execute = __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512bw") &&
		    __builtin_cpu_supports("avx512vl") && __builtin_cpu_supports("avx512dq") &&
		    __builtin_cpu_supports("bmi2");
#endif
	if (char const *m = getenv("RVV_BOTH_MUTATE")) {
		static std::map<std::string, Mut> const names = {
		    {"oracle_stale", Mut::OracleStale}, {"oracle_overskip", Mut::OracleOverSkip},
		    {"oracle_unpublished", Mut::OracleUnpublished}, {"guard_model", Mut::GuardModel},
		    {"census_unbounded", Mut::CensusUnbounded}, {"struct_multi", Mut::StructMulti},
		    {"arm_diff", Mut::ArmDiff}};
		auto it = names.find(m);
		if (it == names.end()) {
			fprintf(stderr, "unknown RVV_BOTH_MUTATE=%s\n", m);
			return 2;
		}
		g_mut = it->second;
		printf("MUTATION %s (negative control: this run MUST fail)\n", m);
	}
	if (argc > 1) {
		g_csv = fopen(argv[1], "w");
		if (!g_csv) {
			perror(argv[1]);
			return 2;
		}
		fprintf(g_csv, "scenario,vlen,arm,case,oracle,fallbacks,expected_fallbacks,census_available,"
			       "expected_available,census_executed,expected_executed,vl\n");
	}
	printf("MODE %s\n", g_execute ? "EXECUTE (AVX-512F/BW/VL/DQ + BMI2 present; campaign config, no force-emit)"
				      : "STRUCTURE-ONLY (host lacks AVX-512; *_force_emit on; nothing executed)");
	std::vector<Scenario> const scs = {MakeS1(), MakeS2(), MakeS3(), MakeS4()};
	CheckSensitivity(scs);
	std::map<std::string, Totals> tot;
	for (auto const &sc : scs)
		for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
			RunScenario(sc, vlen, tot);
	for (auto const &[k, t] : tot)
		printf("TOTAL %s executions=%u with_fallback=%u native_middle=%u skipped_units=%u\n", k.c_str(),
		       t.executions, t.fallback_execs, t.native_mid, t.skipped_units);
	if (g_csv)
		fclose(g_csv);
	printf("RVV_BOTH_BOUNDARY_TEST mode=%s checks=%d failures=%d\n", g_execute ? "execute" : "structure",
	       g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
