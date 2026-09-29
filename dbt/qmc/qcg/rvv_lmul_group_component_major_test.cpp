// C4k: INTEGRAL LMUL REGISTER GROUPS IN THE GROUPED COMPONENT-MAJOR RUN PREDICATE.
//
// Design: C4J_LMUL2_GROUPED_RUN_DESIGN_20260914.md, option A. The change is two conditions inside
// `rvvrun::RvvRunFrameSeparable` plus one caller permission (`rvvrun::GroupAddressing`), and
// NOTHING else: no new QIR op, no emitter change, no CLI change, no admission change, no default
// change. This suite is what makes each half of that claim falsifiable.
//
// WHY A SEPARATE BINARY FROM rvv_grouped_component_major_test. That suite pins the C4e/C4h claims
// at EMUL = 1 and its numbers ARE the pre-C4k behaviour; leaving it untouched is itself part of the
// evidence. Everything C4k adds lives here.
//
// THE SECTIONS, AND WHAT EACH WOULD CATCH:
//
//   [1] THE PREDICATE TRUTH TABLE. `lmul_log2` from -3 to 7 crossed with both GroupAddressing
//       values, each with a geometry that is consistent for THAT EMUL. Only an integral, in-range
//       EMUL passes, and only EMUL = 1 passes without the caller's permission. A deleted
//       permission conjunct, a deleted fractional-EMUL refusal or a deleted range check each flip
//       a named row.
//   [2] THE PRE-C4k REFERENCE, EXHAUSTIVELY, AT EMUL = 1. The old conjunction is re-implemented
//       here from the source text it replaced, and the two are compared on every point of a fact
//       grid. This is the "EMUL = 1 answers are unchanged" claim as a test rather than as an
//       argument, and it is what would catch a new conjunct that looked harmless.
//   [3] THE TWO NEW GEOMETRY FACTS, ISOLATED. A fact set that STRADDLES a register boundary and a
//       fact set that does not COVER the group are each rejected while every other conjunct holds,
//       and each is paired with the accepted fact set it differs from by one field. Zero and
//       overflow inputs fail closed rather than divide, wrap or index.
//   [4] THE COMPONENT-SEPARABLE PATH IS UNCHANGED. `RvvRunComponentSeparable` keeps the refusing
//       default, so it still answers false on every EMUL != 1 input -- on synthetic facts AND on a
//       real e32,m2 descriptor that `RvvRunGroupedComponentMajor` accepts.
//   [5] AN EMUL = 2 RUN REALLY FORMS AND ITS BODY REALLY IS COMPONENT-MAJOR: k = 4 slices at
//       VLEN 1024, slice c closed before slice c+1 opens.
//   [6] B -> C IS STILL A SINGLE FACTOR AT EMUL = 2. Arm C's body minus its `vchunkactive` nodes
//       equals arm B's body node for node; the bounds are k in number with ascending chunk index
//       and element base c * lanes, each immediately before its own slice's mask node.
//   [7] CROSS-REGISTER COMPONENT DATAFLOW. Components 2 and 3 live in the group's SECOND
//       architectural register. Every state offset a slice names is re-derived here from the RVV
//       1.0 element-placement rule -- NOT by calling `group_chunk_location` -- and the base-register
//       set implied by each component's offsets must be the SAME set for every component. Then the
//       dataflow itself: each member's component-c source is the value the previous member
//       published for the SAME c.
//   [8] OVERLAP AND THE FUSED OLD vd AT EMUL = 2. A run holding vd == vs2, vd == vs1 == vs2 and a
//       `vfmacc.vv` that reads its old vd forms, groups, and binds every source before publishing
//       the destination -- checked from the emitted SSA operands, per component.
//   [9] REGISTER PRESSURE IS STILL FAIL-CLOSED, AND STILL SCALES WITH k. The same three guest
//       words form a three-member run at EMUL = 1 (k = 2) and a two-member run at EMUL = 2
//       (k = 4), cut by `CutReason::RegisterPressure`. C4k does not touch the admission bound and
//       this is where that is visible.
//  [10] GENERAL ADMISSION IS UNCHANGED BY THE GROUPED SWITCH. The RVV_RUN counters are identical
//       with the switch off and on, at EMUL = 1 and at EMUL = 2. The grouped switch stays an
//       EMISSION-side switch, which is what elfrun's own option text promises.
//  [11] FAIL-CLOSED CONTRACTS, IN CHILD PROCESSES, AT EMUL = 2. An unmutated control first, then
//       two one-field mutations of the emitted frame that must abort rather than produce code.
//
// EVERY SECTION CARRIES A NEGATIVE CONTROL. A predicate stuck at one answer, an empty counter
// comparison, a grid nothing accepts and a build that Panics on everything are each excluded by an
// explicit check rather than by the absence of a FAIL line.

#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"

#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
namespace rvvrun = dbt::rv32::rvvrun;

namespace
{
int g_failures = 0;

#define CHECK(cond)                                                                                  \
	do {                                                                                         \
		if (!(cond)) {                                                                       \
			fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);            \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

#define CHECK_EQ(a, b)                                                                               \
	do {                                                                                         \
		long long _a = (long long)(a);                                                       \
		long long _b = (long long)(b);                                                       \
		if (_a != _b) {                                                                      \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__,          \
				__LINE__, #a, #b, _a, _b);                                           \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

using GA = rvvrun::GroupAddressing;
using CutReason = rvvrun::CutReason;

// ---------------------------------------------------------------------------------------------
// [0] Compile-time pins. If any of these moves, the numbers below stop meaning what they say.
// ---------------------------------------------------------------------------------------------
static_assert(rvvrun::kMaxChunks >= 4, "an e32,m2 group at VLEN 1024 is four 512-bit components");
static_assert((unsigned)GA::SingleRegister == 0,
	      "the refusing value must be the zero-initialized one, so an un-updated caller refuses");

// ---------------------------------------------------------------------------------------------
// Guest encodings. Field by field; nothing here is a workload constant.
// ---------------------------------------------------------------------------------------------
constexpr u32 MakeOpV(u32 f6, u32 vm, u32 vs2, u32 src1, u32 vd, u32 funct3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (src1 << 15) | (funct3 << 12) | (vd << 7) |
	       0x57u;
}
constexpr u32 Vv(u32 f6, u32 vs2, u32 vs1, u32 vd) { return MakeOpV(f6, 1, vs2, vs1, vd, 0b001u); }

constexpr u32 F6_VFADD = 0b000000u, F6_VFSUB = 0b000010u, F6_VFMUL = 0b100100u;
constexpr u32 F6_VFDIV = 0b100000u, F6_VFSGNJN = 0b001001u, F6_VFMACC = 0b101100u;

// The vtype immediate is built from its FIELDS so the LMUL digit is a field and not a magic
// number: [2:0] LMUL (001 = m2), [5:3] log2(SEW bytes), [6] vta, [7] vma.
constexpr u32 VType(u32 lmul3, u32 sew_log2_bytes, u32 vta, u32 vma)
{
	return lmul3 | (sew_log2_bytes << 3) | (vta << 6) | (vma << 7);
}
// vsetvli a0, a0, <vtype>
constexpr u32 Vsetvli(u32 vtype)
{
	return (vtype << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | 0x57u;
}

constexpr u32 VT_E32M1 = VType(0b000, 2, 1, 1); // e32, m1, ta, ma
constexpr u32 VT_E32M2 = VType(0b001, 2, 1, 1); // e32, m2, ta, ma
constexpr u32 VT_E64M2 = VType(0b001, 3, 1, 1); // e64, m2, ta, ma
static_assert(VT_E32M1 == 0xd0u && VT_E32M2 == 0xd1u && VT_E64M2 == 0xd9u,
	      "these are the vtype immediates the staged teacher guests actually carry");

// Four chained all-FP members. EVEN register numbers, because an EMUL = 2 group base must be
// EMUL-aligned (rv32_vector.h, reg_group_legal) -- and that alignment is exactly what makes the run
// substrate's base-register keying exact, so the test uses it rather than working around it.
std::vector<u32> FpMembers()
{
	return {Vv(F6_VFADD, /*vs2=*/18, /*vs1=*/20, /*vd=*/16),
		Vv(F6_VFMUL, /*vs2=*/16, /*vs1=*/20, /*vd=*/22),
		Vv(F6_VFSUB, /*vs2=*/22, /*vs1=*/16, /*vd=*/24),
		Vv(F6_VFDIV, /*vs2=*/24, /*vs1=*/22, /*vd=*/26)};
}

// The three architecturally legal operand overlaps a run can contain, plus the fused form whose vd
// is a source in its own right.
std::vector<u32> OverlapMembers()
{
	return {Vv(F6_VFADD, /*vs2=*/18, /*vs1=*/20, /*vd=*/16),   // plain
		Vv(F6_VFSUB, /*vs2=*/16, /*vs1=*/18, /*vd=*/16),   // vd == vs2
		Vv(F6_VFSGNJN, /*vs2=*/16, /*vs1=*/16, /*vd=*/16), // vd == vs1 == vs2
		Vv(F6_VFMACC, /*vs2=*/18, /*vs1=*/16, /*vd=*/22)}; // reads its old vd
}

// Three members touching nine distinct register groups, so the member-major admission bound
// (touched + 1) * k is what decides how many of them fit.
std::vector<u32> PressureMembers()
{
	return {Vv(F6_VFADD, /*vs2=*/10, /*vs1=*/12, /*vd=*/8),
		Vv(F6_VFADD, /*vs2=*/16, /*vs1=*/18, /*vd=*/14),
		Vv(F6_VFADD, /*vs2=*/22, /*vs1=*/24, /*vd=*/20)};
}

std::vector<u32> WithSetvl(u32 vtype, std::vector<u32> const &members)
{
	std::vector<u32> out{Vsetvli(vtype)};
	out.insert(out.end(), members.begin(), members.end());
	return out;
}

// ---------------------------------------------------------------------------------------------
// Harness. One fixed code buffer: QEmit embeds absolute addresses, so two arms allocated at two
// addresses differ in immediates for a reason unrelated to the arm under test. Same reason, same
// fix, as the accepted component-separable and grouped suites record.
// ---------------------------------------------------------------------------------------------
alignas(64) u8 g_code_buf[1u << 21];

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint) override
	{
		if (sz > sizeof(g_code_buf))
			Panic("test code buffer too small");
		return g_code_buf;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
};

struct Env {
	u32 vlen_bits = 1024;
	bool grouped = false;
	bool run_bound = false;
};

// Every switch this file's result can depend on is set on EVERY call, so no section inherits a
// value another one left in the process globals.
void ApplyEnv(Env const &e)
{
	config::vlen_bits = e.vlen_bits;
	config::rvv_vector_run = true;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_live_range_split = false;
	config::rvv_run_component_separable = false;
	config::rvv_run_component_demand_placement = false;
	config::rvv_run_scalar_passthrough = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_run_dep_probe_cross = false;
	config::rvv_run_split_value_weighted = false;
	config::rvv_run_frame_census = false;
	config::rvv_run_grouped_component_major = e.grouped;
	config::rvv_qcg_active_vl_run_bound = e.run_bound;
	config::rvv_qcg_active_vl_bound_placebo = false;
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_qcg_active_vl_int_bound = false;
	config::rvv_qcg_active_vl_widen_bound = false;
	config::rvv_qcg_active_vl_narrow_bound = true;
	config::rvv_qcg_active_chunk_census = false;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_lowering = 1;
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	config::rvv_qcg_typed_chunk_fma = true;
	config::rvv_qcg_typed_chunk_fma_force_emit = true;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_sub = true;
	config::rvv_qcg_typed_chunk_mul = true;
	config::rvv_qcg_typed_chunk_xor = true;
	config::rvv_qcg_typed_chunk_or = true;
	config::rvv_qcg_typed_chunk_and = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_sub_force_emit = true;
	config::rvv_qcg_typed_chunk_mul_force_emit = true;
	config::rvv_qcg_typed_chunk_xor_force_emit = true;
	config::rvv_qcg_typed_chunk_or_force_emit = true;
	config::rvv_qcg_typed_chunk_and_force_emit = true;
	config::rvv_qcg_fp_shared_mask = true;
	config::rvv_qcg_full_vl_fast_body = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
}

struct Built {
	MemArena arena{1u << 22};
	std::vector<u32> words;
	Region *region = nullptr;
	TestCompilerRuntime cr;
	std::vector<u8> code;
};

void Translate(Built &b, std::vector<u32> const &words, Env const &e)
{
	ApplyEnv(e);
	b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
}

void Emit(Built &b)
{
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.cr, &segment, b.region, 0);
	b.code.assign(span.begin(), span.end());
	while (!b.code.empty() && b.code.back() == 0)
		b.code.pop_back();
}

// The descriptor path, exactly as rvv_vector_run_admission_test asks for one: the words ARE the
// guest memory image and the observed vtype is given rather than decoded, so a descriptor-level
// section tests the scan and nothing else.
rvvrun::RunDescriptor Admit(std::vector<u32> &members, u32 vtype, Env const &e)
{
	ApplyEnv(e);
	return qir::rv32::RV32Translator::RvvAdmitVectorRun((uptr)members.data(), 0u,
						       (u32)members.size() * 4u,
						       (u32)members.size(), vtype,
						       rvvrun::RunLimits{});
}

struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
	InstRVVTypedChunkEnd *end = nullptr;
	std::vector<Inst *> body;
};

std::vector<Frame> FindFrames(Region *region)
{
	std::vector<Frame> out;
	Frame cur;
	bool open = false;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
				cur = Frame{};
				cur.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
				break;
			case Op::_rvvtypedchunkend:
				if (open) {
					cur.end = static_cast<InstRVVTypedChunkEnd *>(&ins);
					out.push_back(cur);
					open = false;
				}
				break;
			default:
				if (open)
					cur.body.push_back(&ins);
				break;
			}
		}
	return out;
}

Frame const *Widest(std::vector<Frame> const &fs)
{
	Frame const *best = nullptr;
	for (auto const &f : fs)
		if (!best || f.begin->n_members > best->begin->n_members)
			best = &f;
	return best;
}

unsigned CountOpIn(Frame const &f, Op op)
{
	unsigned n = 0;
	for (auto *i : f.body)
		n += i->GetOpcode() == op;
	return n;
}

bool IsLaneOp(Inst *i)
{
	return i->GetOpcode() == Op::_vchunkfalu || i->GetOpcode() == Op::_vchunkfma;
}

u32 LaneChunk(Inst *i)
{
	return i->GetOpcode() == Op::_vchunkfalu ? static_cast<InstVChunkFALU *>(i)->chunk
						 : static_cast<InstVChunkFMA *>(i)->chunk;
}

// A node's identity for the "same body" comparison: the opcode plus whatever chunk/base/offset
// field the node type carries. Two bodies that agree on this sequence agree on every decision the
// bound arm could have taken differently.
std::string NodeKey(Inst *i)
{
	char buf[160];
	switch (i->GetOpcode()) {
	case Op::_vchunkmaskset: {
		auto *n = static_cast<InstVChunkMaskSet *>(i);
		snprintf(buf, sizeof(buf), "maskset c=%u lanes=%u", n->chunk, n->lanes);
		break;
	}
	case Op::_vchunkfalu: {
		auto *n = static_cast<InstVChunkFALU *>(i);
		snprintf(buf, sizeof(buf), "falu c=%u f6=%u k=%u", n->chunk, n->funct6, n->kmask);
		break;
	}
	case Op::_vchunkfma: {
		auto *n = static_cast<InstVChunkFMA *>(i);
		snprintf(buf, sizeof(buf), "fma c=%u f6=%u k=%u", n->chunk, n->funct6, n->kmask);
		break;
	}
	case Op::_vstatechunkload: {
		auto *n = static_cast<InstVStateChunkLoad *>(i);
		snprintf(buf, sizeof(buf), "load offs=%u", (unsigned)n->offs);
		break;
	}
	case Op::_vstatechunkstore: {
		auto *n = static_cast<InstVStateChunkStore *>(i);
		snprintf(buf, sizeof(buf), "store offs=%u", (unsigned)n->offs);
		break;
	}
	case Op::_vchunkactive: {
		auto *n = static_cast<InstVChunkActive *>(i);
		snprintf(buf, sizeof(buf), "BOUND c=%u base=%u", n->chunk, n->element_base);
		break;
	}
	default:
		snprintf(buf, sizeof(buf), "op=%d", (int)i->GetOpcode());
		break;
	}
	return std::string(buf);
}

std::vector<std::string> BodyKeys(Frame const &f, bool drop_bounds)
{
	std::vector<std::string> out;
	for (auto *i : f.body) {
		if (drop_bounds && i->GetOpcode() == Op::_vchunkactive)
			continue;
		out.push_back(NodeKey(i));
	}
	return out;
}

// The state offset component `c` of the group based at `base_reg` MUST name, derived HERE from the
// RVV 1.0 element-placement rule and NOT by calling rv32_vector.h's group_chunk_location. That is
// the whole point of the section that uses it: if the two ever disagree, the emitted frame is
// addressing the wrong architectural register.
//
//   element_base(c) = c * (chunk_bytes / sew)
//   group element e lives in register base + e / (reg_bytes / sew), at element e % (reg_bytes/sew)
u32 ExpectedStateOffs(u32 base_reg, u32 vlen_bits, u32 chunk_bytes, u32 sew, u32 c)
{
	u32 const vreg_base =
	    (u32)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vreg));
	u32 const reg_bytes = vlen_bits / 8u;
	u32 const elems_per_reg = reg_bytes / sew;
	u32 const element_base = c * (chunk_bytes / sew);
	u32 const reg = base_reg + element_base / elems_per_reg;
	u32 const elem_in_reg = element_base % elems_per_reg;
	return vreg_base + reg * dbt::rv32::VLEN_MAX_BYTES + elem_in_reg * sew;
}

u32 OffsReg(u32 offs)
{
	u32 const vreg_base =
	    (u32)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vreg));
	return (offs - vreg_base) / dbt::rv32::VLEN_MAX_BYTES;
}

u32 StateOffsOf(Inst *i)
{
	if (i->GetOpcode() == Op::_vstatechunkload)
		return static_cast<InstVStateChunkLoad *>(i)->offs;
	return static_cast<InstVStateChunkStore *>(i)->offs;
}

bool IsStateAccess(Inst *i)
{
	return i->GetOpcode() == Op::_vstatechunkload ||
	       i->GetOpcode() == Op::_vstatechunkstore;
}

// A Panic aborts, so every fail-closed contract runs in a child whose stderr is matched.
bool ChildSaysPanic(char const *needle, void (*body)())
{
	int fds[2];
	if (pipe(fds) != 0)
		return false;
	pid_t const pid = fork();
	if (pid == 0) {
		close(fds[0]);
		dup2(fds[1], 2);
		dup2(fds[1], 1);
		body();
		fflush(stdout);
		_exit(0);
	}
	close(fds[1]);
	std::string out;
	char buf[4096];
	for (ssize_t n; (n = read(fds[0], buf, sizeof(buf))) > 0;)
		out.append(buf, (size_t)n);
	close(fds[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	bool const died = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
	return died && out.find(needle) != std::string::npos;
}

// ---------------------------------------------------------------------------------------------
// Fact builders. `Facts` is a CONSISTENT fact set for the given EMUL, so every section below
// perturbs exactly one field away from something that passes.
// ---------------------------------------------------------------------------------------------
rvvrun::FrameSeparableFacts Facts(i8 lmul_log2, GA ga, u32 vlen_bits = 1024, u16 chunk_bytes = 64)
{
	u32 const reg_bytes = vlen_bits / 8u;
	u32 const regs = lmul_log2 > 0 ? (1u << (unsigned)lmul_log2) : 1u;
	u32 const k = chunk_bytes ? (reg_bytes / chunk_bytes) * regs : 0u;
	rvvrun::FrameSeparableFacts f{};
	f.chunk_bytes = chunk_bytes;
	f.nchunks = k > 255u ? (u8)255 : (u8)k;
	f.vlen_bits = vlen_bits;
	f.lmul_log2 = lmul_log2;
	f.has_mem = false;
	f.mem_base_mask = 0;
	f.n_scalar_members = 0;
	f.n_vector_members = 4;
	f.n_members = 4;
	f.partial_vl_ok = false;
	f.group_addressing = ga;
	return f;
}

// ---------------------------------------------------------------------------------------------
// [1] THE PREDICATE TRUTH TABLE.
// ---------------------------------------------------------------------------------------------
void Section1()
{
	printf("[1] predicate truth table: integral EMUL, and only with the caller's permission\n");
	struct Row {
		i8 lmul_log2;
		u32 vlen;
		u16 cb;
		GA ga;
		bool want;
		char const *why;
	};
	// The VLEN/chunk pair on each row is chosen so that `k` stays inside kMaxChunks, which is
	// what isolates the EMUL question from the array bound tested in [3].
	Row const rows[] = {
	    {-3, 1024, 64, GA::SingleRegister, false, "fractional EMUL 1/8"},
	    {-3, 1024, 64, GA::RegisterGroup, false, "fractional EMUL 1/8: permission does NOT license it"},
	    {-1, 1024, 64, GA::SingleRegister, false, "fractional EMUL 1/2"},
	    {-1, 1024, 64, GA::RegisterGroup, false, "fractional EMUL 1/2: permission does NOT license it"},
	    {0, 1024, 64, GA::SingleRegister, true, "EMUL 1, one register: the pre-C4k accepted shape"},
	    {0, 1024, 64, GA::RegisterGroup, true, "EMUL 1, group-addressing caller"},
	    {1, 1024, 64, GA::SingleRegister, false, "EMUL 2 WITHOUT the caller's permission"},
	    {1, 1024, 64, GA::RegisterGroup, true, "EMUL 2 WITH it (k = 4)"},
	    {1, 512, 64, GA::SingleRegister, false, "EMUL 2 at VLEN 512, no permission"},
	    {1, 512, 64, GA::RegisterGroup, true, "EMUL 2 at VLEN 512 (k = 2)"},
	    {2, 512, 64, GA::SingleRegister, false, "EMUL 4 without permission"},
	    {2, 512, 64, GA::RegisterGroup, true, "EMUL 4 with it (k = 4)"},
	    {3, 512, 64, GA::SingleRegister, false, "EMUL 8 without permission"},
	    {3, 512, 64, GA::RegisterGroup, true, "EMUL 8 with it (k = 8)"},
	    {4, 1024, 64, GA::RegisterGroup, false, "EMUL 16 is not a legal register group at all"},
	    {7, 1024, 64, GA::RegisterGroup, false, "EMUL 128 is not a legal register group at all"},
	};
	unsigned trues = 0, falses = 0;
	for (auto const &r : rows) {
		auto f = Facts(r.lmul_log2, r.ga, r.vlen, r.cb);
		// A row whose EMUL is not a legal group has no consistent geometry to build, so it is
		// given the EMUL = 1 geometry: the EMUL test must reject it before the geometry is
		// reached, which is exactly what such a row asserts.
		if (r.lmul_log2 > 3)
			f.nchunks = (u8)((r.vlen / 8u) / r.cb);
		bool const got = rvvrun::RvvRunFrameSeparable(f);
		CHECK_EQ(got, r.want);
		trues += got;
		falses += !got;
		printf("      lmul_log2=%2d vlen=%4u %-14s -> %-5s  %s\n", (int)r.lmul_log2, r.vlen,
		       r.ga == GA::RegisterGroup ? "RegisterGroup" : "SingleRegister",
		       got ? "true" : "false", r.why);
	}
	// NEGATIVE CONTROL for the table itself: a predicate stuck at one answer would satisfy every
	// row of a table that only ever expected that answer.
	CHECK(trues >= 6);
	CHECK(falses >= 8);
	printf("    %u accepting rows, %u refusing rows (a stuck predicate cannot produce both)\n",
	       trues, falses);
}

// ---------------------------------------------------------------------------------------------
// [2] THE PRE-C4k REFERENCE, EXHAUSTIVELY, AT EMUL = 1.
//
// The pre-C4k conjunction, transcribed from the source text it replaced. This is the SPECIFICATION
// the EMUL = 1 half of C4k must not move, so it is written out rather than referred to.
// ---------------------------------------------------------------------------------------------
bool PreC4kFrameSeparable(rvvrun::FrameSeparableFacts const &f)
{
	if (f.n_members == 0)
		return false;
	if (f.nchunks < 2)
		return false;
	if (f.lmul_log2 != 0)
		return false;
	if (f.chunk_bytes == 0 || (u32)f.chunk_bytes * (u32)f.nchunks != f.vlen_bits / 8u)
		return false;
	if (f.has_mem || f.mem_base_mask != 0)
		return false;
	if (f.n_scalar_members != 0 || f.n_vector_members != f.n_members)
		return false;
	if (f.partial_vl_ok)
		return false;
	return true;
}

void Section2()
{
	printf("[2] pre-C4k reference: identical answers on every EMUL = 1 fact point\n");
	u32 const vlens[] = {0, 64, 128, 256, 512, 1024, 2048, 4096};
	u16 const cbs[] = {0, 8, 16, 32, 64, 128};
	unsigned points = 0, accepted = 0, disagreements = 0;
	for (u32 vlen : vlens)
		for (u16 cb : cbs)
			for (u8 nch = 0; nch <= 9; ++nch)
				for (unsigned bits = 0; bits < 16; ++bits)
					for (GA ga : {GA::SingleRegister, GA::RegisterGroup}) {
						rvvrun::FrameSeparableFacts f{};
						f.nchunks = nch;
						f.chunk_bytes = cb;
						f.vlen_bits = vlen;
						f.lmul_log2 = 0;
						f.has_mem = (bits & 1) != 0;
						f.mem_base_mask = (bits & 2) ? 4u : 0u;
						f.n_scalar_members = (bits & 4) ? (u8)1 : (u8)0;
						f.n_vector_members = 4;
						f.n_members = 4;
						f.partial_vl_ok = (bits & 8) != 0;
						// BOTH permissions: at EMUL = 1 the permission must be
						// INERT, which is itself part of "nothing moved".
						f.group_addressing = ga;
						bool const now = rvvrun::RvvRunFrameSeparable(f);
						bool const before = PreC4kFrameSeparable(f);
						++points;
						accepted += now;
						if (now != before) {
							++disagreements;
							if (disagreements <= 5)
								fprintf(stderr,
									"  FAIL vlen=%u cb=%u k=%u "
									"bits=%u ga=%d: now=%d "
									"before=%d\n",
									vlen, (unsigned)cb,
									(unsigned)nch, bits, (int)ga,
									now, before);
						}
					}
	CHECK_EQ(disagreements, 0u);
	// NEGATIVE CONTROL: a grid the reference never accepts would make agreement vacuous.
	CHECK(accepted > 0);
	printf("    %u fact points, %u accepted by both, %u disagreements\n", points, accepted,
	       disagreements);
}

// ---------------------------------------------------------------------------------------------
// [3] THE TWO NEW GEOMETRY FACTS, ISOLATED.
// ---------------------------------------------------------------------------------------------
void Section3()
{
	printf("[3] straddle and coverage, each isolated by one field from an accepted fact set\n");

	// (b) STRADDLE. VLEN 128 gives 16-byte registers; EMUL 4 gives a 64-byte group. A shape whose
	// chunks COVER the group exactly but are wider than one register can only be rejected by the
	// straddle conjunct.
	{
		auto const ok = Facts(2, GA::RegisterGroup, /*vlen_bits=*/128, /*chunk_bytes=*/16);
		CHECK_EQ((unsigned)ok.nchunks, 4u);
		CHECK(rvvrun::RvvRunFrameSeparable(ok)); // the accepted neighbour
		// 32 * 2 == 64 == the group's bytes, k = 2 clears P1, and 32 > reg_bytes = 16.
		auto straddle = ok;
		straddle.chunk_bytes = 32;
		straddle.nchunks = 2;
		CHECK_EQ((u32)straddle.chunk_bytes * straddle.nchunks,
			 (straddle.vlen_bits / 8u) * 4u);
		CHECK(!rvvrun::RvvRunFrameSeparable(straddle));
		printf("      straddle: cb=32 k=2 covers the 64-byte group exactly, clears P1, and "
		       "is REFUSED (a 16-byte register cannot hold a 32-byte chunk)\n");
	}
	// (c) COVERAGE. Start from the accepted e32,m2-at-VLEN-1024 shape and move ONLY nchunks.
	{
		auto const ok = Facts(1, GA::RegisterGroup);
		CHECK_EQ((unsigned)ok.nchunks, 4u);
		CHECK(rvvrun::RvvRunFrameSeparable(ok));
		auto under = ok;
		under.nchunks = 2; // one register's worth: the pre-C4k equality, now WRONG
		CHECK(!rvvrun::RvvRunFrameSeparable(under));
		auto over = ok;
		over.nchunks = 8;
		CHECK(!rvvrun::RvvRunFrameSeparable(over));
		printf("      coverage: k=4 accepted; k=2 (ONE register, the pre-C4k equality) and "
		       "k=8 both REFUSED\n");
	}
	// The per-chunk array bound, which this predicate must not rest on its caller for.
	{
		auto const ok = Facts(3, GA::RegisterGroup, /*vlen_bits=*/512, /*chunk_bytes=*/64);
		CHECK_EQ((unsigned)ok.nchunks, 8u);
		CHECK(rvvrun::RvvRunFrameSeparable(ok));
		auto const past = Facts(3, GA::RegisterGroup, /*vlen_bits=*/1024, /*chunk_bytes=*/64);
		CHECK_EQ((unsigned)past.nchunks, 16u);
		CHECK(!rvvrun::RvvRunFrameSeparable(past));
		printf("      per-chunk arrays: k=8 accepted, k=16 REFUSED (kMaxChunks=%u)\n",
		       (unsigned)rvvrun::kMaxChunks);
	}
	// Zero and out-of-range inputs fail closed rather than divide, wrap or index.
	{
		auto const ok = Facts(1, GA::RegisterGroup);
		auto zero_cb = ok;
		zero_cb.chunk_bytes = 0;
		CHECK(!rvvrun::RvvRunFrameSeparable(zero_cb));
		auto zero_vlen = ok;
		zero_vlen.vlen_bits = 0;
		CHECK(!rvvrun::RvvRunFrameSeparable(zero_vlen));
		auto huge = ok;
		huge.vlen_bits = 0xffffffffu;
		CHECK(!rvvrun::RvvRunFrameSeparable(huge));
		auto huge2 = ok;
		huge2.vlen_bits = 1u << 20; // reg_bytes 131072: `reg_bytes * regs` must not be trusted
		CHECK(!rvvrun::RvvRunFrameSeparable(huge2));
		printf("      zero/out-of-range: chunk_bytes=0, vlen=0, vlen=2^32-1 and vlen=2^20 "
		       "all REFUSED\n");
	}
}

// ---------------------------------------------------------------------------------------------
// [4] THE COMPONENT-SEPARABLE PATH IS UNCHANGED.
// ---------------------------------------------------------------------------------------------
void Section4(rvvrun::RunDescriptor const &m2)
{
	printf("[4] RvvRunComponentSeparable keeps the refusing default\n");
	for (i8 l : {(i8)1, (i8)2, (i8)3}) {
		u32 const vlen = l >= 2 ? 512u : 1024u;
		CHECK(rvvrun::RvvRunFrameSeparable(Facts(l, GA::RegisterGroup, vlen)));
		CHECK(!rvvrun::RvvRunFrameSeparable(Facts(l, GA::SingleRegister, vlen)));
	}
	// A REAL descriptor the grouped predicate accepts must still be refused by the P7O-1 one.
	CHECK(!m2.Empty());
	CHECK_EQ((int)m2.lmul_log2, 1);
	CHECK_EQ((unsigned)m2.nchunks, 4u);
	CHECK(rvvrun::RvvRunGroupedComponentMajor(m2));
	CHECK(!rvvrun::RvvRunComponentSeparable(m2));
	// And the descriptor's own recorded bit -- FormRun sets it from RvvRunComponentSeparable --
	// is false, so no ADMISSION decision moved with it.
	CHECK(!m2.component_separable);
	printf("    e32,m2 descriptor (k=%u): grouped=%d, component_separable=%d (predicate) / %d "
	       "(recorded on the descriptor)\n",
	       (unsigned)m2.nchunks, (int)rvvrun::RvvRunGroupedComponentMajor(m2),
	       (int)rvvrun::RvvRunComponentSeparable(m2), (int)m2.component_separable);
}

// ---------------------------------------------------------------------------------------------
// [5] THE BODY IS COMPONENT-MAJOR AT EMUL = 2.
// ---------------------------------------------------------------------------------------------
void Section5(Frame const &f, u32 k)
{
	printf("[5] the e32,m2 body is component-major with k = %u slices\n", k);
	CHECK_EQ(CountOpIn(f, Op::_vchunkmaskset), k);
	int cur = -1;
	unsigned lane_ops = 0, loads = 0, stores = 0;
	std::vector<unsigned> order;
	for (auto *i : f.body) {
		if (i->GetOpcode() == Op::_vchunkmaskset) {
			cur = (int)static_cast<InstVChunkMaskSet *>(i)->chunk;
			order.push_back((unsigned)cur);
			continue;
		}
		if (IsLaneOp(i)) {
			CHECK_EQ((int)LaneChunk(i), cur);
			++lane_ops;
		}
		loads += i->GetOpcode() == Op::_vstatechunkload;
		stores += i->GetOpcode() == Op::_vstatechunkstore;
	}
	CHECK_EQ(order.size(), k);
	for (unsigned c = 0; c < order.size(); ++c)
		CHECK_EQ(order[c], c);
	CHECK_EQ(lane_ops, k * f.begin->n_members);
	// NEGATIVE CONTROL: a frame with no state traffic at all would satisfy the loop above
	// vacuously.
	CHECK(loads > 0);
	CHECK(stores > 0);
	printf("    slices ascending, %u lane ops, %u loads, %u stores, every one inside its own "
	       "slice\n",
	       lane_ops, loads, stores);
}

// ---------------------------------------------------------------------------------------------
// [6] B -> C IS STILL A SINGLE FACTOR AT EMUL = 2.
// ---------------------------------------------------------------------------------------------
void Section6(Frame const &b, Frame const &c, u32 k, u32 lanes)
{
	printf("[6] B -> C at e32,m2: the bodies differ by the bound nodes and by nothing else\n");
	auto const bk = BodyKeys(b, false);
	auto const ck_nobound = BodyKeys(c, true);
	CHECK_EQ(ck_nobound.size(), bk.size());
	CHECK_EQ(BodyKeys(c, false).size(), bk.size() + k);
	bool same = ck_nobound.size() == bk.size();
	for (size_t n = 0; same && n < bk.size(); ++n)
		if (bk[n] != ck_nobound[n]) {
			fprintf(stderr, "  FAIL body node %zu: B '%s' vs C '%s'\n", n, bk[n].c_str(),
				ck_nobound[n].c_str());
			same = false;
		}
	CHECK(same);
	unsigned nbounds = 0;
	for (size_t n = 0; n < c.body.size(); ++n) {
		if (c.body[n]->GetOpcode() != Op::_vchunkactive)
			continue;
		auto *a = static_cast<InstVChunkActive *>(c.body[n]);
		CHECK_EQ(a->chunk, nbounds);
		CHECK_EQ(a->element_base, nbounds * lanes);
		// Each bound opens its own slice: the very next node is that slice's mask node.
		CHECK(n + 1 < c.body.size());
		if (n + 1 < c.body.size()) {
			CHECK(c.body[n + 1]->GetOpcode() == Op::_vchunkmaskset);
			if (c.body[n + 1]->GetOpcode() == Op::_vchunkmaskset)
				CHECK_EQ(static_cast<InstVChunkMaskSet *>(c.body[n + 1])->chunk,
					 a->chunk);
		}
		++nbounds;
	}
	CHECK_EQ(nbounds, k);
	printf("    B body=%zu nodes, C body=%zu nodes (+%u bounds), element bases 0..%u step %u\n",
	       bk.size(), BodyKeys(c, false).size(), k, (k - 1) * lanes, lanes);
}

// ---------------------------------------------------------------------------------------------
// [7] CROSS-REGISTER COMPONENT DATAFLOW.
// ---------------------------------------------------------------------------------------------
void Section7(Frame const &f, u32 k, u32 vlen_bits, u32 chunk_bytes, u32 sew)
{
	u32 const per_reg = (vlen_bits / 8u) / chunk_bytes;
	printf("[7] cross-register dataflow: components %u.. live in the group's SECOND register\n",
	       per_reg);
	CHECK(per_reg >= 1);
	// If k did not exceed the per-register chunk count this section would test nothing.
	CHECK(k > per_reg);

	// For each component, the set of BASE REGISTERS its state offsets imply under the
	// independently derived element rule. Those sets must be identical across components: a body
	// that tiled one register, or that crossed at the wrong component, would produce different
	// ones.
	std::vector<std::set<unsigned>> bases_per_c(k);
	std::set<unsigned> regs_named;
	int cur = -1;
	unsigned checked = 0;
	for (auto *i : f.body) {
		if (i->GetOpcode() == Op::_vchunkmaskset) {
			cur = (int)static_cast<InstVChunkMaskSet *>(i)->chunk;
			continue;
		}
		if (!IsStateAccess(i))
			continue;
		CHECK(cur >= 0 && (u32)cur < k);
		if (cur < 0 || (u32)cur >= (int)k)
			continue;
		u32 const offs = StateOffsOf(i);
		bool matched = false;
		for (u32 base = 0; base < dbt::rv32::VREG_NUM; ++base)
			if (ExpectedStateOffs(base, vlen_bits, chunk_bytes, sew, (u32)cur) == offs) {
				bases_per_c[(u32)cur].insert(base);
				matched = true;
				break;
			}
		CHECK(matched);
		regs_named.insert(OffsReg(offs));
		++checked;
	}
	CHECK(checked > 0);
	for (u32 c = 1; c < k; ++c)
		CHECK(bases_per_c[c] == bases_per_c[0]);
	CHECK(!bases_per_c[0].empty());
	// The group's SECOND architectural register must actually be named: an implementation that
	// tiled only one register would never produce those offsets.
	CHECK(regs_named.size() >= 2);
	printf("    %u state accesses, all at element-derived offsets; %zu base register group(s), "
	       "%zu distinct architectural registers named\n",
	       checked, bases_per_c[0].size(), regs_named.size());

	// The dataflow itself: member i's component-c source is the value member i-1 published for
	// the SAME component.
	unsigned edges = 0;
	for (u32 c = 0; c < k; ++c) {
		std::vector<Inst *> lane;
		int slice = -1;
		for (auto *i : f.body) {
			if (i->GetOpcode() == Op::_vchunkmaskset)
				slice = (int)static_cast<InstVChunkMaskSet *>(i)->chunk;
			if (IsLaneOp(i) && slice == (int)c)
				lane.push_back(i);
		}
		CHECK_EQ(lane.size(), f.begin->n_members);
		for (size_t n = 1; n < lane.size(); ++n) {
			VOperand const def = lane[n - 1]->o(0);
			bool used = false;
			for (u8 s = 0; s < 2; ++s) {
				VOperand const src = lane[n]->i(s);
				used = used || (src.IsVVPR() && def.IsVVPR() &&
						src.GetVVPR() == def.GetVVPR());
			}
			CHECK(used);
			edges += used;
		}
	}
	CHECK_EQ(edges, k * (f.begin->n_members - 1));
	printf("    %u member-to-member component edges, every one inside its own component\n",
	       edges);
}

// ---------------------------------------------------------------------------------------------
// [8] OVERLAP AND THE FUSED OLD vd AT EMUL = 2.
// ---------------------------------------------------------------------------------------------
void Section8(u32 vlen_bits, u32 k)
{
	printf("[8] operand overlap and the fused old vd, at e32,m2\n");
	Built b;
	// Not emitted, for the reason main() records: the allocator would rewrite the very operands
	// this section compares.
	Translate(b, WithSetvl(VT_E32M2, OverlapMembers()), Env{vlen_bits, true, false});
	auto const frames = FindFrames(b.region);
	auto const *f = Widest(frames);
	CHECK(f != nullptr);
	if (!f)
		return;
	CHECK_EQ(f->begin->n_members, 4u);
	CHECK(f->begin->body_component_major);
	// The fused member is present -- one per component -- which is what makes vd a SOURCE.
	CHECK_EQ(CountOpIn(*f, Op::_vchunkfma), k);
	// Per component: a member's destination value must be DIFFERENT from each of its own source
	// values. That is the SSA statement of "all sources are bound before the destination is
	// published": with vd == vs1 == vs2 all naming v16, a body that published first would make
	// the destination its own operand.
	int slice = -1;
	unsigned checked = 0;
	for (auto *i : f->body) {
		if (i->GetOpcode() == Op::_vchunkmaskset)
			slice = (int)static_cast<InstVChunkMaskSet *>(i)->chunk;
		if (!IsLaneOp(i))
			continue;
		CHECK_EQ((int)LaneChunk(i), slice);
		VOperand const d = i->o(0);
		for (u8 s = 0; s < 2; ++s) {
			VOperand const src = i->i(s);
			if (d.IsVVPR() && src.IsVVPR())
				CHECK(d.GetVVPR() != src.GetVVPR());
		}
		++checked;
	}
	CHECK_EQ(checked, k * 4u);
	printf("    %u lane ops (vd==vs2, vd==vs1==vs2 and a fused vd among them); no destination "
	       "is its own operand\n",
	       checked);
}

// ---------------------------------------------------------------------------------------------
// [9] REGISTER PRESSURE IS STILL FAIL-CLOSED, AND STILL SCALES WITH k.
// ---------------------------------------------------------------------------------------------
void Section9()
{
	printf("[9] the member-major admission bound is untouched and still scales with k\n");
	struct Case {
		u32 vtype;
		char const *name;
		u32 k;
		u32 want_members;
	};
	// (touched + 1) * k <= kHostVectorRegs = 30, evaluated as each member is offered:
	//   e32,m1 @ VLEN 1024: k = 2 -> three members touch 9 groups, (9+1)*2 = 20, all fit
	//   e32,m2 @ VLEN 1024: k = 4 -> the third would make it (9+1)*4 = 40, so it is cut
	Case const cases[] = {{VT_E32M1, "e32,m1", 2, 3}, {VT_E32M2, "e32,m2", 4, 2}};
	bool saw_cut = false, saw_full = false;
	for (auto const &c : cases) {
		auto words = PressureMembers();
		auto const d = Admit(words, c.vtype, Env{1024, true, true});
		CHECK_EQ((unsigned)d.nchunks, c.k);
		CHECK_EQ((unsigned)d.n_members, c.want_members);
		if (c.want_members < words.size()) {
			CHECK(d.cut == CutReason::RegisterPressure);
			saw_cut = true;
		} else {
			saw_full = true;
		}
		printf("      %s k=%u: %u member(s) admitted, cut=%s\n", c.name, (unsigned)d.nchunks,
		       (unsigned)d.n_members, rvvrun::CutReasonName(d.cut));
	}
	// NEGATIVE CONTROL: both outcomes must occur, or the bound is not being exercised.
	CHECK(saw_cut);
	CHECK(saw_full);
}

// ---------------------------------------------------------------------------------------------
// [10] GENERAL ADMISSION IS UNCHANGED BY THE GROUPED SWITCH.
// ---------------------------------------------------------------------------------------------
void Section10()
{
	printf("[10] the grouped switch is emission-side: RVV_RUN counters identical in both arms\n");
	for (u32 vtype : {VT_E32M1, VT_E32M2, VT_E64M2}) {
		rvvrun::Stats off{}, on{};
		for (int arm = 0; arm < 2; ++arm) {
			rvvrun::g_stats = rvvrun::Stats{};
			Built b;
			Translate(b, WithSetvl(vtype, FpMembers()), Env{1024, arm != 0, arm != 0});
			Emit(b);
			(arm ? on : off) = rvvrun::g_stats;
		}
		CHECK_EQ(off.scans, on.scans);
		CHECK_EQ(off.runs_formed, on.runs_formed);
		CHECK_EQ(off.multi_member_runs, on.multi_member_runs);
		CHECK_EQ(off.members_admitted, on.members_admitted);
		bool cuts_same = true;
		for (unsigned i = 0; i < rvvrun::kCutReasonCount; ++i)
			cuts_same = cuts_same && off.cuts[i] == on.cuts[i];
		CHECK(cuts_same);
		// NEGATIVE CONTROL: comparing two empty counter sets would prove nothing.
		CHECK(on.multi_member_runs > 0);
		CHECK(on.members_admitted >= 4);
		printf("      vtype 0x%02x: scans=%llu runs=%llu multi=%llu members=%llu, identical\n",
		       vtype, (unsigned long long)on.scans, (unsigned long long)on.runs_formed,
		       (unsigned long long)on.multi_member_runs,
		       (unsigned long long)on.members_admitted);
	}
	rvvrun::g_stats = rvvrun::Stats{};
}

// ---------------------------------------------------------------------------------------------
// [11] FAIL-CLOSED CONTRACTS, IN CHILD PROCESSES, AT EMUL = 2.
// ---------------------------------------------------------------------------------------------
void Section11()
{
	printf("[11] fail-closed contracts at e32,m2, in child processes\n");

	// CONTROL FIRST. The unmutated e32,m2 grouped + bound frame must NOT abort, so a build that
	// Panicked on everything could not pass this section.
	bool const clean = !ChildSaysPanic("Panic", [] {
		Built b;
		Translate(b, WithSetvl(VT_E32M2, FpMembers()), Env{1024, true, true});
		Emit(b);
	});
	CHECK(clean);
	printf("      C1 e32,m2 grouped run, bound on                          clean\n");

	// M1. THE BOUND IS LICENSED BY THE COMPONENT-MAJOR CLAIM AND BY NOTHING ELSE. Clearing the
	// claim on the begin node leaves four `vchunkactive` nodes inside a four-member frame that no
	// longer says its body is component-major, which is exactly the shape QEmit refuses. Without
	// this, an EMUL = 2 frame could carry a bound on a member-major body -- wrong values, not a
	// translation failure.
	bool const m1 = ChildSaysPanic("member-major multi-member run frame", [] {
		Built b;
		Translate(b, WithSetvl(VT_E32M2, FpMembers()), Env{1024, true, true});
		for (auto &bb : b.region->GetBlocks())
			for (auto &ins : bb.ilist)
				if (ins.GetOpcode() == Op::_rvvtypedchunkbegin)
					static_cast<InstRVVTypedChunkBegin *>(&ins)
					    ->body_component_major = false;
		Emit(b);
	});
	CHECK(m1);
	printf("      M1 the component-major claim cleared, bounds left in place  refused\n");

	// M2. THE n_typed SHAPE CONTRACT IS LIVE AT k = 4. The guard-miss arm branches over exactly
	// the declared number of typed body ops, so a frame whose declaration and body disagree must
	// abort rather than emit a branch over the wrong bytes. One field, one direction.
	bool const m2 = ChildSaysPanic("is not the shape begin declared", [] {
		Built b;
		Translate(b, WithSetvl(VT_E32M2, FpMembers()), Env{1024, true, true});
		for (auto &bb : b.region->GetBlocks())
			for (auto &ins : bb.ilist)
				if (ins.GetOpcode() == Op::_rvvtypedchunkbegin)
					static_cast<InstRVVTypedChunkBegin *>(&ins)->n_typed += 1;
		Emit(b);
	});
	CHECK(m2);
	printf("      M2 n_typed declared one too high                           refused\n");
}

} // namespace

int main()
{
	printf("C4k: integral LMUL register groups in the grouped component-major predicate\n");

	Section1();
	Section2();
	Section3();

	u32 const vlen = 1024, sew = 4, chunk_bytes = 64;

	// The descriptor every scan-level section reads, formed the way the translator forms one.
	{
		auto words = FpMembers();
		auto const d = Admit(words, VT_E32M2, Env{vlen, true, true});
		Section4(d);
	}

	// The two emitted e32,m2 arms every body-level section reads.
	//
	// DELIBERATELY NOT EMITTED. `qcg::GenerateCode` runs the register allocator, which REWRITES
	// every VOperand from a virtual VPR to a physical one; the def-use identities sections [7]
	// and [8] read would be gone. The bound nodes and the component-major claim are inserted at
	// TRANSLATION time (rvvfinal::CloseFrame), so nothing these sections examine needs emission.
	// The emitted-code contracts are section [11]'s, and it emits in its own child processes.
	Built bb_arm, bc_arm;
	Translate(bb_arm, WithSetvl(VT_E32M2, FpMembers()), Env{vlen, true, false});
	Translate(bc_arm, WithSetvl(VT_E32M2, FpMembers()), Env{vlen, true, true});
	auto const b_frames = FindFrames(bb_arm.region);
	auto const c_frames = FindFrames(bc_arm.region);
	auto const *bf = Widest(b_frames);
	auto const *cf = Widest(c_frames);
	CHECK(bf != nullptr);
	CHECK(cf != nullptr);
	u32 k = 0;
	if (bf && cf) {
		CHECK(bf->begin->body_component_major);
		CHECK(cf->begin->body_component_major);
		CHECK_EQ(bf->begin->n_members, 4u);
		k = CountOpIn(*bf, Op::_vchunkmaskset);
		CHECK_EQ(k, 4u); // e32,m2 at VLEN 1024: two registers x two 64-byte chunks
		u32 const lanes = chunk_bytes / sew;
		Section5(*cf, k);
		Section6(*bf, *cf, k, lanes);
		Section7(*bf, k, vlen, chunk_bytes, sew);
	}

	if (k)
		Section8(vlen, k);
	Section9();
	Section10();
	Section11();

	if (g_failures)
		printf("FAILURES: %d\n", g_failures);
	else
		printf("OK\n");
	return g_failures != 0;
}
