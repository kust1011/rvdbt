// P7M-A: the cross-operation, component-resident VECTOR RUN generalized to the accepted FP lane
// routes -- implementation, correctness and structure.
//
// WHAT THIS FILE HAS TO PROVE, AND WHY EACH SECTION EXISTS.
//
// The pre-P7M-A run substrate admitted six integer `.vv` routes. Generalizing it to FP is not
// "two more rows": an FP member brings host FP control state, a second register file, a
// read-before-write destination and a different guard predicate into a frame that had none of
// them. Each of the sections below exists because one of those could be got wrong in a way that
// still produces a plausible-looking frame.
//
//   [1] MEMBERSHIP IS THE ROUTE'S OWN ADMISSION, NOT A LIST. The entire OP-V encoding space
//       (funct6 x funct3 x vm = 1024 words) is swept at e64,m1 and e32,m1. A word is admitted as
//       a run member IF AND ONLY IF the same word, translated ALONE with the run switch off,
//       produces a direct typed frame. The oracle is the single-instruction route itself, so a
//       run cannot admit a shape that route would have refused and cannot refuse one it takes.
//       No guest PC, no workload and no opcode constant participates in the rule.
//
//   [2] A RUN FORMS OVER CONSECUTIVE FP OPS AND THE CHUNKS STAY IN COMPONENT SSA. The real
//       miniWeather chain shapes (P7L-A section 3) are translated: the depth-2 `vfsub.vv ->
//       vfdiv.vf`, the depth-3 `vfadd.vf -> vfdiv.vv -> vfsub.vf`, and the fused `vfdiv.vf ->
//       vfnmsub.vf`. The frame's CPUState traffic must be EXACTLY the live-in loads and the
//       final live-out stores -- zero round-trips in the body -- and the low/high chunks must
//       stay k disjoint components across the operation boundary. Components are computed by
//       union-find over QIR value identity, not read off register numbers.
//
//   [3] OPERAND ORDER AND ALIASING. `vfsub`/`vfdiv` are non-commutative and the fused node's
//       three inputs have distinct roles, so the exact input operand of every lane node is
//       pinned to the exact producing value. Legal overlaps -- vd==vs2 for the fused form,
//       vd==vs1 for `.vv` -- are checked to read the PRE-instruction component.
//
//   [4] THE `.vf` SCALAR IS A FRAME LIVE-IN, ONCE. One broadcast per DISTINCT F register for the
//       whole frame, and an F register number never appears in the VECTOR live-in/touched masks.
//
//   [5] THE FP BRACKET IS FRAME-SCOPE. Exactly one `rvvqcgfpbegin`/`rvvqcgfpend` pair per frame
//       whatever the member count, both inside the guarded window, and none at all when no
//       member is FP.
//
//   [6] THE GUARD IS THE CONJUNCTION OF THE MEMBERS' REQUIREMENTS. Integer-only -> VTypeVlVstart
//       with no frm test; FP-only -> VTypePartialVlVstartFrmRNE; MIXED -> VTypeVlVstartFrmRNE,
//       i.e. full VL and frm==RNE. Checked in the node AND in the real disassembly.
//
//   [7] EVERY EXISTING REJECTION STILL REJECTS. Route switches off, --rvv-verify, the LLVM
//       backend, an unobserved vtype, masked encodings, VLEN 256, SEW 8/16, LMUL 2, and the four
//       cut classes (vset, vector memory, scalar, control flow) between two FP members.
//
//   [8] THE TWO BODY MODES AGREE ON THE RUN AND DIFFER ONLY IN THE BODY. Same descriptor, same
//       guard, same bracket, same member PCs; the materialize arm's body is the
//       single-instruction routes' own body, member by member.
//
//   [9] DEFAULT-OFF IS BYTE-IDENTICAL. With `--rvv-vector-run` off nothing changes; with it on,
//       a sequence in which no two-member run can be admitted is still byte-identical, and one
//       in which a run IS admitted is not. Both directions, because a flag that leaks and a
//       flag that stops working are different bugs.
//
//  [10] THE DECLARED TYPED-OP COUNT IS THE REAL ONE, and the pressure bound covers the two new
//       terms. `Emit_rvvtypedchunkend` Panics on a mismatch, so a successful emission is itself
//       part of the check; the counts are also asserted directly.
//
// SCOPE. Structure and translation only. Nothing here EXECUTES emitted code and nothing here is
// timed: the hardware semantics of these FP forms are P7J-A's and P7K-C1's xbd differentials, and
// the application route accounting is P7K-C2's. Like the other route tests this one bypasses the
// AVX-512F/FMA3/BMI2 admission probes with the audit force-emit switches, because it never runs
// what it emits.
//
// INSTRUCTION WORDS. Every word is built by the field encoders below and the encoders are pinned
// by static_assert against the words P7J-B's `--rvv-pc-census` recorded in miniWeather, which are
// the same constants vfalu_residual_e64_route_test.cpp and vfma_typedchunk_route_test.cpp already
// carry. Nothing here is hand-transcribed hex.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
// `using namespace dbt::qir` above makes a bare `rv32::` ambiguous (dbt::rv32 vs
// dbt::qir::rv32), so the guest namespace gets the alias the translator itself uses.
namespace rvg = dbt::rv32;
namespace rvvrun = dbt::rv32::rvvrun;
using rvvrun::CutReason;
using rvvrun::RunOp;
using GuardKind = InstRVVTypedChunkBegin::GuardKind;

namespace
{

int g_failures = 0;

#define CHECK(cond)                                                                                          \
	do {                                                                                                 \
		if (!(cond)) {                                                                               \
			fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                    \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

#define CHECK_EQ(a, b)                                                                                       \
	do {                                                                                                 \
		auto _a = (a);                                                                               \
		auto _b = (b);                                                                               \
		if (!(_a == _b)) {                                                                           \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,    \
				#b, (long long)_a, (long long)_b);                                           \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

// ---------------------------------------------------------------------------------------------
// [0] Pins. These fail to COMPILE rather than to run.
// ---------------------------------------------------------------------------------------------
static_assert(rvvrun::kHostVectorRegs == qcg::ArchTraits::VPR_POOL.count(),
	      "rvvrun::kHostVectorRegs must equal the QCG allocator's V512 pool size");
// The FP-scalar live-in mask is a u32 over the RV32 F register file.
static_assert(sizeof(rvg::FPUState::f) / sizeof(rvg::FPUState::f[0]) == 32,
	      "f_live_in_mask is a u32 mask over the 32 scalar F registers");

// ---------------------------------------------------------------------------------------------
// Encoders and words.
// ---------------------------------------------------------------------------------------------
constexpr u32 VSETVLI_E64M1 = 0x0d857557u; // vsetvli a0,a0,e64,m1,ta,ma
constexpr u32 VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0,a0,e32,m1,ta,ma
constexpr u32 VSETVLI_E64M2 = 0x0d957557u; // vsetvli a0,a0,e64,m2,ta,ma
constexpr u32 VSETVLI_E16M1 = 0x0c857557u; // vsetvli a0,a0,e16,m1,ta,ma

constexpr u32 MakeOpV(u32 f6, u32 vm, u32 vs2, u32 src1, u32 vd, u32 funct3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (src1 << 15) | (funct3 << 12) | (vd << 7) |
	       0x57u;
}
constexpr u32 Vv(u32 f6, u32 vs2, u32 vs1, u32 vd) { return MakeOpV(f6, 1, vs2, vs1, vd, 0b001u); }
constexpr u32 Vf(u32 f6, u32 vs2, u32 rs1, u32 vd) { return MakeOpV(f6, 1, vs2, rs1, vd, 0b101u); }
constexpr u32 Iv(u32 f6, u32 vs2, u32 vs1, u32 vd) { return MakeOpV(f6, 1, vs2, vs1, vd, 0b000u); }

// funct6 values, from dbt/guest/rv32_vector_lower.h.
constexpr u32 F6_VFADD = 0b000000u, F6_VFSUB = 0b000010u, F6_VFMUL = 0b100100u;
constexpr u32 F6_VFDIV = 0b100000u, F6_VFRDIV = 0b100001u;
constexpr u32 F6_VFMADD = 0b101000u, F6_VFNMSUB = 0b101011u;
constexpr u32 F6_VADD = 0b000000u, F6_VSUB = 0b000010u;

// THE ENCODER IS PINNED AGAINST THE MEASURED WORDS. These six constants are the raw values
// P7J-B's per-PC census recorded in miniWeather's `output()` loop and P7D's `compute_tendencies`
// stations; they also appear verbatim in vfalu_residual_e64_route_test.cpp and
// vfma_typedchunk_route_test.cpp. A mistyped field order below fails to compile.
static_assert(Vf(F6_VFADD, 8, 15, 8) == 0x0287d457u, "vfadd.vf v8,v8,fa5");
static_assert(Vf(F6_VFSUB, 8, 13, 8) == 0x0a86d457u, "vfsub.vf v8,v8,fa3");
static_assert(Vv(F6_VFDIV, 9, 8, 9) == 0x829414d7u, "vfdiv.vv v9,v9,v8");
static_assert(Vf(F6_VFMADD, 8, 8, 9) == 0xa28454d7u, "vfmadd.vf v9,fs0,v8");
static_assert(Vf(F6_VFNMSUB, 8, 13, 9) == 0xae86d4d7u, "vfnmsub.vf v9,fa3,v8");
static_assert(Iv(F6_VADD, 1, 2, 3) == 0x021101d7u, "vadd.vv v3,v1,v2");

// miniWeather's measured cross-operation chains (P7L-A section 3). Register numbers are the
// measured ones; nothing in the substrate reads them.
constexpr u32 MW_VFSUB_VV = Vv(F6_VFSUB, /*vs2=*/9, /*vs1=*/8, /*vd=*/8);  // compute_tendencies_x
constexpr u32 MW_VFDIV_VF = Vf(F6_VFDIV, /*vs2=*/8, /*rs1=*/15, /*vd=*/8); // ... -> vfdiv.vf
constexpr u32 MW_VFNMSUB_VF = Vf(F6_VFNMSUB, /*vs2=*/8, /*rs1=*/13, /*vd=*/9);
constexpr u32 MW_VFADD_VF = Vf(F6_VFADD, /*vs2=*/8, /*rs1=*/15, /*vd=*/8); // output() depth-3
constexpr u32 MW_VFDIV_VV = Vv(F6_VFDIV, /*vs2=*/8, /*vs1=*/9, /*vd=*/8);
constexpr u32 MW_VFSUB_VF = Vf(F6_VFSUB, /*vs2=*/8, /*rs1=*/13, /*vd=*/8);
constexpr u32 MW_VFMADD_VF = Vf(F6_VFMADD, /*vs2=*/8, /*rs1=*/8, /*vd=*/9);

// Aliasing shapes.
constexpr u32 VFMADD_ALIAS = Vf(F6_VFMADD, /*vs2=*/9, /*rs1=*/8, /*vd=*/9); // fused vd == vs2
constexpr u32 VFSUB_VV_ALIAS_S1 = Vv(F6_VFSUB, /*vs2=*/7, /*vs1=*/8, /*vd=*/8); // vd == vs1
// Two `.vf` members reading DIFFERENT F registers, and two reading the same one.
constexpr u32 VFMUL_VF_F9 = Vf(F6_VFMUL, /*vs2=*/8, /*rs1=*/9, /*vd=*/8);
constexpr u32 VFDIV_VF_F9 = Vf(F6_VFDIV, /*vs2=*/8, /*rs1=*/9, /*vd=*/8);
// Barriers.
constexpr u32 W_VSETVL = 0x80b57557u;	// vsetvl  a0,a0,a1
constexpr u32 W_VLE64 = 0x02057407u;	// vle64.v v8,(a0)
constexpr u32 W_ADDI = 0x00150513u;	// addi    a0,a0,1
constexpr u32 W_BEQ = 0x00050463u;	// beq     a0,zero,+8
constexpr u32 VFADD_VV_MASKED = MakeOpV(F6_VFADD, 0, 8, 9, 8, 0b001u);
constexpr u32 VFADD_VV_E32 = Vv(F6_VFADD, /*vs2=*/8, /*vs1=*/9, /*vd=*/8);
constexpr u32 VADD_VV_E32 = Iv(F6_VADD, /*vs2=*/1, /*vs1=*/2, /*vd=*/8);

// ---------------------------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------------------------
struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override
	{
		return nullptr;
	}
	std::vector<u8> buf;
};

struct Env {
	u32 vlen_bits = 512;
	bool vector_run = true;
	bool materialize = false;
	bool chunk_major = false;
	bool falu = true;
	bool fma = true;
	bool int_routes = true;
	bool rvv_direct = true;
	bool rvv_verify = false;
	bool aot_use_llvm = false;
	bool force_emit = true;
	// F1 guard (2026-09-23): --rvv-run-fp-store-masked-partial-vl, production default on.
	bool fp_store_masked_partial_vl = true;
};

void ApplyEnv(Env const &e)
{
	config::vlen_bits = e.vlen_bits;
	config::rvv_vector_run = e.vector_run;
	config::rvv_run_fp_store_masked_partial_vl = e.fp_store_masked_partial_vl;
	config::rvv_run_body_materialize = e.materialize;
	config::rvv_run_order_chunk_major = e.chunk_major;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_run_dep_probe_cross = false;
	config::rvv_direct = e.rvv_direct;
	config::rvv_verify = e.rvv_verify;
	config::aot_use_llvm = e.aot_use_llvm;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_qcg_typed_chunk_falu = e.falu;
	config::rvv_qcg_typed_chunk_falu_force_emit = e.falu && e.force_emit;
	config::rvv_qcg_typed_chunk_fma = e.fma;
	config::rvv_qcg_typed_chunk_fma_force_emit = e.fma && e.force_emit;
	config::rvv_qcg_typed_chunk = e.int_routes;
	config::rvv_qcg_typed_chunk_sub = e.int_routes;
	config::rvv_qcg_typed_chunk_mul = e.int_routes;
	config::rvv_qcg_typed_chunk_xor = e.int_routes;
	config::rvv_qcg_typed_chunk_or = e.int_routes;
	config::rvv_qcg_typed_chunk_and = e.int_routes;
	config::rvv_qcg_typed_chunk_force_emit = e.int_routes && e.force_emit;
	config::rvv_qcg_typed_chunk_sub_force_emit = e.int_routes && e.force_emit;
	config::rvv_qcg_typed_chunk_mul_force_emit = e.int_routes && e.force_emit;
	config::rvv_qcg_typed_chunk_xor_force_emit = e.int_routes && e.force_emit;
	config::rvv_qcg_typed_chunk_or_force_emit = e.int_routes && e.force_emit;
	config::rvv_qcg_typed_chunk_and_force_emit = e.int_routes && e.force_emit;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_hit_counter = true;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
	config::rvv_lowering = 1;
}

struct Built {
	MemArena arena{1u << 21};
	std::vector<u32> words;
	Region *region = nullptr;
	TestCompilerRuntime cr;
	std::vector<u8> code;
};

// Translate `words` (a whole ip range starting at guest pc 0). `emit` also runs QSel/QRegAlloc and
// the emitter; QIR-level checks must be run on a region that was NEVER handed to the backend,
// because those passes rewrite operands in place and `GetVVPR()` would then answer with a PHYSICAL
// register number instead of the value identity a dataflow question is about.
void Build(Built &b, std::vector<u32> const &words, Env const &e, bool emit)
{
	ApplyEnv(e);
	b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	if (!emit)
		return;
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.cr, &segment, b.region, 0);
	b.code.assign(span.begin(), span.end());
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

rvvrun::RunDescriptor Admit(std::vector<u32> const &words, Env const &e, u32 observed_vtype)
{
	ApplyEnv(e);
	auto *mem = const_cast<u32 *>(words.data());
	return qir::rv32::RV32Translator::RvvAdmitVectorRun(
	    (uptr)mem, 0u, (u32)words.size() * 4u, (u32)words.size(), observed_vtype,
	    rvvrun::RunLimits{});
}

// Everything from here to the end of section [10] belongs to the NORMAL build. The soft-float
// sibling binary (section [S]) asserts that no FP route exists at all, so it needs the harness
// above and nothing else.
#ifndef RVV_FP_FORCE_SOFT

// The frame of the run, BY VALUE. Returning a pointer into the vector `FindFrames` produced would
// dangle at every `RunFrame(FindFrames(...))` call site -- the vector is a temporary. `begin ==
// nullptr` means no multi-member run was formed; the Inst* members point into the region arena,
// which outlives every use here.
Frame RunFrame(std::vector<Frame> const &frames)
{
	for (auto const &f : frames)
		if (f.end->n_members >= 2)
			return f;
	return Frame{};
}

unsigned CountOp(Frame const &f, Op op)
{
	unsigned n = 0;
	for (auto *i : f.body)
		n += i->GetOpcode() == op;
	return n;
}

std::vector<Inst *> OpsOf(Frame const &f, Op op)
{
	std::vector<Inst *> out;
	for (auto *i : f.body)
		if (i->GetOpcode() == op)
			out.push_back(i);
	return out;
}

// The state offsets the frame's loads/stores name, as (register, chunk) pairs.
constexpr u32 ST_VREG_BASE = (u32)(offsetof(CPUState, vec) + offsetof(rvg::VectorState, vreg));
constexpr u32 ST_F_BASE = (u32)(offsetof(CPUState, fpu) + offsetof(rvg::FPUState, f));

u32 VRegOf(u32 offs) { return (offs - ST_VREG_BASE) / rvg::VLEN_MAX_BYTES; }

// Disassemble the emitted bytes with objdump. Fails loudly: emission evidence that cannot be
// produced is not evidence.
std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_p7ma_XXXXXX";
	int const fd = mkstemp(path);
	if (fd < 0)
		return {};
	size_t written = 0;
	while (written < code.size()) {
		ssize_t const n = write(fd, code.data() + written, code.size() - written);
		if (n <= 0)
			break;
		written += (size_t)n;
	}
	close(fd);
	std::string const cmd =
	    std::string("objdump -D -b binary -m i386:x86-64 -M intel --no-show-raw-insn ") + path +
	    " 2>/dev/null";
	std::vector<std::string> out;
	if (FILE *p = popen(cmd.c_str(), "r")) {
		char line[512];
		while (fgets(line, sizeof(line), p)) {
			std::string s(line);
			auto const colon = s.find(":\t");
			if (colon == std::string::npos)
				continue;
			std::string body = s.substr(colon + 2);
			while (!body.empty() && (body.back() == '\n' || body.back() == ' '))
				body.pop_back();
			out.push_back(body);
		}
		pclose(p);
	}
	unlink(path);
	return out;
}

// The only thing that legitimately differs between two Built objects is the rel32 of the fallback
// arm's `call`, which is relative to whatever heap address the code buffer landed at. That is a
// property of the harness, not of the code generator, so it is normalised away -- and ONLY it.
std::vector<std::string> NormalizeCallTargets(std::vector<std::string> const &lines)
{
	std::vector<std::string> out;
	out.reserve(lines.size());
	for (auto const &l : lines) {
		auto const pos = l.find("call ");
		out.push_back(pos == std::string::npos ? l : l.substr(0, pos + 5) + "<stub>");
	}
	return out;
}

unsigned CountMnemonic(std::vector<std::string> const &lines, char const *m)
{
	unsigned n = 0;
	size_t const len = strlen(m);
	for (auto const &l : lines)
		if (l.compare(0, len, m) == 0 && (l.size() == len || l[len] == ' '))
			++n;
	return n;
}

// Connected components over the frame's LANE ops, using QIR value identity. Computed as
// components rather than read off chunk indices, for M2E's reason: a claim about independence
// must not be a claim about how the allocator numbered registers.
//
// The scalar broadcast values are deliberately EXCLUDED as join edges. A `.vf` member's chunks all
// read the same broadcast, so including it would merge every chunk into one component and the
// measurement would answer a different question -- the broadcast is a loop-invariant frame live-in,
// not a chain link. Which values are broadcasts is taken from the frame's own vchunkfbroadcast
// nodes, not from a register-number heuristic.
unsigned LaneComponents(Frame const &f)
{
	std::set<u32> broadcasts;
	for (auto *i : f.body)
		if (i->GetOpcode() == Op::_vchunkfbroadcast && i->o(0).IsVVPR())
			broadcasts.insert(i->o(0).GetVVPR());

	std::map<u32, u32> parent;
	auto add = [&](u32 x) {
		if (!parent.count(x))
			parent[x] = x;
	};
	std::function<u32(u32)> find = [&](u32 x) {
		while (parent[x] != x)
			x = parent[x] = parent[parent[x]];
		return x;
	};
	auto join = [&](u32 a, u32 b) {
		add(a);
		add(b);
		parent[find(a)] = find(b);
	};
	std::set<u32> nodes;
	for (auto *i : f.body) {
		auto const op = i->GetOpcode();
		if (op != Op::_vchunkfalu && op != Op::_vchunkfma && op != Op::_vchunkadd &&
		    op != Op::_vchunksub && op != Op::_vchunkmul)
			continue;
		if (!i->o(0).IsVVPR())
			continue;
		u32 const d = i->o(0).GetVVPR();
		nodes.insert(d);
		add(d);
		auto ins = i->inputs();
		for (u8 s = 0; s < ins.size(); ++s)
			if (ins[s].IsVVPR() && !broadcasts.count(ins[s].GetVVPR()))
				join(d, ins[s].GetVVPR());
	}
	std::set<u32> roots;
	for (u32 n : nodes)
		roots.insert(find(n));
	return (unsigned)roots.size();
}

// ---------------------------------------------------------------------------------------------
// [1] Membership is the route's own admission predicate, over the whole OP-V encoding space.
// ---------------------------------------------------------------------------------------------

// The ORACLE: does the SINGLE-INSTRUCTION route take this word, and WITH WHICH GUARD KIND?
// Translated with the run switch OFF, so the answer is produced by the accepted per-opcode
// translator and by nothing this checkpoint wrote.
//
// THE GUARD KIND IS NOT DECORATION. Since this section was written a SECOND native dispatcher
// appeared -- `RV32Translator::RvvTryIntegerFamily` (rv32_qir.cpp:2403), reached from
// `TranslateHelper` BEFORE `Create_hcall` -- which also builds `rvvtypedchunkbegin` frames, for
// vialu / vector memory / mask / reduction / gather / slide / fcvt and more. Those frames are
// not the eight accepted element-wise routes: their bodies own mask, tail and vstart themselves
// and they carry their own guard kinds. "A typed frame exists" therefore no longer means "a run
// member's body can execute this", and the kind is what distinguishes the two populations.
GuardKind g_last_single_kind = GuardKind::VTypeVlVstart;
bool SingleInstructionRoutes(u32 vsetvli, u32 word, Env e)
{
	e.vector_run = false;
	MemArena arena{1u << 20};
	std::vector<u32> words{vsetvli, word};
	ApplyEnv(e);
	CompilerJob::IpRangesSet ranges = {{0u, 8u}};
	CompilerJob job(nullptr, (uptr)words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	auto *region = CompilerGenRegionIR(&arena, job);
	for (auto const &f : FindFrames(region))
		if (f.begin->raw == word) {
			g_last_single_kind = f.begin->guard_kind;
			return true;
		}
	return false;
}

// The guard kinds produced by the generic native family, i.e. every kind whose BODY is
// responsible for the mask, the tail and vstart. A run member's body is whole-chunk writeback,
// so none of these can be a member however the tables move; a word served by one of them is
// outside the run's scope by construction, not by omission.
bool GenericNativeFamilyKind(GuardKind k)
{
	switch (k) {
	case GuardKind::VTypeInteger:
	case GuardKind::VTypeIntegerTwoArm:
	case GuardKind::VTypeIntegerNoRestart:
	case GuardKind::VTypeFpNoRestart:
	case GuardKind::VTypeFpAnyRM:
	case GuardKind::VTypeFpAnyRMNoRestart:
	case GuardKind::VlenbRestartable:
		return true;
	default:
		return false;
	}
}

void Check1_MembershipIsTheRoutePredicate()
{
	fprintf(stderr, "[1] OP-V sweep: run membership against the single-instruction route\n");
	struct Shape {
		char const *name;
		u32 vsetvli, vtype;
	};
	Shape const shapes[] = {{"e64,m1", VSETVLI_E64M1, 0xd8u}, {"e32,m1", VSETVLI_E32M1, 0xd0u}};
	for (auto const &s : shapes) {
		for (u32 vlen : {512u, 1024u}) {
			Env e;
			e.vlen_bits = vlen;
			unsigned admitted = 0, unsafe = 0, unexplained = 0;
			unsigned by_generic_family = 0, by_masked_fp = 0;
			for (u32 f6 = 0; f6 < 64; ++f6)
				for (u32 f3 = 0; f3 < 8; ++f3)
					for (u32 vm = 0; vm < 2; ++vm) {
						// vd/vs2/vs1 chosen so every register group is legal at
						// LMUL 1 and 2, so this sweep measures the OPCODE rule
						// and not an alignment accident.
						u32 const raw =
						    MakeOpV(f6, vm, /*vs2=*/8, /*src1=*/10, /*vd=*/12, f3);
						auto const d = Admit({raw, raw}, e, s.vtype);
						bool const got = d.n_members >= 1;
						bool const want =
						    SingleInstructionRoutes(s.vsetvli, raw, e);
						admitted += got;
						// (a) THE SAFETY DIRECTION, exhaustively: a run must
						// never admit a word the single route refuses.
						if (got && !want) {
							fprintf(stderr,
								"  FAIL [unsafe %s vlen%u] raw=%08x "
								"admitted by the run, refused by the "
								"single route\n",
								s.name, vlen, raw);
							++unsafe;
							++g_failures;
						}
						if (!want || got)
							continue;
						// (b) EVERY REFUSAL IS ONE OF THE TWO DOCUMENTED
						// CAUSES below. Anything else is a coverage
						// regression and fails right here.
						rvg::VType const vt{s.vtype};
						bool const masked = ((raw >> 25) & 1u) == 0;
						auto const cls = rvvrun::ClassifyTypedAluRoute(raw);
						bool const fp_row =
						    cls.present && (cls.op == RunOp::FAlu ||
								    cls.op == RunOp::FMA);
						if (GenericNativeFamilyKind(g_last_single_kind)) {
							++by_generic_family;
						} else if (fp_row &&
							   g_last_single_kind ==
							       GuardKind::VTypePartialVlVstartFrmHost &&
							   (masked || !vt.vta())) {
							++by_masked_fp;
						} else {
							fprintf(stderr,
								"  FAIL [unexplained %s vlen%u] "
								"raw=%08x kind=%u present=%d op=%u "
								"masked=%d cut=%s\n",
								s.name, vlen, raw,
								(unsigned)g_last_single_kind,
								(int)cls.present, (unsigned)cls.op,
								(int)masked,
								rvvrun::CutReasonName(d.cut));
							++unexplained;
							++g_failures;
						}
					}
			CHECK_EQ(unsafe, 0u);
			CHECK_EQ(unexplained, 0u);
			CHECK(admitted > 0);
			CHECK(by_generic_family > 0);
			CHECK(by_masked_fp > 0);
			fprintf(stderr,
				"    %s VLEN %-4u  1024 encodings, %u admitted, %u unsafe, "
				"%u unexplained (refused: %u generic-family, %u masked/non-vta FP)\n",
				s.name, vlen, admitted, unsafe, unexplained, by_generic_family,
				by_masked_fp);
		}
	}

	// AND THE RULE IS NOT "EVERY FP OP", which is still the point -- but the two named examples
	// have to be re-derived from the predicate rather than carried forward, because one of them
	// moved.
	//
	// vfrsub.vf IS NOW A MEMBER, and deliberately. A22 (2026-09-06) replaced the falu route's
	// list of observed (form, SEW) pairs with one semantic rule -- `arithmetic_family` in
	// RvvQcgTypedFaluAdmit (rv32_qir.cpp) -- whose last clause is
	// `(vf && (f6 == VF6_VFRSUB || f6 == VF6_VFRDIV))`. The reversed forms only exchange the
	// emitter's operands, so admitting them widens no semantics. This assertion therefore states
	// the CURRENT predicate, and it is still the route's own answer, not a list here.
	//
	// vfredusum.vs is unchanged and carries the section's point on its own: an FP decode class
	// with no row is never a member however many FP switches are on. A reduction is cross-lane,
	// so no run body can ever hold it.
	Env e;
	CHECK_EQ((unsigned)Admit({Vf(39, 8, 13, 12), Vf(39, 8, 13, 12)}, e, 0xd8u).n_members, 2u);
	CHECK_EQ((unsigned)Admit({Vv(1, 8, 10, 12), Vv(1, 8, 10, 12)}, e, 0xd8u).n_members, 0u);
	fprintf(stderr, "    ok  vfrsub.vf is an arithmetic-family member; vfredusum.vs is not\n");
}

// ---------------------------------------------------------------------------------------------
// [2] The run forms, and the chunks stay in component SSA across the operation boundary.
// ---------------------------------------------------------------------------------------------

void Check2_ComponentResidentDataflow()
{
	fprintf(stderr, "[2] cross-operation component residence on miniWeather's real chains\n");
	struct Case {
		char const *name;
		std::vector<u32> body;
		unsigned members;
		u32 live_in, live_out, f_live_in;
	};
	Case const cases[] = {
	    // compute_tendencies_x/z, 28,800 calls each at VLEN 512 (P7L-A section 3).
	    {"vfsub.vv -> vfdiv.vf", {MW_VFSUB_VV, MW_VFDIV_VF}, 2, (1u << 8) | (1u << 9), 1u << 8,
	     1u << 15},
	    // compute_tendencies_z: the FUSED chain. vd = v9 is read before it is written, so v9 is
	    // a live-in even though no earlier member defines it.
	    {"vfdiv.vf -> vfnmsub.vf", {MW_VFDIV_VF, MW_VFNMSUB_VF}, 2, (1u << 8) | (1u << 9),
	     (1u << 8) | (1u << 9), (1u << 15) | (1u << 13)},
	    // output(): the one depth-3 chain in the whole binary.
	    {"vfadd.vf -> vfdiv.vv -> vfsub.vf",
	     {MW_VFADD_VF, MW_VFDIV_VV, MW_VFSUB_VF},
	     3,
	     (1u << 8) | (1u << 9),
	     1u << 8,
	     (1u << 15) | (1u << 13)},
	};
	for (auto const &c : cases) {
		for (u32 vlen : {512u, 1024u}) {
			u8 const k = (u8)(vlen / 512u);
			Env e;
			e.vlen_bits = vlen;
			std::vector<u32> words{VSETVLI_E64M1};
			words.insert(words.end(), c.body.begin(), c.body.end());

			auto const d = Admit(c.body, e, 0xd8u);
			CHECK_EQ((unsigned)d.n_members, c.members);
			CHECK_EQ(d.live_in_mask, c.live_in);
			CHECK_EQ(d.live_out_mask, c.live_out);
			CHECK_EQ(d.f_live_in_mask, c.f_live_in);
			CHECK(d.needs_fp_bracket);
			CHECK(d.partial_vl_ok);
			CHECK((unsigned)d.nchunks == k);

			Built b;
			Build(b, words, e, /*emit=*/false);
			auto const frames = FindFrames(b.region);
			auto const f = RunFrame(frames);
			CHECK(f.begin != nullptr);
			if (!f.begin)
				continue;
			// ONE frame for the whole chain: the members do not each get their own.
			CHECK_EQ(frames.size(), 1u);
			CHECK_EQ((unsigned)f.end->n_members, c.members);

			unsigned const n_in = (unsigned)__builtin_popcount(c.live_in);
			unsigned const n_out = (unsigned)__builtin_popcount(c.live_out);
			unsigned const n_f = (unsigned)__builtin_popcount(c.f_live_in);
			// *** THE CENTRAL ASSERTION OF THIS CHECKPOINT. ***
			// CPUState vector traffic is EXACTLY the live-ins and the final live-outs.
			// The intermediate values -- v8 after member 0, and after member 1 in the
			// depth-3 case -- never reach CPUState at all. Before P7M-A this frame was
			// `members` separate frames with 2k..3k loads and k stores EACH.
			CHECK_EQ(CountOp(f, Op::_vstatechunkload), n_in * k);
			CHECK_EQ(CountOp(f, Op::_vstatechunkstore), n_out * k);
			CHECK_EQ(CountOp(f, Op::_vchunkfbroadcast), n_f);
			CHECK_EQ(CountOp(f, Op::_vchunkfalu) + CountOp(f, Op::_vchunkfma),
				 c.members * k);
			// The low and high chunks stay k DISJOINT components across every operation
			// boundary. That is the property the whole run exists to create.
			CHECK_EQ(LaneComponents(f), (unsigned)k);

			// Every non-first member reads a VALUE, not a load. Checked by value
			// identity: the set of values produced by loads, and the set consumed by
			// lane ops, may overlap only in the live-in components.
			std::set<u32> loaded;
			for (auto *i : OpsOf(f, Op::_vstatechunkload))
				if (i->o(0).IsVVPR())
					loaded.insert(i->o(0).GetVVPR());
			CHECK_EQ(loaded.size(), n_in * k);

			// The declared typed-op count is the real one. Emission would Panic
			// otherwise; assert the number too, so a compensating pair of errors fails.
			unsigned const want_typed = (n_in + n_out + c.members) * k + n_f + 2;
			CHECK_EQ((unsigned)f.begin->n_typed, want_typed);
			CHECK_EQ((unsigned)f.body.size(), want_typed);

			fprintf(stderr,
				"    ok  %-34s VLEN %-4u m=%u k=%u loads=%u stores=%u bcast=%u "
				"components=%u n_typed=%u\n",
				c.name, vlen, c.members, k, n_in * k, n_out * k, n_f,
				LaneComponents(f), want_typed);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [3] Operand order and aliasing, pinned to exact producing values.
// ---------------------------------------------------------------------------------------------

void Check3_OperandOrderAndAliasing()
{
	fprintf(stderr, "[3] operand order and legal operand overlap\n");
	Env e; // VLEN 512 -> k = 1, so every chunk statement below is about one value.

	{
		// `vfsub.vv v8, v9, v8` then `vfdiv.vf v8, v8, fa5`.
		//   member 0: vchunkfalu(d, input0 = load v9, input1 = load v8)  <- MINUEND FIRST
		//   member 1: vchunkfalu(d, input0 = member 0's def, input1 = broadcast fa5)
		// Swapping either pair computes v8-v9 or fa5/v8 -- a different function.
		Built b;
		Build(b, {VSETVLI_E64M1, MW_VFSUB_VV, MW_VFDIV_VF}, e, false);
		auto const frames = FindFrames(b.region);
		auto const f = RunFrame(frames);
		CHECK(f.begin != nullptr);
		if (f.begin) {
			std::map<u32, u32> value_of_reg; // load destination -> guest vreg
			for (auto *i : OpsOf(f, Op::_vstatechunkload))
				value_of_reg[i->o(0).GetVVPR()] =
				    VRegOf(static_cast<InstVStateChunkLoad *>(i)->offs);
			auto const lanes = OpsOf(f, Op::_vchunkfalu);
			CHECK_EQ(lanes.size(), 2u);
			if (lanes.size() == 2) {
				u32 const m0_s2 = lanes[0]->i(0).GetVVPR();
				u32 const m0_s1 = lanes[0]->i(1).GetVVPR();
				CHECK_EQ(value_of_reg.count(m0_s2) ? value_of_reg[m0_s2] : 99u, 9u);
				CHECK_EQ(value_of_reg.count(m0_s1) ? value_of_reg[m0_s1] : 99u, 8u);
				CHECK_EQ((unsigned)static_cast<InstVChunkFALU *>(lanes[0])->funct6,
					 F6_VFSUB);
				// member 1's dividend is member 0's RESULT, and its divisor is the
				// broadcast.
				CHECK_EQ(lanes[1]->i(0).GetVVPR(), lanes[0]->o(0).GetVVPR());
				auto const bc = OpsOf(f, Op::_vchunkfbroadcast);
				CHECK_EQ(bc.size(), 1u);
				if (bc.size() == 1)
					CHECK_EQ(lanes[1]->i(1).GetVVPR(), bc[0]->o(0).GetVVPR());
				CHECK_EQ((unsigned)static_cast<InstVChunkFALU *>(lanes[1])->funct6,
					 F6_VFDIV);
			}
		}
		fprintf(stderr, "    ok  vfsub.vv minuend first; vfdiv.vf dividend is the chain value\n");
	}

	{
		// FUSED OPERAND ROLES. `vfdiv.vf v8,v8,fa5` then `vfnmsub.vf v9, fa3, v8`.
		// InstVChunkFMA is (dold, b, a) = (old vd, scalar, vs2):
		//   dold = the LOAD of v9   (read before write -- v9 is a run live-in)
		//   b    = broadcast(fa3)
		//   a    = member 0's def   (v8)
		// The (b, a) swap is the mutation this pins: it would compute fma(v9, v8, fa3).
		Built b;
		Build(b, {VSETVLI_E64M1, MW_VFDIV_VF, MW_VFNMSUB_VF}, e, false);
		auto const f = RunFrame(FindFrames(b.region));
		CHECK(f.begin != nullptr);
		if (f.begin) {
			auto const fma = OpsOf(f, Op::_vchunkfma);
			auto const falu = OpsOf(f, Op::_vchunkfalu);
			auto const bc = OpsOf(f, Op::_vchunkfbroadcast);
			CHECK_EQ(fma.size(), 1u);
			CHECK_EQ(falu.size(), 1u);
			CHECK_EQ(bc.size(), 2u);
			if (fma.size() == 1 && falu.size() == 1 && bc.size() == 2) {
				std::map<u32, u32> f_of_value;
				for (auto *i : bc)
					f_of_value[i->o(0).GetVVPR()] =
					    (static_cast<InstVChunkFBroadcast *>(i)->offs - ST_F_BASE) /
					    (u32)sizeof(u64);
				u32 dold = fma[0]->i(0).GetVVPR();
				u32 mul = fma[0]->i(1).GetVVPR();
				u32 addend = fma[0]->i(2).GetVVPR();
				// dold is the v9 load, not a broadcast and not the chain value.
				bool dold_is_v9_load = false;
				for (auto *i : OpsOf(f, Op::_vstatechunkload))
					if (i->o(0).GetVVPR() == dold &&
					    VRegOf(static_cast<InstVStateChunkLoad *>(i)->offs) == 9)
						dold_is_v9_load = true;
				CHECK(dold_is_v9_load);
				CHECK_EQ(f_of_value.count(mul) ? f_of_value[mul] : 99u, 13u); // fa3
				CHECK_EQ(addend, falu[0]->o(0).GetVVPR());
				CHECK_EQ((unsigned)static_cast<InstVChunkFMA *>(fma[0])->funct6,
					 F6_VFNMSUB);
			}
		}
		fprintf(stderr, "    ok  vfnmsub.vf inputs are (old vd load, fa3 splat, chain value)\n");
	}

	{
		// FUSED WITH vd == vs2, the legal overlap. Both `dold` and `a` must be the SAME
		// pre-instruction component. A frame that published its destination before binding
		// its sources would read its own result here and nowhere else.
		Built b;
		Build(b, {VSETVLI_E64M1, MW_VFDIV_VF, VFMADD_ALIAS}, e, false);
		auto const f = RunFrame(FindFrames(b.region));
		CHECK(f.begin != nullptr);
		if (f.begin) {
			auto const fma = OpsOf(f, Op::_vchunkfma);
			CHECK_EQ(fma.size(), 1u);
			if (fma.size() == 1)
				CHECK_EQ(fma[0]->i(0).GetVVPR(), fma[0]->i(2).GetVVPR());
			// v9 is read before written, so it is a live-in AND a live-out.
			auto const d = Admit({MW_VFDIV_VF, VFMADD_ALIAS}, e, 0xd8u);
			CHECK_EQ((unsigned)d.n_members, 2u);
			CHECK(d.live_in_mask & (1u << 9));
			CHECK(d.live_out_mask & (1u << 9));
			CHECK(d.members[1].reads_vd);
			CHECK_EQ((int)d.members[1].srcd_def, -1);
		}
		fprintf(stderr, "    ok  fused vd == vs2 binds one pre-instruction component twice\n");
	}

	{
		// `.vv` WITH vd == vs1 INSIDE a run: `vfsub.vv v8, v7, v8` after a member that
		// defines v8. Both operands must be the chain value / the live-in, bound before the
		// destination is republished.
		auto const d = Admit({MW_VFDIV_VF, VFSUB_VV_ALIAS_S1}, Env{}, 0xd8u);
		CHECK_EQ((unsigned)d.n_members, 2u);
		CHECK_EQ((int)d.members[1].src1_def, 0);  // vs1 = v8 = member 0's result
		CHECK_EQ((int)d.members[1].src2_def, -1); // vs2 = v7 is a live-in
		CHECK(d.live_in_mask & (1u << 7));
		fprintf(stderr, "    ok  .vv vd == vs1 resolves vs1 to the producing member\n");
	}
}

// ---------------------------------------------------------------------------------------------
// [4] The `.vf` scalar is a frame live-in, once per DISTINCT F register.
// ---------------------------------------------------------------------------------------------

void Check4_ScalarFLiveIn()
{
	fprintf(stderr, "[4] the .vf scalar is a frame-scope live-in\n");
	Env e;
	{
		// Three `.vf` members, all reading fa5 -> ONE broadcast for the frame.
		Built b;
		Build(b, {VSETVLI_E64M1, MW_VFADD_VF, MW_VFDIV_VF, Vf(F6_VFMUL, 8, 15, 8)}, e, false);
		auto const f = RunFrame(FindFrames(b.region));
		CHECK(f.begin != nullptr);
		if (f.begin) {
			CHECK_EQ((unsigned)f.end->n_members, 3u);
			CHECK_EQ(CountOp(f, Op::_vchunkfbroadcast), 1u);
		}
		auto const d = Admit({MW_VFADD_VF, MW_VFDIV_VF, Vf(F6_VFMUL, 8, 15, 8)}, e, 0xd8u);
		CHECK_EQ(d.f_live_in_mask, 1u << 15);
		CHECK_EQ((unsigned)d.n_fscalar_members, 3u);
		fprintf(stderr, "    ok  3 .vf members, 1 F register -> 1 broadcast\n");
	}
	{
		// Two DISTINCT F registers -> two broadcasts, and only two.
		Built b;
		Build(b, {VSETVLI_E64M1, MW_VFDIV_VF, VFMUL_VF_F9}, e, false);
		auto const f = RunFrame(FindFrames(b.region));
		CHECK(f.begin != nullptr);
		if (f.begin)
			CHECK_EQ(CountOp(f, Op::_vchunkfbroadcast), 2u);
		auto const d = Admit({MW_VFDIV_VF, VFMUL_VF_F9}, e, 0xd8u);
		CHECK_EQ(d.f_live_in_mask, (1u << 15) | (1u << 9));
		fprintf(stderr, "    ok  2 distinct F registers -> 2 broadcasts\n");
	}
	{
		// *** AN F REGISTER IS NOT A VECTOR REGISTER. ***
		// `vfdiv.vf v8, v8, f9` names f9 in the rs1 FIELD. If the substrate treated that
		// field as a vector operand, v9 would appear as a vector live-in and in touched_mask,
		// the frame would emit a load of v9 that nothing reads, and the pressure bound would
		// charge a register the body never creates. None of that may happen.
		auto const d = Admit({VFDIV_VF_F9, VFMUL_VF_F9}, e, 0xd8u);
		CHECK_EQ((unsigned)d.n_members, 2u);
		CHECK_EQ(d.live_in_mask, 1u << 8);
		CHECK_EQ(d.touched_mask, 1u << 8);
		CHECK_EQ(d.f_live_in_mask, 1u << 9);
		CHECK(d.members[0].src1_is_fscalar);
		CHECK_EQ((int)d.members[0].src1_def, -1);
		Built b;
		Build(b, {VSETVLI_E64M1, VFDIV_VF_F9, VFMUL_VF_F9}, e, false);
		auto const f = RunFrame(FindFrames(b.region));
		CHECK(f.begin != nullptr);
		if (f.begin) {
			CHECK_EQ(CountOp(f, Op::_vstatechunkload), 1u); // v8 only
			for (auto *i : OpsOf(f, Op::_vstatechunkload))
				CHECK_EQ(VRegOf(static_cast<InstVStateChunkLoad *>(i)->offs), 8u);
			// The broadcast names f9's CPUState slot, not v9's.
			auto const bc = OpsOf(f, Op::_vchunkfbroadcast);
			CHECK_EQ(bc.size(), 1u);
			if (bc.size() == 1)
				CHECK_EQ(static_cast<InstVChunkFBroadcast *>(bc[0])->offs,
					 ST_F_BASE + 9u * (u32)sizeof(u64));
		}
		fprintf(stderr, "    ok  rs1=f9 makes f9 a scalar live-in and leaves v9 untouched\n");
	}
	{
		// A `.vv` member has NO broadcast and its rs1 IS a vector live-in -- the same rule,
		// the other way round.
		auto const d = Admit({Vv(F6_VFADD, 8, 9, 12), Vv(F6_VFSUB, 12, 8, 13)}, e, 0xd8u);
		CHECK_EQ((unsigned)d.n_members, 2u);
		CHECK_EQ(d.f_live_in_mask, 0u);
		CHECK_EQ(d.live_in_mask, (1u << 8) | (1u << 9));
		CHECK(!d.members[0].src1_is_fscalar);
		fprintf(stderr, "    ok  a .vv member's rs1 is a vector live-in and makes no splat\n");
	}
}

// ---------------------------------------------------------------------------------------------
// [5] The FP control/exception bracket is frame-scope.
// ---------------------------------------------------------------------------------------------

void Check5_FrameScopeFpBracket()
{
	fprintf(stderr, "[5] one host FP control/exception bracket per FRAME\n");
	for (u32 vlen : {512u, 1024u}) {
		for (bool materialize : {false, true}) {
			Env e;
			e.vlen_bits = vlen;
			e.materialize = materialize;
			Built b;
			Build(b, {VSETVLI_E64M1, MW_VFADD_VF, MW_VFDIV_VV, MW_VFSUB_VF}, e, true);
			auto const f = RunFrame(FindFrames(b.region));
			CHECK(f.begin != nullptr);
			if (!f.begin)
				continue;
			CHECK_EQ((unsigned)f.end->n_members, 3u);
			// EXACTLY ONE PAIR, whatever the member count and whatever the body mode.
			// Three separate frames would have three pairs.
			CHECK_EQ(CountOp(f, Op::_rvvqcgfpbegin), 1u);
			CHECK_EQ(CountOp(f, Op::_rvvqcgfpend), 1u);
			// And the pair BRACKETS the body: begin first, end last, both inside the
			// guarded window (they are in `f.body`, which is what "inside" means -- the
			// guard's fallback label is bound after the whole body).
			CHECK(f.body.front()->GetOpcode() == Op::_rvvqcgfpbegin);
			CHECK(f.body.back()->GetOpcode() == Op::_rvvqcgfpend);

			// In the emitted bytes: THREE stmxcsr/ldmxcsr for the whole three-member
			// frame, not two, and the third pair is required rather than tolerated.
			//
			// `Emit_rvvqcgfpbegin` (qemit.cpp:4575) emits a CONDITIONAL PRE-CLOSE ahead of
			// the bracket it opens:
			//     cmpb $0, [fround_run_open] ; je fresh ; <EmitCloseRvvFpBracket> ; fresh:
			// A preceding SCALAR FP instruction with an explicit rm can leave a bracket open
			// (rv32_fpu.h FRound under --rvv-scalar-fround-run), holding its exceptions in
			// MXCSR and not yet in fcsr; the `and eax, ~(0x3f|0x6000|0x8040)` two
			// instructions later would wipe them. So the emitted count is one pre-close pair
			// plus the bracket's own open and close = 3, EMITTED unconditionally and taken at
			// run time only when a bracket is actually open.
			//
			// This is not an inferred expectation. FFLAGS_PRECLOSE_CHECK.md (2026-09-08)
			// deleted exactly this `EmitCloseRvvFpBracket()` call and ran the result on xbd:
			// the mutant loses the scalar instruction's DZ/NV/NX in 6 of 30 oracle lines at
			// both VLENs and both run modes, while 16 unmutated arms stay byte-identical to
			// QEMU. Two is the count of a build that would drop those exceptions.
			auto const lines = Disassemble(b.code);
			CHECK(!lines.empty());
			CHECK_EQ(CountMnemonic(lines, "stmxcsr"), 3u);
			CHECK_EQ(CountMnemonic(lines, "ldmxcsr"), 3u);
			fprintf(stderr,
				"    ok  VLEN %-4u %-11s 1 bracket + 1 pre-close, 3 stmxcsr / 3 ldmxcsr\n",
				vlen, materialize ? "materialize" : "ssa");
		}
	}
	{
		// WITHOUT the run, the same three instructions get three frames and three brackets.
		// That contrast is what makes the count above a result rather than a definition.
		Env e;
		e.vector_run = false;
		Built b;
		Build(b, {VSETVLI_E64M1, MW_VFADD_VF, MW_VFDIV_VV, MW_VFSUB_VF}, e, true);
		auto const frames = FindFrames(b.region);
		CHECK_EQ(frames.size(), 3u);
		unsigned begins = 0;
		for (auto const &f : frames)
			begins += CountOp(f, Op::_rvvqcgfpbegin);
		CHECK_EQ(begins, 3u);
		// Three frames x (1 conditional pre-close + open + close) = 9, for the reason the
		// three-member case above states.
		CHECK_EQ(CountMnemonic(Disassemble(b.code), "stmxcsr"), 9u);
		fprintf(stderr, "    ok  run off: 3 frames, 3 brackets + 3 pre-closes, 9 stmxcsr\n");
	}
	{
		// An INTEGER-only run emits no bracket at all -- the FP machinery is not switched on
		// by the existence of the FP routes, only by an FP member.
		Env e;
		Built b;
		Build(b, {VSETVLI_E32M1, Iv(F6_VADD, 1, 2, 3), Iv(F6_VSUB, 3, 2, 4)}, e, true);
		auto const f = RunFrame(FindFrames(b.region));
		CHECK(f.begin != nullptr);
		if (f.begin) {
			CHECK_EQ(CountOp(f, Op::_rvvqcgfpbegin), 0u);
			CHECK_EQ(CountOp(f, Op::_rvvqcgfpend), 0u);
		}
		CHECK_EQ(CountMnemonic(Disassemble(b.code), "stmxcsr"), 0u);
		fprintf(stderr, "    ok  integer-only run: no bracket, no MXCSR instruction\n");
	}
}

// ---------------------------------------------------------------------------------------------
// [6] The guard is the conjunction of the members' requirements.
// ---------------------------------------------------------------------------------------------

// The frm test the FP guard adds, as it appears in objdump's Intel syntax.
bool HasFrmTest(std::vector<std::string> const &lines)
{
	for (auto const &l : lines)
		if (l.find("test") == 0 && l.find("0xe0") != std::string::npos)
			return true;
	return false;
}

void Check6_GuardKindIsTheConjunction()
{
	fprintf(stderr, "[6] the run's guard kind is the conjunction of its members' guards\n");
	struct Row {
		char const *name;
		u32 vsetvli, vtype;
		std::vector<u32> body;
		GuardKind want;
		bool want_frm;
		bool store_masked = true; // F1 guard switch for this row
	};
	Row const rows[] = {
	    {"integer only", VSETVLI_E32M1, 0xd0u, {Iv(F6_VADD, 1, 2, 3), Iv(F6_VSUB, 3, 2, 4)},
	     GuardKind::VTypeVlVstart, false},
	    {"FP only", VSETVLI_E64M1, 0xd8u, {MW_VFSUB_VV, MW_VFDIV_VF},
	     GuardKind::VTypePartialVlVstartFrmRNE, true},
	    // e32 is the one width at which an integer route and an FP route can be members of the
	    // SAME run, so the conjunction is reachable rather than hypothetical.
	    //
	    // F1 GUARD (2026-09-23). With --rvv-run-fp-store-masked-partial-vl=0 the conjunction is
	    // the F0 one (vl == VLMAX). With it on (the default) the integer member is lane-local,
	    // non-trapping and vector-state-only, every live-out store is masked by the live vl, and
	    // the frame takes the FP routes' own partial kind; both rows are pinned.
	    {"mixed, F1 guard off", VSETVLI_E32M1, 0xd0u, {VADD_VV_E32, VFADD_VV_E32},
	     GuardKind::VTypeVlVstartFrmRNE, true, false},
	    {"mixed, F1 guard on", VSETVLI_E32M1, 0xd0u, {VADD_VV_E32, VFADD_VV_E32},
	     GuardKind::VTypePartialVlVstartFrmRNE, true, true},
	};
	for (auto const &r : rows) {
		Env e;
		e.fp_store_masked_partial_vl = r.store_masked;
		auto const d = Admit(r.body, e, r.vtype);
		CHECK_EQ((unsigned)d.n_members, 2u);
		std::vector<u32> words{r.vsetvli};
		words.insert(words.end(), r.body.begin(), r.body.end());
		Built b;
		Build(b, words, e, true);
		auto const f = RunFrame(FindFrames(b.region));
		CHECK(f.begin != nullptr);
		if (!f.begin)
			continue;
		CHECK(f.begin->guard_kind == r.want);
		auto const lines = Disassemble(b.code);
		CHECK(!lines.empty());
		CHECK_EQ(HasFrmTest(lines), r.want_frm);
		// The vl comparison's branch: `ja` for the partial-vl kind, `jne` for the two that
		// require full VL. Both kinds emit exactly one `cmp` against vl, so the presence of
		// `ja` separates them.
		bool const has_ja = CountMnemonic(lines, "ja") > 0;
		CHECK_EQ(has_ja, r.want == GuardKind::VTypePartialVlVstartFrmRNE);
		fprintf(stderr, "    ok  %-20s guard_kind=%u frm_test=%d partial_vl=%d\n", r.name,
			(unsigned)f.begin->guard_kind, (int)r.want_frm, (int)has_ja);
	}
}

// ---------------------------------------------------------------------------------------------
// [7] Every existing rejection still rejects.
// ---------------------------------------------------------------------------------------------

void Check7_FailClosed()
{
	fprintf(stderr, "[7] rejection conditions are not relaxed\n");
	std::vector<u32> const fp_pair{MW_VFSUB_VV, MW_VFDIV_VF};
	std::vector<u32> const fused_pair{MW_VFDIV_VF, MW_VFNMSUB_VF};

	struct Row {
		char const *name;
		Env e;
		std::vector<u32> body;
		u32 vtype;
		unsigned want_members;
		CutReason want_cut;
	};
	auto off_falu = [] {
		Env e;
		e.falu = false;
		return e;
	};
	auto off_fma = [] {
		Env e;
		e.fma = false;
		return e;
	};
	auto verify = [] {
		Env e;
		e.rvv_verify = true;
		return e;
	};
	auto llvm = [] {
		Env e;
		e.aot_use_llvm = true;
		return e;
	};
	auto no_force = [] {
		Env e;
		e.force_emit = false;
		return e;
	};
	auto vlen256 = [] {
		Env e;
		e.vlen_bits = 256;
		return e;
	};
	Row const rows[] = {
	    // The route's OWN switch. The A1 contract: nothing else in the substrate can admit it.
	    {"--rvv-qcg-typed-chunk-falu off", off_falu(), fp_pair, 0xd8u, 0,
	     CutReason::RouteNotAdmitted},
	    // With the FMA route off, the first member is still admitted and the run TRUNCATES --
	    // partial refusal, not all-or-nothing.
	    {"--rvv-qcg-typed-chunk-fma off", off_fma(), fused_pair, 0xd8u, 1,
	     CutReason::RouteNotAdmitted},
	    {"--rvv-verify", verify(), fp_pair, 0xd8u, 0, CutReason::Disabled},
	    {"LLVM backend", llvm(), fp_pair, 0xd8u, 0, CutReason::RouteNotAdmitted},
	    // VLEN 256. e64,m1 IS a supported vtype at that VLEN, so the run's own vtype rule has
	    // nothing to say; what refuses the member is the FP route's `vlen_bits != 512 && != 1024`
	    // line -- i.e. the route's own predicate, reached through MemberAdmit. That is the
	    // stronger of the two possible answers, and it is the one the A1 contract requires.
	    {"VLEN 256", vlen256(), fp_pair, 0xd8u, 0, CutReason::RouteNotAdmitted},
	    // SEW and LMUL. e16 is refused by the route (its SEW set is {32, 64}).
	    //
	    // e64,m2 IS NO LONGER REFUSED BY A SINGLE-LMUL RULE, and the cut reason moved with the
	    // semantics rather than drifting. RvvRunMemberChunks now lets FP arithmetic and
	    // whole-register memory form an integral-LMUL run ("Most integer and move bodies still
	    // describe one architectural register. FP arithmetic and whole-register memory expose
	    // the complete logical group shape"), so m2 passes the run's own vtype gate and is cut
	    // one step LATER, on register-group legality: `fp_pair`'s first word is
	    // MW_VFSUB_VV = vfsub.vv v8, v9, v8, and vs2 = v9 is odd, so a two-register group at
	    // LMUL 2 is illegal -- the very refusal the P7E note in RvvQcgTypedFaluAdmit names.
	    // `want_members` is still 0: what changed is which rule says no, not whether it says no.
	    {"e16,m1", Env{}, fp_pair, 0xc8u, 0, CutReason::RouteNotAdmitted},
	    {"e64,m2 (odd vs2)", Env{}, fp_pair, 0xd9u, 0, CutReason::RegGroupIllegal},
	    // A MASKED FP OP IS REFUSED BY ITS ROUTE, NOT BY THE DECODER, and the difference from
	    // the integer family is worth naming. `rv32_decode.h` routes a masked `vadd.vv` away
	    // from `Op::_vadd_vv` to the generic `vialu` helper op, which has no route row, so the
	    // integer case is UnsupportedVector. The FP decode classes have no such split -- vm is
	    // part of the `vfalu` class -- so the vm test lives in `RvvQcgTypedFaluAdmit`
	    // (`((raw >> 25) & 1u) == 0 -> return 0`) and the run learns about it the same way it
	    // learns about every other route condition. Both are fail-closed; only the diagnostic
	    // name differs.
	    {"masked vfadd.vv", Env{}, {VFADD_VV_MASKED, MW_VFDIV_VF}, 0xd8u, 0,
	     CutReason::RouteNotAdmitted},
	};
	for (auto const &r : rows) {
		auto const d = Admit(r.body, r.e, r.vtype);
		CHECK_EQ((unsigned)d.n_members, r.want_members);
		CHECK_EQ(d.cut, r.want_cut);
		fprintf(stderr, "    ok  %-32s -> %u member(s), %s\n", r.name, r.want_members,
			rvvrun::CutReasonName(r.want_cut));
	}

	{
		// AN UNOBSERVED VTYPE. `RvvAdmitVectorRun` is given ~0u, the value the translator
		// uses when the block contained no `vsetvli`. The FP routes refuse to be bet on a
		// candidate shape they did not propose, so the run is cut with the named reason --
		// and the single-instruction frames are still produced, which is what "fail closed"
		// has to mean here: coverage moves back to the accepted route, it does not disappear.
		//
		// TWO SUB-CASES, because the unobserved path's own shape is not the run's. That path
		// proposes a hard-coded e64/e32 **m2** candidate (P7E/P7K-B: widening it would move
		// which shape an unobserved block bets on), and at m2 an ODD register is not a legal
		// group. `vfsub.vv v8, v9, v8` therefore keeps going to its helper on that path, for
		// a reason that predates this checkpoint and that P7D measured. The even-register
		// pair below is the same test without that confound, and gets both frames.
		Env e;
		for (bool even_regs : {false, true}) {
			std::vector<u32> const pair =
			    even_regs ? std::vector<u32>{Vv(F6_VFSUB, /*vs2=*/10, /*vs1=*/8, /*vd=*/8),
							 MW_VFDIV_VF}
				      : fp_pair;
			auto const d = Admit(pair, e, ~0u);
			CHECK_EQ((unsigned)d.n_members, 0u);
			CHECK_EQ(d.cut, CutReason::UnobservedVType);
			CHECK(!d.vtype_observed);
			Built b;
			Build(b, pair, e, false);
			auto const frames = FindFrames(b.region);
			// The odd-register member is refused by the unobserved path's m2 candidate, so
			// it produces no frame; the even-register pair produces one frame each.
			CHECK_EQ(frames.size(), even_regs ? 2u : 1u);
			for (auto const &f : frames) {
				CHECK_EQ((unsigned)f.end->n_members, 1u);
				// A single-instruction frame, so no run bracket bookkeeping: exactly
				// one FP bracket pair, which is what that route emitted before P7M-A.
				CHECK_EQ(CountOp(f, Op::_rvvqcgfpbegin), 1u);
			}
			fprintf(stderr,
				"    ok  unobserved vtype (%s regs) -> no run, %zu single-instruction "
				"frame(s)\n",
				even_regs ? "even" : "odd", frames.size());
		}
	}
	{
		// HOST FEATURE PROBES. With the audit force-emit switches off, admission must be
		// exactly what the single-instruction route says on THIS host -- whichever that is.
		// Asserting the equality rather than a fixed answer is what makes this row valid on a
		// machine without AVX-512.
		Env e = no_force();
		auto const d = Admit(fp_pair, e, 0xd8u);
		bool const single = SingleInstructionRoutes(VSETVLI_E64M1, MW_VFSUB_VV, e);
		CHECK_EQ(d.n_members >= 1, single);
		fprintf(stderr, "    ok  force-emit off: run membership == single-route (%d)\n",
			(int)single);
	}
	{
		// THE FOUR CUT CLASSES, between two FP members. None of them may be relaxed to make
		// an FP chain longer -- VectorMemory in particular is the whole non-trapping
		// fast-path argument.
		struct Cut {
			char const *name;
			u32 word;
			CutReason want;
		};
		Cut const cuts[] = {
		    {"vsetvl", W_VSETVL, CutReason::GuardStateWrite},
		    {"vle64.v", W_VLE64, CutReason::VectorMemory},
		    {"addi", W_ADDI, CutReason::ScalarInsn},
		    {"beq", W_BEQ, CutReason::ControlFlow},
		};
		for (auto const &c : cuts) {
			Env e;
			auto const d = Admit({MW_VFSUB_VV, c.word, MW_VFDIV_VF}, e, 0xd8u);
			CHECK_EQ((unsigned)d.n_members, 1u);
			CHECK_EQ(d.cut, c.want);
			CHECK_EQ(d.cut_pc, 4u);
			fprintf(stderr, "    ok  FP, %-8s, FP -> 1 member, %s\n", c.name,
				rvvrun::CutReasonName(c.want));
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [8] The two body modes form the SAME run and differ only in the body.
// ---------------------------------------------------------------------------------------------

void Check8_BodyModesAgreeOnTheRun()
{
	fprintf(stderr, "[8] materialize and ssa arms form the same run\n");
	std::vector<u32> const words{VSETVLI_E64M1, MW_VFADD_VF, MW_VFDIV_VV, MW_VFSUB_VF};
	for (u32 vlen : {512u, 1024u}) {
		u32 const k = vlen / 512u;
		Env ssa;
		ssa.vlen_bits = vlen;
		Env mat = ssa;
		mat.materialize = true;

		// The DESCRIPTOR is body-independent: the scan never sees the switch.
		auto const d_ssa = Admit({MW_VFADD_VF, MW_VFDIV_VV, MW_VFSUB_VF}, ssa, 0xd8u);
		auto const d_mat = Admit({MW_VFADD_VF, MW_VFDIV_VV, MW_VFSUB_VF}, mat, 0xd8u);
		CHECK_EQ((unsigned)d_ssa.n_members, (unsigned)d_mat.n_members);
		CHECK_EQ(d_ssa.live_in_mask, d_mat.live_in_mask);
		CHECK_EQ(d_ssa.live_out_mask, d_mat.live_out_mask);
		CHECK_EQ(d_ssa.f_live_in_mask, d_mat.f_live_in_mask);
		CHECK_EQ((unsigned)d_ssa.peak_live_bound, (unsigned)d_mat.peak_live_bound);
		CHECK_EQ(d_ssa.needs_fp_bracket, d_mat.needs_fp_bracket);
		CHECK_EQ(d_ssa.partial_vl_ok, d_mat.partial_vl_ok);

		Built bs, bm;
		Build(bs, words, ssa, true);
		Build(bm, words, mat, true);
		auto const fs = RunFrame(FindFrames(bs.region));
		auto const fm = RunFrame(FindFrames(bm.region));
		CHECK(fs.begin != nullptr && fm.begin != nullptr);
		if (!fs.begin || !fm.begin)
			continue;
		// Same run, same guard, same bracket, same member PCs.
		CHECK_EQ((unsigned)fs.end->n_members, (unsigned)fm.end->n_members);
		CHECK(fs.begin->guard_kind == fm.begin->guard_kind);
		CHECK_EQ(CountOp(fs, Op::_rvvqcgfpbegin), CountOp(fm, Op::_rvvqcgfpbegin));
		for (u8 i = 0; i < fs.end->n_members; ++i)
			CHECK_EQ(fs.end->members[i].pc, fm.end->members[i].pc);

		// THE DIFFERENCE, and it is the only one. The materialize arm is the
		// single-instruction bodies concatenated: per member, its own source loads, its own
		// broadcast where it has one, its own lane ops and its own destination store.
		//   vfadd.vf : k loads + 1 bcast + k ops + k stores
		//   vfdiv.vv : 2k loads +          k ops + k stores
		//   vfsub.vf : k loads + 1 bcast + k ops + k stores
		CHECK_EQ(CountOp(fm, Op::_vstatechunkload), 4u * k);
		CHECK_EQ(CountOp(fm, Op::_vstatechunkstore), 3u * k);
		CHECK_EQ(CountOp(fm, Op::_vchunkfbroadcast), 2u);
		CHECK_EQ(CountOp(fm, Op::_vchunkfalu), 3u * k);
		// The SSA arm reads CPUState twice and writes it once, for any member count.
		CHECK_EQ(CountOp(fs, Op::_vstatechunkload), 2u * k);
		CHECK_EQ(CountOp(fs, Op::_vstatechunkstore), 1u * k);
		CHECK_EQ(CountOp(fs, Op::_vchunkfbroadcast), 2u);
		// Declared counts match the bodies in both arms (emission would have Panicked).
		CHECK_EQ((unsigned)fs.begin->n_typed, (unsigned)fs.body.size());
		CHECK_EQ((unsigned)fm.begin->n_typed, (unsigned)fm.body.size());
		CHECK_EQ((unsigned)fm.begin->n_typed, 4u * k + 3u * k + 3u * k + 2u + 2u);
		fprintf(stderr,
			"    ok  VLEN %-4u ssa %u loads / %u stores, materialize %u / %u, same run\n",
			vlen, 2u * k, 1u * k, 4u * k, 3u * k);
	}

	// P6C's chunk-major issue order lowers the SAME run too, including the FP members' third
	// source and the broadcasts.
	//
	// TWO BUILDS, and the split is not cosmetic. The component count is a QIR DATAFLOW question,
	// so it must be asked of a region that was never handed to the backend: QSel/QRegAlloc
	// rewrite operands in place, and `IsVVPR()` is false afterwards, so the same query on an
	// emitted region silently answers "zero lane nodes" instead of failing. The second build
	// emits, which is what proves the declared typed-op count survives `Emit_rvvtypedchunkend`.
	Env cm;
	cm.chunk_major = true;
	cm.vlen_bits = 1024;
	std::vector<u32> const cm_words{VSETVLI_E64M1, MW_VFDIV_VF, MW_VFNMSUB_VF};
	Built b_ir, b_emit;
	Build(b_ir, cm_words, cm, /*emit=*/false);
	Build(b_emit, cm_words, cm, /*emit=*/true);
	auto const f_ir = RunFrame(FindFrames(b_ir.region));
	auto const f_emit = RunFrame(FindFrames(b_emit.region));
	CHECK(f_ir.begin != nullptr);
	CHECK(f_emit.begin != nullptr);
	if (f_ir.begin && f_emit.begin) {
		CHECK_EQ((unsigned)f_ir.end->n_members, 2u);
		CHECK_EQ(LaneComponents(f_ir), 2u);
		CHECK_EQ((unsigned)f_ir.begin->n_typed, (unsigned)f_ir.body.size());
		CHECK_EQ((unsigned)f_emit.begin->n_typed, (unsigned)f_ir.begin->n_typed);
		CHECK(!b_emit.code.empty());
	}
	fprintf(stderr, "    ok  chunk-major order lowers the same FP run, 2 components at k=2\n");
}

// ---------------------------------------------------------------------------------------------
// [9] Default-off byte identity, in both directions.
// ---------------------------------------------------------------------------------------------

void Check9_DefaultOffByteIdentity()
{
	fprintf(stderr, "[9] the switch's effect has an exact boundary\n");
	struct Row {
		char const *name;
		std::vector<u32> words;
		u32 vsetvli;
		bool expect_identical;
	};
	Row const rows[] = {
	    // A run IS admitted here, so the flag MUST change the emitted bytes. If this row went
	    // identical, the feature would have silently stopped working and every "no change" row
	    // below would be vacuous.
	    {"two FP members", {MW_VFSUB_VV, MW_VFDIV_VF}, VSETVLI_E64M1, false},
	    {"fused chain", {MW_VFDIV_VF, MW_VFNMSUB_VF}, VSETVLI_E64M1, false},
	    // No two-member run can be admitted: the flag must not touch one byte.
	    {"FP, barrier, FP", {MW_VFSUB_VV, W_VLE64, MW_VFDIV_VF}, VSETVLI_E64M1, true},
	    {"FP, vsetvl, FP", {MW_VFSUB_VV, W_VSETVL, MW_VFDIV_VF}, VSETVLI_E64M1, true},
	    {"single FP member", {MW_VFDIV_VF}, VSETVLI_E64M1, true},
	    {"unadmitted SEW", {MW_VFSUB_VV, MW_VFDIV_VF}, VSETVLI_E16M1, true},
	    {"scalar only", {W_ADDI, W_ADDI}, VSETVLI_E64M1, true},
	};
	for (auto const &r : rows) {
		for (u32 vlen : {512u, 1024u}) {
			std::vector<u32> words{r.vsetvli};
			words.insert(words.end(), r.words.begin(), r.words.end());
			Env off;
			off.vlen_bits = vlen;
			off.vector_run = false;
			Env on = off;
			on.vector_run = true;
			Built a, b;
			Build(a, words, off, true);
			Build(b, words, on, true);
			auto const la = NormalizeCallTargets(Disassemble(a.code));
			auto const lb = NormalizeCallTargets(Disassemble(b.code));
			CHECK(!la.empty());
			CHECK_EQ(la == lb, r.expect_identical);
			if (r.expect_identical)
				CHECK_EQ(a.code.size(), b.code.size());
		}
		fprintf(stderr, "    ok  %-20s run off vs on: %s\n", r.name,
			r.expect_identical ? "byte-identical" : "differs (a run was admitted)");
	}
}

// ---------------------------------------------------------------------------------------------
// [10] Typed-op capacity and the peak-liveness bound, with the two new terms.
// ---------------------------------------------------------------------------------------------

// An INDEPENDENT simulation of the SSA body's schedule, written from the frame's description
// rather than from the production code. It counts how many distinct component values are
// simultaneously live, including the frame-scope broadcasts (created at entry, live throughout)
// and the fused forms' third source.
unsigned SimulatePeak(rvvrun::RunDescriptor const &d)
{
	u8 const k = d.nchunks;
	std::array<std::array<int, rvg::VREG_NUM>, 8> cur{};
	for (auto &row : cur)
		row.fill(0);
	unsigned live = 0, peak = 0;
	// Frame-scope broadcasts: one value each, live for the whole body.
	live += (unsigned)__builtin_popcount(d.f_live_in_mask);
	// Live-in loads.
	for (u32 r = 0; r < rvg::VREG_NUM; ++r)
		if (d.live_in_mask & (1u << r))
			for (u8 c = 0; c < k; ++c) {
				cur[c][r] = 1;
				++live;
			}
	peak = live;
	for (u8 i = 0; i < d.n_members; ++i) {
		auto const &m = d.members[i];
		for (u8 c = 0; c < k; ++c) {
			// The destination is live simultaneously with the sources of the same
			// operation.
			++live;
			peak = std::max(peak, live);
			if (cur[c][m.rd]) // the previous value of rd dies here
				--live;
			cur[c][m.rd] = 1;
		}
	}
	return peak;
}

void Check10_CapacityAndPressure()
{
	fprintf(stderr, "[10] typed-op capacity and the peak-liveness bound\n");
	// The bound is unchanged for every integer-only shape -- the two new terms default off.
	for (unsigned touched = 1; touched <= 24; ++touched)
		for (u8 k : {(u8)1, (u8)2, (u8)4, (u8)8})
			CHECK_EQ((unsigned)rvvrun::RvvRunPeakLiveBound((u8)touched, k),
				 std::max((touched + 1u) * k, 3u * k));
	// The broadcast term adds exactly one register per DISTINCT F register on the SSA side.
	CHECK_EQ((unsigned)rvvrun::RvvRunPeakLiveBound(2, 2, 0, false), 6u);
	CHECK_EQ((unsigned)rvvrun::RvvRunPeakLiveBound(2, 2, 1, false), 7u);
	CHECK_EQ((unsigned)rvvrun::RvvRunPeakLiveBound(2, 2, 3, false), 9u);
	// The fused term binds only on the materialize side and only at small `touched`.
	CHECK_EQ((unsigned)rvvrun::RvvRunPeakLiveBound(1, 4, 0, true), 16u); // 4k > (1+1)k
	CHECK_EQ((unsigned)rvvrun::RvvRunPeakLiveBound(8, 4, 0, true), 36u); // (8+1)k > 4k
	// It never wraps: the clamp is what turns "cut this run" into a decision rather than a u8
	// accident.
	CHECK_EQ((unsigned)rvvrun::RvvRunPeakLiveBound(255, 8, 32, true), 255u);
	// The typed-op rule is unchanged for integer-only runs, term by term.
	CHECK_EQ(rvvrun::RvvRunTypedOpCount(2, 1, 64, 1), 256u);
	CHECK_EQ(rvvrun::RvvRunTypedOpCount(2, 1, 4, 1), 16u);
	CHECK_EQ(rvvrun::RvvRunTypedOpCount(2, 1, 64, 2), 512u);
	// ... and grows by exactly the FP terms. Both numbers are the MATERIALIZE side, which is the
	// larger of the two at these shapes:
	//   4 members, k=1, 1 broadcast, 1 .vf member, no fused, bracket
	//     ssa         = (2 + 1 + 4)*1 + 1 + 2                    = 10
	//     materialize = 4*4*1 + 0*1   + 1 + 2                    = 19   <- max
	//   4 members, k=1, no broadcast, no .vf, 4 fused, bracket
	//     ssa         = (2 + 1 + 4)*1 + 0 + 2                    =  9
	//     materialize = 4*4*1 + 4*1   + 0 + 2                    = 22   <- max
	CHECK_EQ(rvvrun::RvvRunTypedOpCount(2, 1, 4, 1, 1, 1, 0, true), 19u);
	CHECK_EQ(rvvrun::RvvRunTypedOpCount(2, 1, 4, 1, 0, 0, 4, true), 22u);
	// The bracket term alone, with every FP shape term zero, is exactly +2.
	CHECK_EQ(rvvrun::RvvRunTypedOpCount(2, 1, 4, 1, 0, 0, 0, true),
		 rvvrun::RvvRunTypedOpCount(2, 1, 4, 1) + 2u);
	fprintf(stderr, "    ok  bound and capacity rules, integer terms unchanged\n");

	// The production bound is never below an independent simulation of the real frame, over
	// every FP shape this checkpoint admits.
	std::vector<std::vector<u32>> const shapes = {
	    {MW_VFSUB_VV, MW_VFDIV_VF},
	    {MW_VFDIV_VF, MW_VFNMSUB_VF},
	    {MW_VFADD_VF, MW_VFDIV_VV, MW_VFSUB_VF},
	    {MW_VFDIV_VF, VFMADD_ALIAS},
	    {VFDIV_VF_F9, VFMUL_VF_F9},
	    {Vv(F6_VFADD, 8, 9, 12), Vv(F6_VFSUB, 12, 8, 13), Vv(F6_VFDIV, 13, 12, 14)},
	};
	for (auto const &s : shapes)
		for (u32 vlen : {512u, 1024u}) {
			Env e;
			e.vlen_bits = vlen;
			auto const d = Admit(s, e, 0xd8u);
			CHECK(d.n_members >= 2);
			CHECK(d.peak_live_bound >= SimulatePeak(d));
			CHECK(d.peak_live_bound <= rvvrun::kHostVectorRegs);
			// And the declared frame really fits: emission Panics otherwise.
			std::vector<u32> words{VSETVLI_E64M1};
			words.insert(words.end(), s.begin(), s.end());
			for (bool mat : {false, true}) {
				Env em = e;
				em.materialize = mat;
				Built b;
				Build(b, words, em, true);
				auto const f = RunFrame(FindFrames(b.region));
				CHECK(f.begin != nullptr);
				if (f.begin)
					CHECK_EQ((unsigned)f.begin->n_typed,
						 (unsigned)f.body.size());
			}
		}
	fprintf(stderr, "    ok  %zu FP shapes x 2 VLENs x 2 bodies: bound >= simulated peak, "
			"declared n_typed == real body\n",
		shapes.size());
}

// ---------------------------------------------------------------------------------------------
// [11] The ordered fallback arm, and the two things about it that P7M-A had to keep true.
//
//   * THE FP BRACKET IS INSIDE THE GUARDED WINDOW. `Emit_rvvtypedchunkend` binds the fallback
//     label AFTER the whole body, so a guard MISS branches over `rvvqcgfpbegin` as well as over
//     the lane ops. If the bracket had been emitted outside the frame -- or if the miss arm fell
//     through it -- the helpers would run with a translator-modified MXCSR, which is a silent
//     numerical change with no test that would otherwise notice. Checked by POSITION in the real
//     disassembly: every MXCSR instruction must precede the fallback arm's counter.
//
//   * THE HELPERS ARE THE MEMBERS' OWN, IN GUEST ORDER, EACH WITH ITS OWN PC. Members 1..m-1 have
//     no PreSideeff of their own, so without the per-member `state->ip` store a helper trap would
//     report member 0's PC. This is unchanged by P7M-A, and it has to be re-checked here because
//     the FP members' stubs (`rv32_vfalu` / `rv32_vfma`) are new to a run.
//
// AND THE STICKY-FFLAGS SEMANTICS, which is the whole justification for hoisting the bracket to
// the frame. Every close must ACCRUE: five conditional `or` of a guest flag bit into
// CPUState::fpu.fcsr, and no write that REPLACES fcsr. A frame emits TWO closes (the conditional
// pre-close in `Emit_rvvqcgfpbegin` and `Emit_rvvqcgfpend`), so ten ORs. An implementation that assigned instead of
// OR-ing would pass every structural check above and would clear flags the guest had already
// accumulated -- and it would be invisible until a workload read fflags.
// ---------------------------------------------------------------------------------------------

std::string HexOffs(u32 offs)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "0x%x", offs);
	return buf;
}

// Index of the first line whose mnemonic is `mnem` and whose text contains `needle`, or npos.
size_t FindLine(std::vector<std::string> const &lines, char const *mnem, std::string const &needle)
{
	size_t const len = strlen(mnem);
	for (size_t i = 0; i < lines.size(); ++i)
		if (lines[i].compare(0, len, mnem) == 0 && lines[i].find(needle) != std::string::npos)
			return i;
	return std::string::npos;
}

void Check11_OrderedFallbackAndStickyFlags()
{
	fprintf(stderr, "[11] ordered fallback arm, bracket position, and fflags accrual\n");
	std::string const fb = HexOffs((u32)offsetof(CPUState, rvv_direct_fallbacks));
	std::string const fcsr =
	    HexOffs((u32)(offsetof(CPUState, fpu) + offsetof(rvg::FPUState, fcsr)));

	for (u32 vlen : {512u, 1024u}) {
		for (bool materialize : {false, true}) {
			Env e;
			e.vlen_bits = vlen;
			e.materialize = materialize;
			// Three FP members at guest pc 4, 8, 12 (the vsetvli occupies pc 0).
			Built b;
			Build(b, {VSETVLI_E64M1, MW_VFADD_VF, MW_VFDIV_VV, MW_VFSUB_VF}, e, true);
			auto const f = RunFrame(FindFrames(b.region));
			CHECK(f.begin != nullptr);
			auto const lines = Disassemble(b.code);
			CHECK(!lines.empty());
			if (!f.begin || lines.empty())
				continue;

			// THE FALLBACK ARM'S ENTRY: the one `inc` of CPUState::rvv_direct_fallbacks.
			size_t const fb_at = FindLine(lines, "inc", fb);
			CHECK(fb_at != std::string::npos);
			if (fb_at == std::string::npos)
				continue;

			// Every MXCSR instruction is BEFORE it -- the miss arm branches over the
			// bracket.
			unsigned mxcsr_before = 0, mxcsr_after = 0;
			for (size_t i = 0; i < lines.size(); ++i) {
				bool const is_mxcsr = lines[i].compare(0, 7, "stmxcsr") == 0 ||
						      lines[i].compare(0, 7, "ldmxcsr") == 0;
				if (!is_mxcsr)
					continue;
				(i < fb_at ? mxcsr_before : mxcsr_after) += 1;
			}
			// SIX, not four. `Emit_rvvqcgfpbegin` opens with a CONDITIONAL
			// `EmitCloseRvvFpBracket()` -- if a preceding scalar instruction left a
			// bracket open with an explicit rounding mode, its exceptions are folded
			// before MXCSR is reprogrammed for the guest frm. That pre-close carries its
			// own stmxcsr+ldmxcsr, on top of the open's pair and the real close's pair.
			// It is skipped at run time when fround_run_open == 0, but it is EMITTED
			// unconditionally, and this counter counts emitted instructions.
			CHECK_EQ(mxcsr_before, 6u); // pre-close(2) + open(2) + close(2)
			CHECK_EQ(mxcsr_after, 0u);

			// ONE HELPER CALL PER MEMBER, IN GUEST ORDER, EACH WITH ITS OWN PC AND ITS
			// OWN RAW WORD. Counting calls alone would be weak; what the contract
			// actually says is that the arm REPRODUCES THE GUEST SEQUENCE, so the
			// (state->ip, rsi) pairs are read out of the disassembly and compared to the
			// members.
			//
			// The `call` matcher tolerates a `rex ` prefix: asmjit emits the stub call
			// with a REX prefix and objdump prints it as `rex call 0x...`. A matcher that
			// required the mnemonic at column 0 silently found ONE call in a three-member
			// fallback arm, which is exactly the kind of vacuous pass this file is
			// supposed to avoid.
			std::string const ip_off = HexOffs((u32)offsetof(CPUState, ip));
			std::vector<std::pair<u64, u64>> got; // (guest pc, raw)
			u64 pending_pc = ~0ull, pending_raw = ~0ull;
			unsigned calls_after = 0;
			for (size_t i = fb_at; i < lines.size(); ++i) {
				auto const &l = lines[i];
				if (l.compare(0, 4, "mov ") == 0 &&
				    l.find("[r13+" + ip_off + "]") != std::string::npos) {
					auto const c = l.rfind(",0x");
					if (c != std::string::npos)
						pending_pc = strtoull(l.c_str() + c + 1, nullptr, 16);
					continue;
				}
				auto const rsi = l.find("rsi,0x");
				if (rsi != std::string::npos &&
				    (l.compare(0, 4, "mov ") == 0 || l.compare(0, 7, "movabs ") == 0)) {
					pending_raw = strtoull(l.c_str() + rsi + 4, nullptr, 16);
					continue;
				}
				bool const is_call = l.compare(0, 5, "call ") == 0 ||
						     l.compare(0, 9, "rex call ") == 0;
				if (is_call && pending_pc != ~0ull && pending_raw != ~0ull) {
					++calls_after;
					got.push_back({pending_pc, pending_raw});
					pending_pc = pending_raw = ~0ull;
				}
			}
			std::vector<std::pair<u64, u64>> const want{
			    {4u, MW_VFADD_VF}, {8u, MW_VFDIV_VV}, {12u, MW_VFSUB_VF}};
			if (got != want) {
				fprintf(stderr, "    [diag] fb=%s fb_at=%zu of %zu lines; tail:\n",
					fb.c_str(), fb_at, lines.size());
				for (size_t i = (fb_at > 4 ? fb_at - 4 : 0); i < lines.size(); ++i)
					fprintf(stderr, "      %3zu %s\n", i, lines[i].c_str());
			}
			CHECK(got == want);
			CHECK_EQ(calls_after, 3u);

			// STICKY FFLAGS: only conditional ORs into fcsr, and nothing that REPLACES it.
			//
			// THE `mov` MATCHER COUNTS WRITES ONLY. In objdump's Intel syntax a write is
			// `mov DWORD PTR [r13+<fcsr>],...` and a READ is `mov <reg>,DWORD PTR
			// [r13+<fcsr>]`. The earlier matcher tested only `l.compare(0,4,"mov ")` and
			// therefore counted the frm READ that `Emit_rvvqcgfpbegin` performs to map the
			// guest rounding mode into the MXCSR RC field. That read is not a replacement,
			// so counting it made this check report a violation that does not exist. The
			// assertion's SUBJECT is unchanged: no instruction may assign to fcsr.
			std::string const fcsr_write = "mov    DWORD PTR [r13+" + fcsr + "],";
			unsigned or_fcsr = 0, mov_fcsr = 0;
			for (auto const &l : lines) {
				if (l.find(fcsr) == std::string::npos)
					continue;
				if (l.compare(0, 3, "or ") == 0)
					++or_fcsr;
				if (l.compare(0, fcsr_write.size(), fcsr_write) == 0)
					++mov_fcsr;
			}
			// TEN, not five: the frame emits TWO closes -- the conditional pre-close inside
			// `Emit_rvvqcgfpbegin` (see the mxcsr count above) and the real
			// `Emit_rvvqcgfpend` -- and each is five conditional ORs (NV, DZ, OF, UF, NX).
			// Accrual is idempotent, so ORing a bit twice is the same architectural result;
			// what would break stickiness is an assignment, which `mov_fcsr` still forbids.
			// Verified dynamically in FFLAGS_RUN_BLOCKER.md: with fflags preseeded to S the
			// guest observes exactly S | (flags the chain raises from 0), matching QEMU
			// bit-for-bit at m1 and m2 and with vector-run off and on.
			CHECK_EQ(or_fcsr, 10u);
			CHECK_EQ(mov_fcsr, 0u);
			fprintf(stderr,
				"    ok  VLEN %-4u %-11s bracket before fallback (%u/%u), %u ordered "
				"helper calls, %u fcsr OR / %u fcsr MOV\n",
				vlen, materialize ? "materialize" : "ssa", mxcsr_before, mxcsr_after,
				calls_after, or_fcsr, mov_fcsr);
		}
	}

	// THE SAME THREE INSTRUCTIONS WITHOUT THE RUN: three frames, so three separate fallback
	// entries. The run replaced three guards and three fallback arms with one of each; that is
	// the contrast that makes the single count above a result.
	Env off;
	off.vector_run = false;
	Built b;
	Build(b, {VSETVLI_E64M1, MW_VFADD_VF, MW_VFDIV_VV, MW_VFSUB_VF}, off, true);
	auto const lines = Disassemble(b.code);
	unsigned fb_count = 0;
	for (auto const &l : lines)
		if (l.compare(0, 4, "inc ") == 0 && l.find(fb) != std::string::npos)
			++fb_count;
	CHECK_EQ(fb_count, 3u);
	Env on;
	Built b2;
	Build(b2, {VSETVLI_E64M1, MW_VFADD_VF, MW_VFDIV_VV, MW_VFSUB_VF}, on, true);
	auto const lines2 = Disassemble(b2.code);
	unsigned fb_count2 = 0;
	for (auto const &l : lines2)
		if (l.compare(0, 4, "inc ") == 0 && l.find(fb) != std::string::npos)
			++fb_count2;
	CHECK_EQ(fb_count2, 1u);
	fprintf(stderr, "    ok  run off: 3 fallback arms; run on: 1 fallback arm, 3 ordered calls\n");
}

#endif // !RVV_FP_FORCE_SOFT

// ---------------------------------------------------------------------------------------------
// [S] THE SOFT-FLOAT BUILD GATE. Compiled from the SAME source with -DRVV_FP_FORCE_SOFT, which
// makes fp_mode() force the exact softfloat core, so the two FP routes must not exist at all.
//
// WHY IT IS A SEPARATE BINARY AND NOT A CONFIG ROW. No RUNTIME guard can express "the reference
// implementation changed": frm is still RNE, the vtype still matches, every architectural
// precondition still holds. The only fail-closed form available is for the route -- and therefore
// for run membership, which is that route's own predicate -- not to exist in that build. This
// section is what proves the run substrate inherited that property instead of routing around it.
// ---------------------------------------------------------------------------------------------
void CheckS_ForceSoftFailsClosed()
{
	fprintf(stderr, "[S] RVV_FP_FORCE_SOFT: no FP member, at any setting\n");
	std::vector<std::vector<u32>> const shapes = {
	    {MW_VFSUB_VV, MW_VFDIV_VF},
	    {MW_VFDIV_VF, MW_VFNMSUB_VF},
	    {MW_VFADD_VF, MW_VFDIV_VV, MW_VFSUB_VF},
	    {VFADD_VV_E32, VFADD_VV_E32},
	};
	unsigned cases = 0;
	for (auto const &s : shapes)
		for (u32 vlen : {512u, 1024u})
			for (u32 vtype : {0xd8u, 0xd0u}) {
				Env e;
				e.vlen_bits = vlen;
				auto const d = Admit(s, e, vtype);
				CHECK_EQ((unsigned)d.n_members, 0u);
				CHECK_EQ(d.cut, CutReason::RouteNotAdmitted);
				// And no frame either: the single-instruction routes are gone too, so
				// every one of these words goes to its architectural helper.
				std::vector<u32> words{vtype == 0xd8u ? VSETVLI_E64M1 : VSETVLI_E32M1};
				words.insert(words.end(), s.begin(), s.end());
				Built b;
				Build(b, words, e, false);
				CHECK_EQ(FindFrames(b.region).size(), 0u);
				++cases;
			}
	fprintf(stderr, "    ok  %u (shape x VLEN x vtype) cases, 0 members and 0 frames\n", cases);

	// The INTEGER run is untouched by the soft-float build -- the gate is the FP routes', not the
	// substrate's. If this regressed, the force-soft binary would be proving the wrong thing.
	Env e;
	auto const d = Admit({Iv(F6_VADD, 1, 2, 3), Iv(F6_VSUB, 3, 2, 4)}, e, 0xd0u);
	CHECK_EQ((unsigned)d.n_members, 2u);
	CHECK(!d.needs_fp_bracket);
	fprintf(stderr, "    ok  the integer run still forms in the soft-float build\n");
}

} // namespace

#ifdef RVV_FP_FORCE_SOFT
int main()
{
	printf("P7M-A: FP component run, RVV_FP_FORCE_SOFT gate\n");
	CheckS_ForceSoftFailsClosed();
	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("PASSED\n");
	return 0;
}
#else
int main()
{
	printf("P7M-A: FP cross-operation component-resident vector run\n");
	Check1_MembershipIsTheRoutePredicate();
	Check2_ComponentResidentDataflow();
	Check3_OperandOrderAndAliasing();
	Check4_ScalarFLiveIn();
	Check5_FrameScopeFpBracket();
	Check6_GuardKindIsTheConjunction();
	Check7_FailClosed();
	Check8_BodyModesAgreeOnTheRun();
	Check9_DefaultOffByteIdentity();
	Check10_CapacityAndPressure();
	Check11_OrderedFallbackAndStickyFlags();
	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("PASSED\n");
	return 0;
}
#endif
