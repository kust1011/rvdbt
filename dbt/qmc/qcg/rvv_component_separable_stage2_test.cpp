// P7O-1 STAGE 2: the first complete default-off prototype of component-separable run formation --
// the component-resident admission bound and the component-major body, changed together.
// Design: experiments/2026-08-30-prof-hung-teacher-closure/COMPONENT_SEPARABLE_RUN_DESIGN.md.
// Stage 1 (classifier + pure bound): qmc/qcg/rvv_component_separable_stage1_test.cpp.
//
// WHY ADMISSION AND EMISSION ARE ONE CHANGE, AND WHY THIS FILE TESTS THEM TOGETHER. A run is
// admitted on a bound; the bound is only true of the body that is actually emitted. Admitting on
// RvvRunPeakLiveBoundCS and emitting the member-major body puts `|live_in| * k` values live where
// the bound budgeted for `|live_in|`, which is a spill inside an open group -- QEmit::Emit_mov's
// Panic, arbitrarily far from the decision that caused it. So `RunDescriptor::component_separable`
// is the SCAN's decision and the emitter's ONLY input, and every section below checks the pair.
//
// THE SECTIONS, AND WHAT EACH ONE WOULD CATCH:
//
//   [1] PRESSURE-CUT REMOVAL, on a synthetic run with the shape of a ChaCha20 column round --
//       lane-local integer add/xor/shift-rotate over 15 guest vector registers. At VLEN 1024 the
//       default arm cuts it with CutReason::RegisterPressure; the feature arm forms the whole
//       sequence as one run with ZERO pressure cuts. Both member counts and both bounds are pinned,
//       so "it got bigger" is not enough to pass.
//   [2] THE ONE-COMPONENT NO-OP. The same words at VLEN 1024 vs 512. At k = 1 the two arms must
//       produce identical descriptors, identical QIR and identical host bytes.
//   [3] IDENTICAL TYPED-OP ACCOUNTING. For a run both arms form identically, the frame's declared
//       `n_typed`, its body length and its per-opcode multiset must be equal: the component-major
//       body is a REORDERING, not a different amount of work.
//   [4] PER-COMPONENT LOAD / BODY / STORE ORDER. Component c's stores all precede component c+1's
//       loads. This is the structural property the whole design is about, and it is exactly what
//       the emission-order ablation could NOT achieve downstream of admission.
//   [5] THE FP BRACKET STAYS SINGLE AND OUTERMOST. One `rvvqcgfpbegin` before every body op and one
//       `rvvqcgfpend` after every body op, in a run that mixes an FP member with an integer one.
//       A bracket moved inside the component loop would change the ROUNDING MODE's scope, which is
//       not what sticky OR-accumulated fflags make order-independent.
//   [6] EVERY P1-P11 VIOLATION KEEPS THE OLD BOUND AND THE OLD BODY. For each rejected category the
//       descriptor's `peak_live_bound` must still be RvvRunPeakLiveBound's value and the host bytes
//       must be byte-identical between the two arms.
//   [7] A GUARD MISS SKIPS THE FULL FRAME. Read back from objdump: every guard branch emitted
//       before the body jumps to one target, and that target is past the LAST vector instruction of
//       the component-major body.
//   [8] THE ALLOCATOR NEVER EXCEEDS ITS POOL. After the real QSel and QRegAlloc passes, the
//       60-member component-major frame contains zero allocator `mov`s and its distinct allocated
//       ZMM count is within ArchTraits::VPR_POOL -- which the member-major body could not have
//       managed, since its own bound is what refused the run in [1].
//
// SCOPE. No workload, no timing, no ISA change, no tuning. Nothing here executes emitted code.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_printer.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
namespace rvvrun = dbt::rv32::rvvrun;
using rvvrun::RunOp;

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
// [0] Compile-time pins.
// ---------------------------------------------------------------------------------------------
static_assert(rvvrun::kHostVectorRegs == qcg::ArchTraits::VPR_POOL.count(),
	      "rvvrun::kHostVectorRegs must equal the QCG allocator's V512 pool size");
static_assert(rvvrun::kHostVectorRegs == 30, "the pinned member counts below assume a pool of 30");
static_assert(rvvrun::kMaxRunMembers == 64, "the synthetic run below is sized to stay under this");

// ---------------------------------------------------------------------------------------------
// Encoders, field by field, in RVV 1.0's own layout, pinned against assembled words.
// ---------------------------------------------------------------------------------------------
constexpr u32 OPV = 0b1010111u;
constexpr u32 Enc(u32 funct6, u32 vm, u32 vs2, u32 vs1_or_imm, u32 funct3, u32 vd)
{
	return (funct6 << 26) | (vm << 25) | (vs2 << 20) | (vs1_or_imm << 15) | (funct3 << 12) |
	       (vd << 7) | OPV;
}
constexpr u32 F3_OPIVV = 0b000u, F3_OPIVI = 0b011u, F3_OPFVV = 0b001u;
constexpr u32 F6_VADD = 0b000000u, F6_VSUB = 0b000010u, F6_VXOR = 0b001011u, F6_VOR = 0b001010u;
constexpr u32 F6_VSLL = 0b100101u, F6_VSRL = 0b101000u;
constexpr u32 F6_VFADD = 0b000000u, F6_VFSUB = 0b000010u;

constexpr u32 Vvv(u32 f6, u32 vd, u32 vs2, u32 vs1) { return Enc(f6, 1, vs2, vs1, F3_OPIVV, vd); }
constexpr u32 Vvi(u32 f6, u32 vd, u32 vs2, u32 uimm) { return Enc(f6, 1, vs2, uimm, F3_OPIVI, vd); }
constexpr u32 Vfvv(u32 f6, u32 vd, u32 vs2, u32 vs1) { return Enc(f6, 1, vs2, vs1, F3_OPFVV, vd); }
constexpr u32 Vmvx(u32 f6, u32 vd, u32 vs2, u32 rs1) { return Enc(f6, 1, vs2, rs1, 0b110u, vd); }
constexpr u32 VlNre32(u32 nf, u32 rs1, u32 vd)
{
	return 0b0000111u | (vd << 7) | (0b110u << 12) | (rs1 << 15) | (0b01000u << 20) |
	       (1u << 25) | ((nf - 1) << 29);
}
static_assert(Vvv(F6_VADD, 3, 1, 2) == 0x021101d7u, "vadd.vv v3,v1,v2");
static_assert(Vvv(F6_VSUB, 4, 3, 2) == 0x0a310257u, "vsub.vv v4,v3,v2");
static_assert(Vvv(F6_VXOR, 6, 5, 4) == 0x2e520357u, "vxor.vv v6,v5,v4");
static_assert(Vvv(F6_VOR, 7, 6, 5) == 0x2a6283d7u, "vor.vv  v7,v6,v5");
static_assert(VlNre32(1, 14, 8) == 0x02876407u, "vl1re32.v v8,(a4)");
static_assert(Vmvx(dbt::rv32::VF6_VMUL, 8, 8, 11) == 0x9685e457u, "vmul.vx v8,v8,a1");

constexpr u32 W_VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0,a0,e32,m1,ta,ma
constexpr u32 W_ADDI = 0x00150513u;	     // addi a0,a0,1
constexpr u32 VTYPE_E32_M1 = dbt::rv32::VTYPE_E32_M1_TA_MA;
static_assert(VTYPE_E32_M1 == ((0x0d057557u >> 20) & 0x7ffu), "vsetvli a0,a0,e32,m1,ta,ma");

// Three plain lane-local members, for the sections that need a run both arms form identically.
constexpr u32 W_ADD_V3_V1_V2 = Vvv(F6_VADD, 3, 1, 2);
constexpr u32 W_SUB_V4_V3_V2 = Vvv(F6_VSUB, 4, 3, 2);
constexpr u32 W_XOR_V6_V5_V4 = Vvv(F6_VXOR, 6, 5, 4);
constexpr u32 W_VFADD_VV = Vfvv(F6_VFADD, /*vd=*/8, /*vs2=*/8, /*vs1=*/9);
constexpr u32 W_VFSUB_VV = Vfvv(F6_VFSUB, /*vd=*/9, /*vs2=*/8, /*vs1=*/9);
constexpr u32 W_VL1RE32 = VlNre32(1, /*rs1=*/14, /*vd=*/8);

// ---------------------------------------------------------------------------------------------
// THE SYNTHETIC ChaCha20-SHAPED RUN.
//
// It is the ARR/XOR/ROTATE quarter-round SHAPE, not ChaCha20: no guest pc, no workload binary and
// no constant from one appears here, and nothing about the result depends on it being a cipher.
// What matters is that every member is lane-local, integer, unmasked, e32/m1 -- and that the
// working set is large enough for `(touched + 1) * k` to cross the 30-register pool at k = 2 while
// `touched + 1` does not.
//
//   QR(a, b, c, d) with scratch t, rotations 16/12/8/7 as in the ChaCha20 quarter round:
//     a += b;  d ^= a;  d <<<= 16
//     c += d;  b ^= c;  b <<<= 12
//     a += b;  d ^= a;  d <<<=  8
//     c += d;  b ^= c;  b <<<=  7
//   A rotate is the three RVV instructions rvdbt's route table actually covers:
//     t = vsll.vi(x, n);  x = vsrl.vi(x, 32 - n);  x = vor.vv(x, t)
//
// so one QR is 20 instructions touching 5 vector registers. Three of them, with SEPARATE scratch
// registers, is 60 instructions touching 15 -- under kMaxRunMembers (64), and chosen so the
// default arm's bound crosses the pool INSIDE the third round rather than at its boundary.
// ---------------------------------------------------------------------------------------------
void EmitRotL(std::vector<u32> &w, u32 x, u32 t, u32 n)
{
	w.push_back(Vvi(F6_VSLL, /*vd=*/t, /*vs2=*/x, /*uimm=*/n));
	w.push_back(Vvi(F6_VSRL, /*vd=*/x, /*vs2=*/x, /*uimm=*/32u - n));
	w.push_back(Vvv(F6_VOR, /*vd=*/x, /*vs2=*/x, /*vs1=*/t));
}
void EmitQuarterRound(std::vector<u32> &w, u32 a, u32 b, u32 c, u32 d, u32 t)
{
	w.push_back(Vvv(F6_VADD, a, a, b));
	w.push_back(Vvv(F6_VXOR, d, d, a));
	EmitRotL(w, d, t, 16);
	w.push_back(Vvv(F6_VADD, c, c, d));
	w.push_back(Vvv(F6_VXOR, b, b, c));
	EmitRotL(w, b, t, 12);
	w.push_back(Vvv(F6_VADD, a, a, b));
	w.push_back(Vvv(F6_VXOR, d, d, a));
	EmitRotL(w, d, t, 8);
	w.push_back(Vvv(F6_VADD, c, c, d));
	w.push_back(Vvv(F6_VXOR, b, b, c));
	EmitRotL(w, b, t, 7);
}
std::vector<u32> ChaChaShapedWords()
{
	std::vector<u32> w;
	EmitQuarterRound(w, /*a=*/1, /*b=*/5, /*c=*/9, /*d=*/13, /*t=*/17);
	EmitQuarterRound(w, /*a=*/2, /*b=*/6, /*c=*/10, /*d=*/14, /*t=*/18);
	EmitQuarterRound(w, /*a=*/3, /*b=*/7, /*c=*/11, /*d=*/15, /*t=*/19);
	return w;
}

// ---------------------------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------------------------
// ONE FIXED CODE BUFFER FOR EVERY ARM, AND THAT IS WHAT MAKES "BYTE-IDENTICAL" MEAN ANYTHING.
//
// QEmit embeds ABSOLUTE addresses -- the helper stub table, and intra-blob references computed from
// the address the CompilerRuntime handed back. A runtime that returns a fresh heap block per call
// gives two arms two different addresses, and their bytes then differ in exactly those immediates
// for a reason that has nothing to do with the arm under test. (Measured before this was fixed: the
// VLEN 512 sixty-member no-op differed in 62 of 2552 bytes while its QIR dump was IDENTICAL.) A
// single static buffer removes that variable, so a byte difference is an emitter difference.
//
// The buffer is reused, so each arm's bytes must be COPIED OUT before the next emission -- which is
// what Build() and EmitBytes() below do, and why no two emitting Built objects are alive at once.
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
	u32 vlen = 1024;
	bool component_separable = true;
	bool scalar_passthrough = false;
	bool route_falu = false;
	bool route_mem = false;
	bool route_vx_mulacc = false;
	u32 observed_vtype = VTYPE_E32_M1;
};

// Every switch this file's result can depend on is set on EVERY call, so no section inherits a
// value another one left in the process globals.
void Apply(Env const &e)
{
	config::vlen_bits = e.vlen;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::rvv_lowering = 1;
	config::rvv_vector_run = true;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_live_range_split = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_run_scalar_passthrough = e.scalar_passthrough;
	config::rvv_run_component_separable = e.component_separable;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_sub = true;
	config::rvv_qcg_typed_chunk_mul = true;
	config::rvv_qcg_typed_chunk_xor = true;
	config::rvv_qcg_typed_chunk_or = true;
	config::rvv_qcg_typed_chunk_and = true;
	config::rvv_qcg_typed_chunk_shift = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_sub_force_emit = true;
	config::rvv_qcg_typed_chunk_mul_force_emit = true;
	config::rvv_qcg_typed_chunk_xor_force_emit = true;
	config::rvv_qcg_typed_chunk_or_force_emit = true;
	config::rvv_qcg_typed_chunk_and_force_emit = true;
	config::rvv_qcg_typed_chunk_shift_force_emit = true;
	config::rvv_qcg_typed_chunk_falu = e.route_falu;
	config::rvv_qcg_typed_chunk_falu_force_emit = e.route_falu;
	config::rvv_qcg_typed_chunk_fma = false;
	config::rvv_qcg_whole_reg = e.route_mem;
	config::rvv_qcg_whole_reg_force_emit = e.route_mem;
	config::rvv_qcg_vx_mulacc = e.route_vx_mulacc;
	config::rvv_qcg_vx_mulacc_force_emit = e.route_vx_mulacc;
	// Pinned OFF rather than left to the shipped default: each one adds a second arm or a
	// per-lane mask to the frame, and this file's subject is the order of the FULL body.
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_full_vl_fast_body = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
}

rvvrun::RunDescriptor Admit(std::vector<u32> const &words, Env const &e)
{
	Apply(e);
	auto *mem = const_cast<u32 *>(words.data());
	u32 const boundary = (u32)words.size() * 4u;
	return qir::rv32::RV32Translator::RvvAdmitVectorRun((uptr)mem, 0u, boundary,
							    (u32)words.size(), e.observed_vtype,
							    rvvrun::RunLimits{});
}

struct Built {
	MemArena arena{1u << 22};
	std::vector<u32> words;
	Region *region = nullptr;
	TestCompilerRuntime cr;
	std::vector<u8> code;
};

// `emit == false` stops after QIR construction, which is what the QSel/QRegAlloc section needs.
void Build(Built &b, std::vector<u32> const &words, Env const &e, bool emit = true)
{
	Apply(e);
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

// THE TRANSLATED WORD LIST CARRIES A LEADING `vsetvli`, and the admitted one does not, because the
// two entry points learn the run's vtype differently. RvvAdmitVectorRun is TOLD the vtype (and told
// that it was observed); the real translator has to SEE one in the block, and three of the route
// rows this file uses -- the two FP rows and the whole-register transfer pair -- declare
// `requires_observed_vtype` and refuse to be admitted into a run formed under a shape nobody
// observed. Without this prefix those sections would translate to single-instruction frames and
// their assertions about a run's body would be vacuously true.
std::vector<u32> WithVsetvli(std::vector<u32> const &w)
{
	std::vector<u32> out;
	out.reserve(w.size() + 1);
	out.push_back(W_VSETVLI_E32M1);
	out.insert(out.end(), w.begin(), w.end());
	return out;
}

// One arm's host bytes, copied out of the shared buffer before the next arm overwrites it.
std::vector<u8> EmitBytes(std::vector<u32> const &words, Env const &e)
{
	Built b;
	Build(b, words, e);
	return b.code;
}

struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
	InstRVVTypedChunkEnd *end = nullptr;
	std::vector<Inst *> body;
};

std::vector<Frame> FindFrames(Region *region)
{
	std::vector<Frame> frames;
	Frame cur;
	bool open = false;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist) {
			auto const op = ins.GetOpcode();
			if (op == Op::_rvvtypedchunkbegin) {
				cur = Frame{};
				cur.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
			} else if (op == Op::_rvvtypedchunkend) {
				if (open) {
					cur.end = static_cast<InstRVVTypedChunkEnd *>(&ins);
					frames.push_back(cur);
				}
				open = false;
			} else if (open) {
				cur.body.push_back(&ins);
			}
		}
	return frames;
}

Frame const *Widest(std::vector<Frame> const &fs)
{
	Frame const *best = nullptr;
	for (auto const &f : fs)
		if (!best || f.begin->n_members > best->begin->n_members)
			best = &f;
	return best;
}

// The chunk index a state load/store names, recovered from the SAME arithmetic
// rv32::group_chunk_state_offset performs -- at LMUL = 1 a register's k chunks are k consecutive
// `stride`-byte windows inside its VLEN_MAX_BYTES slot.
u32 StateChunkIndex(u32 offs, u32 stride)
{
	u32 const vreg_base =
	    (u32)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vreg));
	return ((offs - vreg_base) % dbt::rv32::VLEN_MAX_BYTES) / stride;
}

u8 Pop(u32 m) { return (u8)__builtin_popcount(m); }

// THE PEAK NUMBER OF SIMULTANEOUSLY LIVE 512-BIT SSA VALUES IN A FRAME'S BODY, computed from the
// QIR before register allocation. This is the quantity RvvRunPeakLiveBound and
// RvvRunPeakLiveBoundCS claim to bound, measured directly instead of inferred from the allocator's
// answer -- the allocator's DISTINCT register count is an upper bound on nothing (it may reuse one
// register many times, or use many for a small live set).
//
// A value is live from its definition until its LAST use, and the peak is taken AFTER the
// definitions at an index and BEFORE the releases at that same index, because a lane op's
// destination and the sources that define it ARE simultaneously live -- which is exactly the `+ 1`
// term R1A.2b section 5 added to the bound.
unsigned PeakLiveV512(Frame const &f)
{
	std::map<unsigned, int> last_use;
	auto each = [](Inst *ins, bool defs, auto &&fn) {
		auto sp = defs ? ins->outputs() : ins->inputs();
		for (u8 j = 0; j < sp.size(); ++j)
			if (sp[j].IsVVPR() && sp[j].GetType() == VType::V512)
				fn(sp[j].GetVVPR());
	};
	for (size_t i = 0; i < f.body.size(); ++i)
		each(f.body[i], false, [&](unsigned r) { last_use[r] = (int)i; });

	std::vector<unsigned> alive;
	unsigned peak = 0;
	for (size_t i = 0; i < f.body.size(); ++i) {
		each(f.body[i], true, [&](unsigned r) {
			if (std::find(alive.begin(), alive.end(), r) == alive.end())
				alive.push_back(r);
		});
		if (alive.size() > peak)
			peak = (unsigned)alive.size();
		alive.erase(std::remove_if(alive.begin(), alive.end(),
					   [&](unsigned r) {
						   auto it = last_use.find(r);
						   return it != last_use.end() &&
							  it->second == (int)i;
					   }),
			    alive.end());
	}
	return peak;
}

// ---------------------------------------------------------------------------------------------
// [1] Pressure-cut removal on the ChaCha20-shaped run.
// ---------------------------------------------------------------------------------------------
void CheckPressureCutRemoval()
{
	printf("[1] pressure-cut removal on a ChaCha20-shaped synthetic run\n");
	auto const words = ChaChaShapedWords();
	CHECK_EQ(words.size(), (size_t)60);

	Env off;
	off.vlen = 1024;
	off.component_separable = false;
	Env on = off;
	on.component_separable = true;

	auto const d_off = Admit(words, off);
	auto const d_on = Admit(words, on);

	// THE DEFAULT ARM IS CUT BY REGISTER PRESSURE, and the numbers are pinned rather than
	// described: at k = 2 the run stops as soon as `(touched + 1) * 2` would exceed 30, i.e. the
	// moment a 15th vector register is touched.
	CHECK(d_off.cut == rvvrun::CutReason::RegisterPressure);
	CHECK(!d_off.component_separable);
	CHECK_EQ((unsigned)Pop(d_off.touched_mask), 14u);
	CHECK_EQ((unsigned)d_off.peak_live_bound, 30u);
	CHECK_EQ((unsigned)d_off.peak_live_bound,
		 (unsigned)rvvrun::RvvRunPeakLiveBound(Pop(d_off.touched_mask), d_off.nchunks,
						       Pop(d_off.f_live_in_mask),
						       d_off.n_fused_members != 0));

	// THE FEATURE ARM FORMS THE WHOLE SEQUENCE. `touched + 1 = 16 <= 30`, so no member is ever
	// refused for pressure, and the scan stops only when it runs out of words.
	CHECK(d_on.component_separable);
	CHECK(d_on.cut != rvvrun::CutReason::RegisterPressure);
	CHECK_EQ((unsigned)d_on.n_members, 60u);
	CHECK_EQ((unsigned)Pop(d_on.touched_mask), 15u);
	CHECK_EQ((unsigned)d_on.peak_live_bound, 16u);
	CHECK_EQ((unsigned)d_on.peak_live_bound,
		 (unsigned)rvvrun::RvvRunPeakLiveBoundCS(Pop(d_on.touched_mask),
							 Pop(d_on.f_live_in_mask),
							 Pop(d_on.x_live_in_mask),
							 d_on.n_fused_members != 0));
	// ... and the SSA bound of that same run is the one that refused it: 32 > 30. This is the
	// arithmetic the design rests on, measured on a real descriptor rather than assumed.
	CHECK_EQ((unsigned)rvvrun::RvvRunPeakLiveBound(Pop(d_on.touched_mask), d_on.nchunks,
						       Pop(d_on.f_live_in_mask),
						       d_on.n_fused_members != 0),
		 32u);
	CHECK((unsigned)d_on.n_members > (unsigned)d_off.n_members);

	// THE WHOLE-BLOCK COUNTERS, which is what an ablation would report: over a translation of the
	// same 60 words the pressure cut disappears entirely and the run count drops because the runs
	// that remain are longer.
	for (int arm = 0; arm < 2; ++arm) {
		Built b;
		rvvrun::g_stats = rvvrun::Stats{};
		Build(b, WithVsetvli(words), arm ? on : off);
		auto const st = rvvrun::g_stats;
		auto const frames = FindFrames(b.region);
		auto const *w = Widest(frames);
		CHECK(w != nullptr);
		if (arm) {
			CHECK_EQ((unsigned long long)st.cuts[(unsigned)rvvrun::CutReason::
								     RegisterPressure],
				 0ull);
			CHECK_EQ((unsigned)w->begin->n_members, 60u);
		} else {
			CHECK(st.cuts[(unsigned)rvvrun::CutReason::RegisterPressure] > 0ull);
			CHECK((unsigned)w->begin->n_members < 60u);
		}
		printf("    %-4s runs=%llu members=%llu register_pressure cuts=%llu widest frame=%u "
		       "members, %zu host bytes\n",
		       arm ? "on" : "off", (unsigned long long)st.runs_formed,
		       (unsigned long long)st.members_admitted,
		       (unsigned long long)st.cuts[(unsigned)rvvrun::CutReason::RegisterPressure],
		       w ? (unsigned)w->begin->n_members : 0u, b.code.size());
	}
}

// ---------------------------------------------------------------------------------------------
// [2] The one-component no-op.
// ---------------------------------------------------------------------------------------------
void CheckOneComponentNoOp()
{
	printf("[2] one component (VLEN 512): the feature is the identity\n");
	std::vector<std::vector<u32>> const rows = {
	    {W_ADD_V3_V1_V2, W_SUB_V4_V3_V2},
	    {W_ADD_V3_V1_V2, W_SUB_V4_V3_V2, W_XOR_V6_V5_V4},
	    ChaChaShapedWords(),
	};
	for (auto const &words : rows) {
		Env off;
		off.vlen = 512;
		off.component_separable = false;
		Env on = off;
		on.component_separable = true;

		auto const d_off = Admit(words, off);
		auto const d_on = Admit(words, on);
		CHECK_EQ((unsigned)d_off.nchunks, 1u);
		// P1 refuses at one component, so the bit is false and the SSA bound is used --
		// which at k = 1 is the value RvvRunPeakLiveBoundCS would have produced anyway when
		// there is no GPR broadcast.
		CHECK(!d_on.component_separable);
		CHECK_EQ((unsigned)d_on.n_members, (unsigned)d_off.n_members);
		CHECK_EQ((unsigned)d_on.peak_live_bound, (unsigned)d_off.peak_live_bound);
		CHECK(d_on.cut == d_off.cut);

		auto const code_off = EmitBytes(WithVsetvli(words), off);
		auto const code_on = EmitBytes(WithVsetvli(words), on);
		bool const same = code_off == code_on;
		CHECK(same);
		printf("    %s  %2zu words: %u members, bound %u, %zu host bytes %s\n",
		       same ? "ok " : "FAIL", words.size(), d_on.n_members, d_on.peak_live_bound,
		       code_on.size(), same ? "identical" : "DIFFER");
	}
}

// ---------------------------------------------------------------------------------------------
// [3] Identical typed-op accounting.
// ---------------------------------------------------------------------------------------------
void CheckTypedOpAccounting()
{
	printf("[3] the component-major body is a REORDERING: identical typed-op accounting\n");
	std::vector<std::vector<u32>> const rows = {
	    {W_ADD_V3_V1_V2, W_SUB_V4_V3_V2},
	    {W_ADD_V3_V1_V2, W_SUB_V4_V3_V2, W_XOR_V6_V5_V4},
	};
	for (auto const &words : rows) {
		Env off;
		off.vlen = 1024;
		off.component_separable = false;
		Env on = off;
		on.component_separable = true;

		Built b_off, b_on;
		Build(b_off, WithVsetvli(words), off, /*emit=*/false);
		Build(b_on, WithVsetvli(words), on, /*emit=*/false);
		auto const f_off = FindFrames(b_off.region);
		auto const f_on = FindFrames(b_on.region);
		CHECK_EQ(f_off.size(), f_on.size());
		if (f_off.size() != f_on.size() || f_off.empty())
			continue;
		auto const *w_off = Widest(f_off);
		auto const *w_on = Widest(f_on);

		// The run itself is the same run: same members, same guard, same declared window.
		CHECK_EQ((unsigned)w_on->begin->n_members, (unsigned)w_off->begin->n_members);
		CHECK_EQ((unsigned)w_on->begin->guard_kind, (unsigned)w_off->begin->guard_kind);
		CHECK_EQ((unsigned)w_on->begin->n_typed, (unsigned)w_off->begin->n_typed);
		CHECK_EQ(w_on->body.size(), w_off->body.size());
		// The DECLARED count is what the guard-miss arm branches over, and for an integer run
		// every body node is a typed op, so the two must be the same number.
		CHECK_EQ((size_t)w_on->begin->n_typed, w_on->body.size());

		// Same multiset of opcodes -- so the difference between the arms is order and
		// nothing else.
		std::map<unsigned, unsigned> h_off, h_on;
		for (auto *i : w_off->body)
			h_off[(unsigned)i->GetOpcode()]++;
		for (auto *i : w_on->body)
			h_on[(unsigned)i->GetOpcode()]++;
		CHECK(h_off == h_on);

		// NON-VACUITY, and the reason the section is not just "nothing changed": for a run
		// both arms DO form, the emitted host bytes must DIFFER. If they did not, the
		// component-major arm would not be emitting a different schedule at all and every
		// other assertion in this file would be about the same body twice.
		auto const code_off = EmitBytes(WithVsetvli(words), off);
		auto const code_on = EmitBytes(WithVsetvli(words), on);
		CHECK(code_off.size() == code_on.size());
		CHECK(code_off != code_on);

		// THE MEASURED PEAK, which is what the two bounds are bounds ON. Same run, same work,
		// strictly smaller simultaneous working set -- and each arm's peak within the bound
		// its own admission used.
		unsigned const peak_off = PeakLiveV512(*w_off);
		unsigned const peak_on = PeakLiveV512(*w_on);
		auto const d_off = Admit(words, off);
		auto const d_on = Admit(words, on);
		CHECK(peak_on < peak_off);
		CHECK(peak_off <= (unsigned)d_off.peak_live_bound);
		CHECK(peak_on <= (unsigned)d_on.peak_live_bound);
		CHECK(peak_on <= (unsigned)rvvrun::kHostVectorRegs);
		printf("    ok  %zu words: n_typed %u, body %zu nodes, identical multiset; peak live "
		       "%u -> %u (bounds %u -> %u); %zu host bytes, differing\n",
		       words.size(), (unsigned)w_on->begin->n_typed, w_on->body.size(), peak_off,
		       peak_on, (unsigned)d_off.peak_live_bound, (unsigned)d_on.peak_live_bound,
		       code_on.size());
	}
}

// ---------------------------------------------------------------------------------------------
// [4] Per-component load / body / store order.
// ---------------------------------------------------------------------------------------------
void CheckComponentOrder()
{
	printf("[4] per-component order: component c's stores precede component c+1's loads\n");
	std::vector<std::vector<u32>> const rows = {
	    {W_ADD_V3_V1_V2, W_SUB_V4_V3_V2, W_XOR_V6_V5_V4},
	    ChaChaShapedWords(),
	};
	for (auto const &words : rows) {
		Env off;
		off.vlen = 1024;
		off.component_separable = false;
		Env on = off;
		on.component_separable = true;

		for (int arm = 0; arm < 2; ++arm) {
			Built b;
			Build(b, WithVsetvli(words), arm ? on : off, /*emit=*/false);
			auto const frames = FindFrames(b.region);
			auto const *w = Widest(frames);
			CHECK(w != nullptr);
			if (!w)
				continue;
			u32 const stride = (arm ? Admit(words, on) : Admit(words, off)).chunk_bytes;
			CHECK(stride != 0);

			// Index of the first/last load and store of each component.
			int first_load[rvvrun::kMaxChunks], last_load[rvvrun::kMaxChunks];
			int first_store[rvvrun::kMaxChunks], last_store[rvvrun::kMaxChunks];
			for (unsigned c = 0; c < rvvrun::kMaxChunks; ++c)
				first_load[c] = last_load[c] = first_store[c] = last_store[c] = -1;
			for (size_t idx = 0; idx < w->body.size(); ++idx) {
				Inst *ins = w->body[idx];
				if (ins->GetOpcode() == Op::_vstatechunkload) {
					u32 const c = StateChunkIndex(
					    static_cast<InstVStateChunkLoad *>(ins)->offs, stride);
					CHECK(c < rvvrun::kMaxChunks);
					if (first_load[c] < 0)
						first_load[c] = (int)idx;
					last_load[c] = (int)idx;
				} else if (ins->GetOpcode() == Op::_vstatechunkstore) {
					u32 const c = StateChunkIndex(
					    static_cast<InstVStateChunkStore *>(ins)->offs, stride);
					CHECK(c < rvvrun::kMaxChunks);
					if (first_store[c] < 0)
						first_store[c] = (int)idx;
					last_store[c] = (int)idx;
				}
			}
			CHECK(first_load[0] >= 0 && first_load[1] >= 0);
			CHECK(first_store[0] >= 0 && first_store[1] >= 0);
			if (arm) {
				// COMPONENT-MAJOR. Component 0 is finished -- loaded, computed and
				// STORED -- before component 1 is loaded at all. This single
				// inequality is the whole structural claim of the design, and it is
				// exactly what the downstream emission-order ablation could not
				// produce, because pass 1 and pass 3 stayed frame-scope there.
				CHECK(last_store[0] < first_load[1]);
				// ... and each component's own loads still precede its own stores.
				for (unsigned c = 0; c < 2; ++c)
					CHECK(last_load[c] < first_store[c]);
				printf("    ok  %2zu words on : c0 stores end at %d, c1 loads start "
				       "at %d\n",
				       words.size(), last_store[0], first_load[1]);
			} else {
				// MEMBER-MAJOR (default): every live-in of every component is loaded
				// before any member runs, and every store is at the end. Asserted so
				// the row above is a CONTRAST and not just a property nobody checked
				// on the other arm.
				CHECK(last_load[1] < first_store[0]);
				CHECK(last_load[0] < first_store[0]);
				printf("    ok  %2zu words off: all loads end at %d, first store at "
				       "%d\n",
				       words.size(), std::max(last_load[0], last_load[1]),
				       first_store[0]);
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [5] The FP bracket stays single and outermost.
// ---------------------------------------------------------------------------------------------
void CheckFpBracket()
{
	printf("[5] FP bracket: exactly one, outside the component loop\n");
	// A run mixing an integer member with FP members. The mix is REQUIRED: both FP rows declare
	// `partial_vl_ok`, so a pure-FP run is refused by P6 -- an integer member is what pins the
	// frame's guard to `vl == VLMAX`.
	std::vector<u32> const words = {W_ADD_V3_V1_V2, W_VFADD_VV, W_VFSUB_VV};
	Env on;
	on.vlen = 1024;
	on.route_falu = true;
	on.component_separable = true;

	auto const d = Admit(words, on);
	CHECK(d.needs_fp_bracket);
	CHECK(!d.partial_vl_ok);
	CHECK(d.component_separable);
	CHECK_EQ((unsigned)d.n_members, 3u);
	if (!d.component_separable)
		return;

	Built b;
	Build(b, WithVsetvli(words), on, /*emit=*/false);
	auto const frames = FindFrames(b.region);
	auto const *w = Widest(frames);
	CHECK(w != nullptr);
	if (!w)
		return;
	int begin_at = -1, end_at = -1, n_begin = 0, n_end = 0;
	int first_body = -1, last_body = -1;
	for (size_t i = 0; i < w->body.size(); ++i) {
		auto const op = w->body[i]->GetOpcode();
		if (op == Op::_rvvqcgfpbegin) {
			begin_at = (int)i;
			++n_begin;
		} else if (op == Op::_rvvqcgfpend) {
			end_at = (int)i;
			++n_end;
		} else {
			if (first_body < 0)
				first_body = (int)i;
			last_body = (int)i;
		}
	}
	// ONE bracket for the whole frame, not one per component. A bracket inside the component
	// loop would save and restore MXCSR k times: the accrued fflags would still be right
	// (sticky, OR-accumulated, so order-independent) but the ROUNDING MODE's scope would have
	// changed, which is the failure mode a flags-only assertion cannot see.
	CHECK_EQ(n_begin, 1);
	CHECK_EQ(n_end, 1);
	CHECK(begin_at >= 0 && end_at >= 0 && first_body >= 0);
	CHECK(begin_at < first_body);
	CHECK(end_at > last_body);
	// ... and the body it encloses really is component-major.
	u32 const stride = d.chunk_bytes;
	int last_store_c0 = -1, first_load_c1 = -1;
	for (size_t i = 0; i < w->body.size(); ++i) {
		Inst *ins = w->body[i];
		if (ins->GetOpcode() == Op::_vstatechunkstore &&
		    StateChunkIndex(static_cast<InstVStateChunkStore *>(ins)->offs, stride) == 0)
			last_store_c0 = (int)i;
		if (ins->GetOpcode() == Op::_vstatechunkload && first_load_c1 < 0 &&
		    StateChunkIndex(static_cast<InstVStateChunkLoad *>(ins)->offs, stride) == 1)
			first_load_c1 = (int)i;
	}
	CHECK(last_store_c0 >= 0 && first_load_c1 >= 0);
	CHECK(last_store_c0 < first_load_c1);
	printf("    ok  1 fpbegin at %d, 1 fpend at %d, body [%d,%d], c0 stores < c1 loads "
	       "(%d < %d)\n",
	       begin_at, end_at, first_body, last_body, last_store_c0, first_load_c1);
}

// ---------------------------------------------------------------------------------------------
// [6] Every P1-P11 violation keeps the old bound and the old body.
// ---------------------------------------------------------------------------------------------
void CheckViolationsKeepOldPath()
{
	printf("[6] every rejected category keeps the SSA bound and byte-identical host code\n");
	struct Row {
		char const *name;
		std::vector<u32> words;
		Env env;
	};
	auto base = [] {
		Env e;
		e.vlen = 1024;
		return e;
	};
	std::vector<Row> rows;
	{ // P4: a whole-register memory member
		Env e = base();
		e.route_mem = true;
		rows.push_back({"P4 memory member", {W_VL1RE32, W_ADD_V3_V1_V2}, e});
	}
	{ // P5: a bridging scalar passthrough member
		Env e = base();
		e.scalar_passthrough = true;
		rows.push_back({"P5 bridging scalar",
				{W_ADD_V3_V1_V2, W_ADDI, W_SUB_V4_V3_V2}, e});
	}
	{ // P6: an all-partial-vl FP run
		Env e = base();
		e.route_falu = true;
		rows.push_back({"P6 partial-vl FP run", {W_VFADD_VV, W_VFSUB_VV}, e});
	}
	{ // P1: one component
		Env e = base();
		e.vlen = 512;
		rows.push_back({"P1 one component", {W_ADD_V3_V1_V2, W_SUB_V4_V3_V2}, e});
	}

	for (auto const &r : rows) {
		Env off = r.env, on = r.env;
		off.component_separable = false;
		on.component_separable = true;

		auto const d_off = Admit(r.words, off);
		auto const d_on = Admit(r.words, on);
		// The feature arm refuses the run, so it must reach the SAME descriptor and the SAME
		// bound the default arm reaches -- and that bound must be the SSA one.
		CHECK(!d_on.component_separable);
		CHECK_EQ((unsigned)d_on.n_members, (unsigned)d_off.n_members);
		CHECK_EQ((unsigned)d_on.peak_live_bound, (unsigned)d_off.peak_live_bound);
		CHECK_EQ((unsigned)d_on.peak_live_bound,
			 (unsigned)rvvrun::RvvRunPeakLiveBound(Pop(d_on.touched_mask), d_on.nchunks,
							       Pop(d_on.f_live_in_mask),
							       d_on.n_fused_members != 0));
		auto const code_off = EmitBytes(WithVsetvli(r.words), off);
		auto const code_on = EmitBytes(WithVsetvli(r.words), on);
		bool const same = code_off == code_on;
		CHECK(same);
		printf("    %s  %-22s %u members, SSA bound %u, %zu host bytes %s\n",
		       same ? "ok " : "FAIL", r.name, d_on.n_members, d_on.peak_live_bound,
		       code_on.size(), same ? "identical" : "DIFFER");
	}
}

// ---------------------------------------------------------------------------------------------
// [7] A guard miss skips the full frame.
// ---------------------------------------------------------------------------------------------
std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_p7o1_emit_XXXXXX";
	int const fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "  mkstemp failed: %s\n", strerror(errno));
		return {};
	}
	size_t written = 0;
	while (written < code.size()) {
		ssize_t const n = write(fd, code.data() + written, code.size() - written);
		if (n <= 0) {
			close(fd);
			unlink(path);
			return {};
		}
		written += (size_t)n;
	}
	close(fd);
	std::string const cmd =
	    std::string("objdump -D -b binary -m i386:x86-64 -M intel --no-show-raw-insn ") + path +
	    " 2>&1";
	FILE *p = popen(cmd.c_str(), "r");
	if (!p) {
		unlink(path);
		return {};
	}
	std::vector<std::string> lines;
	char buf[1024];
	std::string cur;
	while (fgets(buf, sizeof(buf), p)) {
		cur += buf;
		if (!cur.empty() && cur.back() == '\n') {
			cur.pop_back();
			lines.push_back(cur);
			cur.clear();
		}
	}
	if (!cur.empty())
		lines.push_back(cur);
	int const rc = pclose(p);
	unlink(path);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
		fprintf(stderr, "  objdump did not exit cleanly (raw status %d)\n", rc);
		return {};
	}
	return lines;
}

void CheckGuardMissSkipsFrame()
{
	printf("[7] a guard miss branches past the LAST vector instruction of the component body\n");
	auto const words = ChaChaShapedWords();
	Env on;
	on.vlen = 1024;
	on.component_separable = true;
	Built b;
	Build(b, WithVsetvli(words), on);
	CHECK(!b.code.empty());
	// Reaching this line at all is already part of the evidence: Emit_rvvtypedchunkend Panics
	// unless the emitter saw EXACTLY the `n_typed` the frame declared, and that count is what
	// defines the byte window the guard-miss arm branches over. A component-major body that
	// emitted one op too many or too few would have aborted here rather than reached objdump.
	auto const lines = Disassemble(b.code);
	CHECK(!lines.empty());
	if (lines.empty())
		return;

	// Parse `<addr>:\t<mnem>\t<ops>` records.
	struct Line {
		u64 addr = 0;
		std::string mnem, ops;
	};
	std::vector<Line> recs;
	for (auto const &l : lines) {
		auto const tab = l.find('\t');
		if (tab == std::string::npos)
			continue;
		std::string const head = l.substr(0, tab);
		if (head.find(':') == std::string::npos)
			continue;
		Line r;
		r.addr = strtoull(head.c_str(), nullptr, 16);
		std::string body = l.substr(tab + 1);
		auto const sp = body.find_first_of(" \t");
		r.mnem = sp == std::string::npos ? body : body.substr(0, sp);
		if (sp != std::string::npos) {
			r.ops = body.substr(sp);
			r.ops.erase(0, r.ops.find_first_not_of(" \t"));
		}
		recs.push_back(r);
	}
	CHECK(recs.size() > 10);

	u64 first_vec = ~0ull, last_vec = 0;
	bool any_vec = false;
	for (auto const &r : recs)
		if (r.ops.find("zmm") != std::string::npos) {
			if (!any_vec)
				first_vec = r.addr;
			any_vec = true;
			last_vec = r.addr;
		}
	CHECK(any_vec);
	if (!any_vec)
		return;

	// Every conditional branch emitted BEFORE the body is a guard branch: this region holds one
	// run and nothing else, and the frame's guard is the only thing between its entry and its
	// first vector instruction.
	std::vector<u64> guard_targets;
	for (auto const &r : recs) {
		if (r.addr >= first_vec)
			break;
		if (r.mnem == "jne" || r.mnem == "ja" || r.mnem == "jb" || r.mnem == "jbe")
			guard_targets.push_back(strtoull(r.ops.c_str(), nullptr, 16));
	}
	CHECK(!guard_targets.empty());
	bool one_target = true;
	for (auto t : guard_targets)
		one_target = one_target && t == guard_targets[0];
	// ONE fallback label for every guard branch, and it is past the whole body: a missed guard
	// executes NONE of the component-major frame, exactly as it executes none of the
	// member-major one. If the component loop had been emitted outside the guarded window, some
	// vector instruction would sit at or after this target.
	CHECK(one_target);
	CHECK(guard_targets[0] > last_vec);
	printf("    ok  %zu guard branch(es) -> %#llx, last body vector insn at %#llx (%zu host "
	       "bytes)\n",
	       guard_targets.size(), (unsigned long long)guard_targets[0],
	       (unsigned long long)last_vec, b.code.size());
}

// ---------------------------------------------------------------------------------------------
// [8] The allocator never exceeds its pool.
// ---------------------------------------------------------------------------------------------
void CheckAllocatorPool()
{
	printf("[8] after QSel + QRegAlloc: no spill, and the pool is not exceeded\n");
	auto const words = ChaChaShapedWords();
	Env on;
	on.vlen = 1024;
	on.component_separable = true;

	Built b;
	// Exactly the two passes qcg::GenerateCode runs before constructing QEmit.
	Build(b, WithVsetvli(words), on, /*emit=*/false);
	qcg::MachineRegionInfo mri;
	qcg::QSelPass::run(b.region, &mri);
	qcg::QRegAllocPass::run(b.region);

	auto const frames = FindFrames(b.region);
	auto const *w = Widest(frames);
	CHECK(w != nullptr);
	if (!w)
		return;
	CHECK_EQ((unsigned)w->begin->n_members, 60u);

	unsigned movs = 0;
	std::vector<unsigned> pregs;
	unsigned bad_operands = 0;
	for (auto *ins : w->body) {
		// Any `mov` inside an open group would be an allocator spill, fill or copy --
		// QEmit::Emit_mov Panics on one, so seeing it here at all is already the failure.
		movs += ins->GetOpcode() == Op::_mov;
		auto scan = [&](VOperand o) {
			if (o.GetType() != VType::V512)
				return;
			if (!o.IsPVPR() || !qcg::ArchTraits::VPR_POOL.Test(o.GetPVPR())) {
				++bad_operands;
				return;
			}
			pregs.push_back(o.GetPVPR());
		};
		auto outs = ins->outputs();
		for (u8 i = 0; i < outs.size(); ++i)
			scan(outs[i]);
		auto ins_ops = ins->inputs();
		for (u8 i = 0; i < ins_ops.size(); ++i)
			scan(ins_ops[i]);
	}
	CHECK_EQ(movs, 0u);
	CHECK_EQ(bad_operands, 0u);
	std::sort(pregs.begin(), pregs.end());
	pregs.erase(std::unique(pregs.begin(), pregs.end()), pregs.end());
	// The frame's descriptor bound was 16; the allocator's own answer must fit the same pool.
	// The member-major body for these words does not exist to compare against -- its bound (32)
	// is what refused the run in [1] -- which is the point of the section.
	CHECK(pregs.size() <= (size_t)qcg::ArchTraits::VPR_POOL.count());
	CHECK(pregs.size() <= (size_t)rvvrun::kHostVectorRegs);

	// The distinct-register count above is what the ALLOCATOR used over the whole frame; it is an
	// upper bound on nothing, because the allocator may reuse one register many times. The
	// quantity the admission bound is about is the PEAK simultaneous live set, measured on the
	// pre-allocation QIR, and it must fit inside the bound the scan admitted this run on.
	Built pre;
	Build(pre, WithVsetvli(words), on, /*emit=*/false);
	auto const pre_frames = FindFrames(pre.region);
	auto const *pw = Widest(pre_frames);
	CHECK(pw != nullptr);
	if (pw) {
		unsigned const peak = PeakLiveV512(*pw);
		auto const d = Admit(words, on);
		CHECK_EQ((unsigned)d.peak_live_bound, 16u);
		CHECK(peak <= (unsigned)d.peak_live_bound);
		CHECK(peak <= (unsigned)rvvrun::kHostVectorRegs);
		printf("    ok  60-member component-major frame: peak %u live V512 values against "
		       "the admitted bound %u (pool %u); %zu distinct pool ZMMs, 0 allocator movs\n",
		       peak, (unsigned)d.peak_live_bound,
		       (unsigned)qcg::ArchTraits::VPR_POOL.count(), pregs.size());
	}
}


// ---------------------------------------------------------------------------------------------
// [9] THE REGIME WHERE THE COMPONENT-RESIDENT BOUND IS THE LARGER ONE.
//
// Stage 1's exhaustive sweep found 747 inputs, all with four or more frame-scope broadcasts, where
// RvvRunPeakLiveBoundCS EXCEEDS RvvRunPeakLiveBound -- the new bound charges `n_fbcast + n_xbcast`
// in both of its terms while the old one charges `n_fbcast` in one and `(n_fbcast ? 1 : 0)` in the
// other, and never sees the GPR broadcasts at all. This section builds a run that REACHES that
// regime, which matters for two reasons that no other section can show:
//
//   * the run is LEGALLY separable (RvvRunComponentSeparable says yes) and must still be REFUSED,
//     because taking the larger bound would let the feature cut a run the default arm admits;
//   * it is the only input on which "the descriptor bit is the scan's DECISION" and "the
//     descriptor bit is the legality PREDICATE" give different answers. Recording legality here
//     would emit the component-major body for a run admitted on the SSA bound -- the exact hole
//     Stage 1's report flagged as open.
//
// FOUR `.vx` MEMBERS READING FOUR DIFFERENT GPRs is the smallest shape that gets there: one touched
// vector register, four frame-scope broadcasts.
//   SSA bound  max((1 + 1) * 2 + 0, 3 * 2 + 0)  = 6
//   CS  bound  max((1 + 1) + 4,     3 + 4)      = 7   > 6
// ---------------------------------------------------------------------------------------------
void CheckBoundInversionRegime()
{
	printf("[9] a legally separable run whose component-resident bound is LARGER is refused\n");
	std::vector<u32> const words = {
	    Vmvx(dbt::rv32::VF6_VMUL, /*vd=*/8, /*vs2=*/8, /*rs1=*/11),
	    Vmvx(dbt::rv32::VF6_VMUL, /*vd=*/8, /*vs2=*/8, /*rs1=*/12),
	    Vmvx(dbt::rv32::VF6_VMUL, /*vd=*/8, /*vs2=*/8, /*rs1=*/13),
	    Vmvx(dbt::rv32::VF6_VMUL, /*vd=*/8, /*vs2=*/8, /*rs1=*/14),
	};
	Env off;
	off.vlen = 1024;
	off.route_vx_mulacc = true;
	off.component_separable = false;
	Env on = off;
	on.component_separable = true;

	auto const d_off = Admit(words, off);
	auto const d_on = Admit(words, on);
	CHECK_EQ((unsigned)d_on.n_members, 4u);
	CHECK_EQ((unsigned)Pop(d_on.touched_mask), 1u);
	CHECK_EQ((unsigned)Pop(d_on.x_live_in_mask), 4u);

	u8 const touched = Pop(d_on.touched_mask), nf = Pop(d_on.f_live_in_mask),
		 nx = Pop(d_on.x_live_in_mask);
	bool const fused = d_on.n_fused_members != 0;
	u8 const ssa = rvvrun::RvvRunPeakLiveBound(touched, d_on.nchunks, nf, fused);
	u8 const cs = rvvrun::RvvRunPeakLiveBoundCS(touched, nf, nx, fused);
	// The inversion is REACHED -- if it were not, everything below would pass vacuously.
	CHECK_EQ((unsigned)ssa, 6u);
	CHECK_EQ((unsigned)cs, 7u);
	CHECK(cs > ssa);

	// It is legally separable...
	CHECK(rvvrun::RvvRunComponentSeparable(d_on));
	// ... and the scan still refuses to take the component-resident bound, so the descriptor
	// carries no bit, keeps the SSA bound, and the emitter produces the default body.
	CHECK(!d_on.component_separable);
	CHECK_EQ((unsigned)d_on.peak_live_bound, (unsigned)ssa);
	CHECK_EQ((unsigned)d_on.peak_live_bound, (unsigned)d_off.peak_live_bound);
	auto const code_off = EmitBytes(WithVsetvli(words), off);
	auto const code_on = EmitBytes(WithVsetvli(words), on);
	CHECK(code_off == code_on);
	printf("    ok  4 .vx members, touched=%u broadcasts=%u: legality YES, decision NO "
	       "(cs %u > ssa %u), %zu host bytes identical\n",
	       touched, nx, cs, ssa, code_on.size());
}

} // namespace

int main()
{
	printf("P7O-1 stage 2: component-resident admission bound + component-major body\n");
	CheckPressureCutRemoval();
	CheckOneComponentNoOp();
	CheckTypedOpAccounting();
	CheckComponentOrder();
	CheckFpBracket();
	CheckViolationsKeepOldPath();
	CheckGuardMissSkipsFrame();
	CheckAllocatorPool();
	CheckBoundInversionRegime();
	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("PASS\n");
	return 0;
}
