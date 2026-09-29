// P7O-2: demand-driven CPUState placement inside the component-major vector-run body.
// Design: experiments/2026-08-30-prof-hung-teacher-closure/COMPONENT_MAJOR_DEMAND_PLACEMENT_DESIGN.md
// The body this one re-places: qmc/qcg/rvv_component_separable_stage2_test.cpp (P7O-1 Stage 2).
//
// WHAT THE SWITCH IS. `--rvv-run-component-demand-placement=1` keeps the component-major body's
// nodes exactly as they are and moves only WHERE its CPUState accesses sit:
//
//   Rule L  a live-in's chunk-c load is emitted immediately before the FIRST member of component c
//           that reads it, at the operand-binding site;
//   Rule S  a live-out's chunk-c store is emitted immediately after the member `last_def[r]` names
//           has finished component c -- the earliest position at which the value is final.
//
// It is an EMISSION-side switch read after admission, so both arms form the SAME runs from the
// SAME descriptors under the SAME bound. That is what every section below is written to check
// rather than assume.
//
// THE SECTIONS, AND WHAT EACH ONE WOULD CATCH:
//
//   [1] THE section-5.4 FAIL-CLOSED PRECONDITION, by single-field descriptor mutation. Rule S uses
//       `last_def[r]` as an emission POSITION, so an out-of-range entry must be refused rather than
//       silently anchoring a store to a member that does not exist.
//   [2] THE NO-OP SET, byte-for-byte: VLEN 512 (k = 1, where P1 admits no component-separable run
//       at all), the feature switch off, and a run P1-P11 refuses. If any of these differed, the
//       switch would not be confined to the component-major arm.
//   [3] SINGLE FACTOR, on eighteen member shapes covering everything RvvRunComponentSeparable
//       admits today. Same declared `n_typed`, same body length, same opcode multiset, the same
//       ARITHMETIC SEQUENCE with the same per-operand provenance, and the same STORE PROVENANCE --
//       which is what makes "Rule S stores the final value" a checked property (a store anchored
//       one member too early names a different producer) rather than an argument.
//   [4] THE SIX PLACEMENT OBLIGATIONS I1-I6 on the emitted node stream, per (register, chunk).
//   [5] PLACEMENT, measured: maximum consecutive memory / load / store instructions and the
//       c0 -> c1 boundary burst, against the offline model's predictions for the ChaCha20 shape.
//   [6] PEAK LIVENESS falls and never exceeds the bound the run was admitted on.
//   [7] THE FP BRACKET stays single and outermost, and the frame-scope broadcasts stay out of the
//       component loop.
//   [8] AFTER THE REAL QSel + QRegAlloc: no allocator mov, pool not exceeded.
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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
namespace rvvrun = dbt::rv32::rvvrun;
using rvvrun::RunOp;

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
		auto _a = (a);                                                                       \
		auto _b = (b);                                                                        \
		if (!(_a == _b)) {                                                                   \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__,         \
				__LINE__, #a, #b, (long long)_a, (long long)_b);                     \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

// ---------------------------------------------------------------------------------------------
// [0] Compile-time pins.
// ---------------------------------------------------------------------------------------------
static_assert(rvvrun::kHostVectorRegs == qcg::ArchTraits::VPR_POOL.count(),
	      "rvvrun::kHostVectorRegs must equal the QCG allocator's V512 pool size");
static_assert(rvvrun::kHostVectorRegs == 30, "the pinned member counts below assume a pool of 30");
static_assert(rvvrun::kMaxRunMembers == 64, "the synthetic runs below stay under this");

// ---------------------------------------------------------------------------------------------
// Encoders, in RVV 1.0's own layout, pinned against assembled words.
// ---------------------------------------------------------------------------------------------
constexpr u32 OPV = 0b1010111u;
constexpr u32 Enc(u32 funct6, u32 vm, u32 vs2, u32 vs1_or_imm, u32 funct3, u32 vd)
{
	return (funct6 << 26) | (vm << 25) | (vs2 << 20) | (vs1_or_imm << 15) | (funct3 << 12) |
	       (vd << 7) | OPV;
}
constexpr u32 F3_OPIVV = 0b000u, F3_OPIVI = 0b011u, F3_OPIVX = 0b100u, F3_OPFVV = 0b001u,
	      F3_OPFVF = 0b101u, F3_OPMVX = 0b110u;
constexpr u32 F6_VADD = 0b000000u, F6_VSUB = 0b000010u, F6_VXOR = 0b001011u, F6_VOR = 0b001010u;
constexpr u32 F6_VSLL = 0b100101u, F6_VSRL = 0b101000u;
constexpr u32 F6_VFADD = 0b000000u, F6_VFSUB = 0b000010u;
constexpr u32 F6_VFMACC = 0b101100u;
constexpr u32 F6_MERGE = 0b010111u; // vmv.v.{v,x,i} / vfmv.v.f at vm = 1, vs2 = 0

constexpr u32 Vvv(u32 f6, u32 vd, u32 vs2, u32 vs1) { return Enc(f6, 1, vs2, vs1, F3_OPIVV, vd); }
constexpr u32 Vvi(u32 f6, u32 vd, u32 vs2, u32 uimm) { return Enc(f6, 1, vs2, uimm, F3_OPIVI, vd); }
constexpr u32 Vfvv(u32 f6, u32 vd, u32 vs2, u32 vs1) { return Enc(f6, 1, vs2, vs1, F3_OPFVV, vd); }
constexpr u32 Vfvf(u32 f6, u32 vd, u32 vs2, u32 fs1) { return Enc(f6, 1, vs2, fs1, F3_OPFVF, vd); }
constexpr u32 Vmvx(u32 f6, u32 vd, u32 vs2, u32 rs1) { return Enc(f6, 1, vs2, rs1, F3_OPMVX, vd); }
constexpr u32 VmvVV(u32 vd, u32 vs1) { return Enc(F6_MERGE, 1, 0, vs1, F3_OPIVV, vd); }
constexpr u32 VmvVX(u32 vd, u32 rs1) { return Enc(F6_MERGE, 1, 0, rs1, F3_OPIVX, vd); }
constexpr u32 VmvVI(u32 vd, u32 imm) { return Enc(F6_MERGE, 1, 0, imm & 0x1fu, F3_OPIVI, vd); }
constexpr u32 VfmvVF(u32 vd, u32 fs1) { return Enc(F6_MERGE, 1, 0, fs1, F3_OPFVF, vd); }
constexpr u32 VlNre32(u32 nf, u32 rs1, u32 vd)
{
	return 0b0000111u | (vd << 7) | (0b110u << 12) | (rs1 << 15) | (0b01000u << 20) |
	       (1u << 25) | ((nf - 1) << 29);
}
static_assert(Vvv(F6_VADD, 3, 1, 2) == 0x021101d7u, "vadd.vv v3,v1,v2");
static_assert(Vvv(F6_VSUB, 4, 3, 2) == 0x0a310257u, "vsub.vv v4,v3,v2");
static_assert(Vvv(F6_VXOR, 6, 5, 4) == 0x2e520357u, "vxor.vv v6,v5,v4");
static_assert(VmvVV(9, 8) == 0x5e0404d7u, "vmv.v.v v9,v8");
static_assert(VmvVI(8, 5) == 0x5e02b457u, "vmv.v.i v8,5");
static_assert(VlNre32(1, 14, 8) == 0x02876407u, "vl1re32.v v8,(a4)");
static_assert(Vmvx(dbt::rv32::VF6_VMUL, 8, 8, 11) == 0x9685e457u, "vmul.vx v8,v8,a1");

constexpr u32 W_VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0,a0,e32,m1,ta,ma
constexpr u32 VTYPE_E32_M1 = dbt::rv32::VTYPE_E32_M1_TA_MA;
static_assert(VTYPE_E32_M1 == ((0x0d057557u >> 20) & 0x7ffu), "vsetvli a0,a0,e32,m1,ta,ma");

// ---------------------------------------------------------------------------------------------
// The ChaCha20-SHAPED synthetic run, identical to the one Stage 2's test uses so the two files
// are talking about the same frame. It is the ADD/XOR/ROTATE quarter-round SHAPE, not ChaCha20:
// no guest pc, no workload binary and no constant from one appears here.
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
// Harness. ONE FIXED CODE BUFFER FOR EVERY ARM, for the reason Stage 2's file states: QEmit embeds
// absolute addresses, so two arms allocated at two addresses differ in immediates that have
// nothing to do with the arm under test. With one buffer a byte difference is an emitter
// difference -- which is what the no-op sections in [2] need to mean anything.
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
	u32 vlen = 1024;
	bool component_separable = true;
	bool demand_placement = false;
	bool route_falu = false;
	bool route_fma = false;
	bool route_mem = false;
	bool route_vx_mulacc = false;
	bool route_vmv = false;
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
	config::rvv_run_dep_probe_cross = false;
	config::rvv_run_scalar_passthrough = false;
	config::rvv_run_component_separable = e.component_separable;
	config::rvv_run_component_demand_placement = e.demand_placement;
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
	config::rvv_qcg_typed_chunk_fma = e.route_fma;
	config::rvv_qcg_typed_chunk_fma_force_emit = e.route_fma;
	config::rvv_qcg_typed_chunk_vmv = e.route_vmv;
	config::rvv_qcg_typed_chunk_vmv_force_emit = e.route_vmv;
	config::rvv_qcg_whole_reg = e.route_mem;
	config::rvv_qcg_whole_reg_force_emit = e.route_mem;
	config::rvv_qcg_vx_mulacc = e.route_vx_mulacc;
	config::rvv_qcg_vx_mulacc_force_emit = e.route_vx_mulacc;
	// Pinned OFF rather than left to the shipped default: each one adds a second arm or a
	// per-lane mask to the frame, and this file's subject is the placement inside the FULL body.
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

// The translated word list carries a leading `vsetvli` and the admitted one does not: the FP and
// whole-register route rows declare `requires_observed_vtype` and refuse a run formed under a shape
// nobody observed, so without this prefix those rows would translate to single-instruction frames
// and every assertion about a run's body would be vacuously true.
std::vector<u32> WithVsetvli(std::vector<u32> const &w)
{
	std::vector<u32> out;
	out.reserve(w.size() + 1);
	out.push_back(W_VSETVLI_E32M1);
	out.insert(out.end(), w.begin(), w.end());
	return out;
}

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

// BY VALUE, deliberately. `FindFrames` returns a vector, so a helper that handed back a POINTER
// into it would dangle the moment the caller wrote `Widest(FindFrames(region))` -- which every call
// site here would have. `begin == nullptr` means the region contains no frame.
Frame WidestFrame(Region *region)
{
	Frame best;
	for (auto const &f : FindFrames(region))
		if (!best.begin || f.begin->n_members > best.begin->n_members)
			best = f;
	return best;
}

u32 VregBase()
{
	return (u32)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vreg));
}
// The (register, chunk) a state access names, recovered from the SAME arithmetic
// rv32::group_chunk_state_offset performs: at LMUL = 1 a register's k chunks are k consecutive
// `stride`-byte windows inside its VLEN_MAX_BYTES slot.
u32 StateReg(u32 offs) { return (offs - VregBase()) / dbt::rv32::VLEN_MAX_BYTES; }
u32 StateChunk(u32 offs, u32 stride)
{
	return ((offs - VregBase()) % dbt::rv32::VLEN_MAX_BYTES) / stride;
}

u8 Pop(u32 m) { return (u8)__builtin_popcount(m); }

bool IsStateLoad(Inst *i) { return i->GetOpcode() == Op::_vstatechunkload; }
bool IsStateStore(Inst *i) { return i->GetOpcode() == Op::_vstatechunkstore; }
bool IsStateAccess(Inst *i) { return IsStateLoad(i) || IsStateStore(i); }
u32 AccessOffs(Inst *i)
{
	return IsStateLoad(i) ? static_cast<InstVStateChunkLoad *>(i)->offs
			      : static_cast<InstVStateChunkStore *>(i)->offs;
}

// ---------------------------------------------------------------------------------------------
// THE PROVENANCE PROGRAM: what makes "the arithmetic did not change" a CHECK.
//
// Walking the body once, every vector value gets a producer name that is independent of the SSA
// numbering the two arms happen to hand out:
//
//   state:<offs>   defined by a `vstatechunkload` of that CPUState offset
//   arith:<n>      defined by the n-th NON-state body node, counted in emission order
//
// `arith` is then the ordered list of (opcode, arity, producer of each vector input), and `stores`
// maps each stored CPUState offset to the producer of the value written there.
//
// WHY BOTH LISTS ARE NEEDED AND WHAT EACH FALSIFIES.
//   * `arith` equal element-by-element  ==>  the same lane ops in the same linear order reading the
//     same values -- so Rule L put every load in front of the right operand of the right member,
//     and nothing about the arithmetic moved. A load bound to the wrong operand, a member reordered
//     or a source re-bound after a republish all change this list.
//   * `stores` equal as a MAP (not as a sequence -- the store ORDER is exactly what the switch
//     changes)  ==>  every live-out slot receives the value the accepted body writes there. This is
//     obligation I5/I6 as a check: anchoring Rule S one member too early makes the store name an
//     earlier producer, and this comparison is the only thing in the file that would notice.
// ---------------------------------------------------------------------------------------------
struct Prov {
	int kind = -1; // -1 unknown, 0 state load, 1 non-state node
	u64 key = 0;
	bool operator==(Prov const &o) const { return kind == o.kind && key == o.key; }
	bool operator!=(Prov const &o) const { return !(*this == o); }
};
struct ArithNode {
	unsigned opcode = 0;
	unsigned arity = 0;
	std::vector<Prov> srcs;
	bool operator==(ArithNode const &o) const
	{
		return opcode == o.opcode && arity == o.arity && srcs == o.srcs;
	}
};
struct ProvProgram {
	std::vector<ArithNode> arith;
	std::map<u32, Prov> stores;
	std::vector<u32> load_offs;  // in emission order
	std::vector<u32> store_offs; // in emission order
};

ProvProgram BuildProvProgram(Frame const &f)
{
	ProvProgram p;
	std::map<unsigned, Prov> def;
	auto prov_of = [&](VOperand o) -> Prov {
		if (!o.IsVVPR())
			return Prov{};
		auto it = def.find(o.GetVVPR());
		return it == def.end() ? Prov{} : it->second;
	};
	for (auto *ins : f.body) {
		if (IsStateLoad(ins)) {
			u32 const offs = AccessOffs(ins);
			p.load_offs.push_back(offs);
			auto outs = ins->outputs();
			for (u8 j = 0; j < outs.size(); ++j)
				if (outs[j].IsVVPR())
					def[outs[j].GetVVPR()] = Prov{0, offs};
			continue;
		}
		if (IsStateStore(ins)) {
			u32 const offs = AccessOffs(ins);
			p.store_offs.push_back(offs);
			auto in = ins->inputs();
			CHECK(in.size() >= 1);
			p.stores[offs] = in.size() >= 1 ? prov_of(in[0]) : Prov{};
			continue;
		}
		ArithNode n;
		n.opcode = (unsigned)ins->GetOpcode();
		auto in = ins->inputs();
		n.arity = in.size();
		for (u8 j = 0; j < in.size(); ++j)
			if (in[j].IsVVPR())
				n.srcs.push_back(prov_of(in[j]));
		unsigned const idx = (unsigned)p.arith.size();
		auto outs = ins->outputs();
		for (u8 j = 0; j < outs.size(); ++j)
			if (outs[j].IsVVPR())
				def[outs[j].GetVVPR()] = Prov{1, idx};
		p.arith.push_back(std::move(n));
	}
	return p;
}

// Maximal consecutive-memory-instruction metrics, computed on the emitted node stream. `boundary`
// is the design's "c0 -> c1 boundary burst": the longest run of consecutive memory instructions
// that touches BOTH a component-0 and a component-1 slot, which is exactly the 33-instruction block
// the offline model measured for the accepted component-major body.
struct Bursts {
	unsigned mem = 0, load = 0, store = 0, boundary = 0;
};
Bursts MeasureBursts(Frame const &f, u32 stride)
{
	Bursts b;
	size_t i = 0;
	while (i < f.body.size()) {
		if (!IsStateAccess(f.body[i])) {
			++i;
			continue;
		}
		size_t j = i;
		unsigned run_load = 0, run_store = 0, best_load = 0, best_store = 0;
		std::set<u32> chunks;
		while (j < f.body.size() && IsStateAccess(f.body[j])) {
			chunks.insert(StateChunk(AccessOffs(f.body[j]), stride));
			if (IsStateLoad(f.body[j])) {
				run_store = 0;
				best_load = std::max(best_load, ++run_load);
			} else {
				run_load = 0;
				best_store = std::max(best_store, ++run_store);
			}
			++j;
		}
		unsigned const len = (unsigned)(j - i);
		b.mem = std::max(b.mem, len);
		b.load = std::max(b.load, best_load);
		b.store = std::max(b.store, best_store);
		if (chunks.count(0) && chunks.count(1))
			b.boundary = std::max(b.boundary, len);
		i = j;
	}
	return b;
}

// The peak number of simultaneously live V512 SSA values, from the QIR before allocation. Same
// function Stage 2's test uses, and for the same reason: the allocator's DISTINCT register count
// is an upper bound on nothing.
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
// THE SHAPE TABLE: every member class RvvRunComponentSeparable admits today, plus the operand
// overlaps and the two Mov cases the design's section 5.3 singles out as the one weakened claim.
// ---------------------------------------------------------------------------------------------
struct Shape {
	char const *name;
	std::vector<u32> words;
	Env env;
	bool expect_separable = true;
};

Env EInt()
{
	Env e;
	e.vlen = 1024;
	return e;
}
Env EFalu()
{
	Env e = EInt();
	e.route_falu = true;
	return e;
}
Env EFma()
{
	Env e = EInt();
	e.route_falu = true;
	e.route_fma = true;
	return e;
}
Env EVmv()
{
	Env e = EInt();
	e.route_vmv = true;
	return e;
}
Env EVmvF()
{
	Env e = EVmv();
	e.route_falu = true;
	return e;
}
Env EVx()
{
	Env e = EInt();
	e.route_vx_mulacc = true;
	return e;
}

std::vector<Shape> Shapes()
{
	std::vector<Shape> s;
	// Plain lane-local integer .vv, the general form of both rules.
	s.push_back({"int .vv chain",
		     {Vvv(F6_VADD, 3, 1, 2), Vvv(F6_VSUB, 4, 3, 2), Vvv(F6_VXOR, 6, 5, 4)},
		     EInt()});
	// Operand overlap: every architecturally legal one. Rule L must still bind all sources
	// before the destination is published, so each of these reads the PRE-instruction value.
	s.push_back({"overlap vd == vs2", {Vvv(F6_VADD, 3, 3, 2), Vvv(F6_VXOR, 4, 3, 2)}, EInt()});
	s.push_back({"overlap vd == vs1", {Vvv(F6_VADD, 3, 2, 3), Vvv(F6_VXOR, 4, 3, 2)}, EInt()});
	s.push_back({"overlap vd == vs1 == vs2", {Vvv(F6_VADD, 3, 3, 3), Vvv(F6_VXOR, 4, 3, 2)},
		     EInt()});
	// OPIVI: ONE vector source and an immediate. Binding cur[rs1] for one would read a
	// component the run never made live, so the shift rows keep that path honest.
	s.push_back({"OPIVI shift + or",
		     {Vvi(F6_VSLL, 4, 3, 7), Vvi(F6_VSRL, 3, 3, 25), Vvv(F6_VOR, 3, 3, 4)}, EInt()});
	// Mov, all four forms. Zero lane ops per chunk, so Rule S has no arithmetic to anchor to
	// and uses the republish instead -- the design's one weakened burst claim (section 5.3).
	s.push_back({"MOVV alias, source is a LIVE-IN",
		     {VmvVV(/*vd=*/9, /*vs1=*/8), Vvv(F6_VADD, 10, 9, 8)}, EVmv()});
	s.push_back({"MOVV self (vmv.v.v v3,v3)",
		     {Vvv(F6_VADD, 3, 1, 2), VmvVV(/*vd=*/3, /*vs1=*/3), Vvv(F6_VXOR, 4, 3, 2)},
		     EVmv()});
	s.push_back({"two adjacent MOVs, both live-out",
		     {Vvv(F6_VADD, 3, 1, 2), VmvVV(4, 3), VmvVV(5, 3), Vvv(F6_VXOR, 6, 4, 5)},
		     EVmv()});
	s.push_back({"MOV .vi (constant materialised per component)",
		     {VmvVI(/*vd=*/8, /*imm=*/5), Vvv(F6_VADD, 9, 8, 1)}, EVmv()});
	s.push_back({"MOV .vx (frame-scope GPR broadcast)",
		     {VmvVX(/*vd=*/8, /*rs1=*/11), Vvv(F6_VADD, 9, 8, 1)}, EVmv()});
	s.push_back({"MOV .vf (frame-scope F broadcast)",
		     {VfmvVF(/*vd=*/8, /*fs1=*/12), Vvv(F6_VADD, 9, 8, 1)}, EVmvF()});
	// .vx multiply and multiply-accumulate: source 1 is the frame's GPR broadcast, and MAccX
	// emits TWO lane ops per chunk, so Rule S must anchor after the SECOND.
	s.push_back({"MULX  .vx", {Vmvx(dbt::rv32::VF6_VMUL, 8, 8, 11), Vvv(F6_VADD, 9, 8, 1)},
		     EVx()});
	s.push_back({"MACCX .vx (reads_vd, two lane ops)",
		     {Vmvx(dbt::rv32::VF6_VMACC, 8, 9, 11), Vvv(F6_VADD, 10, 8, 1)}, EVx()});
	// FP: the bracket is frame-scope and must stay outside the component loop.
	// EVERY FP ROW CARRIES AN INTEGER MEMBER, and that is not decoration: both FP route rows
	// declare `partial_vl_ok`, so a pure-FP run is refused by P6. The integer member is what pins
	// the frame's guard to `vl == VLMAX` and lets the run be admitted at all.
	s.push_back({"FALU .vv",
		     {Vvv(F6_VADD, 3, 1, 2), Vfvv(F6_VFADD, 8, 8, 9), Vfvv(F6_VFSUB, 9, 8, 9)},
		     EFalu()});
	s.push_back({"FALU .vf",
		     {Vvv(F6_VADD, 3, 1, 2), Vfvf(F6_VFADD, 8, 8, /*fs1=*/12),
		      Vfvv(F6_VFSUB, 9, 8, 10)},
		     EFalu()});
	// Fused: the old vd is an ordinary THIRD vector source, so Rule L may have to load it.
	s.push_back({"FMA .vv (reads_vd)",
		     {Vvv(F6_VADD, 3, 1, 2), Vfvv(F6_VFMACC, 9, 10, 8), Vfvv(F6_VFMACC, 11, 12, 8)},
		     EFma()});
	s.push_back({"FMA .vf (reads_vd + F broadcast)",
		     {Vvv(F6_VADD, 3, 1, 2), Vfvf(F6_VFMACC, 9, 10, /*fs1=*/12),
		      Vfvv(F6_VFMACC, 11, 12, 8)},
		     EFma()});
	// The real shape this design was measured on.
	s.push_back({"ChaCha20-shaped, 60 members", ChaChaShapedWords(), EInt()});
	return s;
}

// ---------------------------------------------------------------------------------------------
// [1] The section-5.4 fail-closed precondition, by single-field descriptor mutation.
// ---------------------------------------------------------------------------------------------
void CheckLastDefAnchorPrecondition()
{
	printf("[1] Rule S's `last_def` range precondition, by descriptor mutation\n");
	Env e = EInt();
	auto const base =
	    Admit({Vvv(F6_VADD, 3, 1, 2), Vvv(F6_VSUB, 4, 3, 2), Vvv(F6_VXOR, 6, 5, 4)}, e);
	// The baseline must be an accepted component-separable run, or every row below is vacuous.
	CHECK_EQ((unsigned)base.n_members, 3u);
	CHECK_EQ((unsigned)base.nchunks, 2u);
	CHECK(base.component_separable);
	CHECK(rvvrun::RvvRunDemandStoreAnchorsValid(base));
	CHECK_EQ((unsigned)Pop(base.live_out_mask), 3u);

	// A trim that dropped a VECTOR member would leave `last_def` naming a member that no longer
	// exists. `n_members` is the field FormRun's trailing-scalar trim actually rewrites, so this
	// is the mutation that models the future change the check exists for.
	{
		auto d = base;
		d.n_members = 2;
		CHECK(!rvvrun::RvvRunDemandStoreAnchorsValid(d));
	}
	// The other direction: a live-out whose anchor was never recorded at all.
	{
		auto d = base;
		for (u32 r = 0; r < dbt::rv32::VREG_NUM; ++r)
			if (d.live_out_mask & (1u << r)) {
				d.last_def[r] = -1;
				break;
			}
		CHECK(!rvvrun::RvvRunDemandStoreAnchorsValid(d));
	}
	// NON-VACUITY OF THE MASK RESTRICTION: a stale anchor on a register that is NOT live-out is
	// not an error, because Rule S never reads it. Without this row the predicate could be
	// "no entry is ever -1", which every fresh descriptor would fail.
	{
		auto d = base;
		for (u32 r = 0; r < dbt::rv32::VREG_NUM; ++r)
			if (!(d.live_out_mask & (1u << r))) {
				d.last_def[r] = 99;
				break;
			}
		CHECK(rvvrun::RvvRunDemandStoreAnchorsValid(d));
	}
	printf("    ok  in-range accepted; trimmed n_members and an unset anchor both refused; a "
	       "stale anchor outside live_out_mask ignored\n");
}

// ---------------------------------------------------------------------------------------------
// [2] The no-op set, byte for byte.
// ---------------------------------------------------------------------------------------------
void CheckNoOpSet()
{
	printf("[2] the no-op set: host bytes byte-identical with the switch on and off\n");

	// (a) VLEN 512 -> k = 1. P1 refuses `nchunks < 2`, so no descriptor is component-separable
	//     and the demand arm is unreachable BY ADMISSION rather than by a special case.
	{
		auto const words = WithVsetvli(
		    {Vvv(F6_VADD, 3, 1, 2), Vvv(F6_VSUB, 4, 3, 2), Vvv(F6_VXOR, 6, 5, 4)});
		Env off = EInt();
		off.vlen = 512;
		Env on = off;
		on.demand_placement = true;
		auto const d = Admit({Vvv(F6_VADD, 3, 1, 2)}, off);
		CHECK_EQ((unsigned)d.nchunks, 1u);
		CHECK(!d.component_separable);
		Built b_off, b_on;
		Build(b_off, words, off, /*emit=*/false);
		Build(b_on, words, on, /*emit=*/false);
		CHECK(PrinterPass::run(b_off.region) == PrinterPass::run(b_on.region));
		auto const c_off = EmitBytes(words, off);
		auto const c_on = EmitBytes(words, on);
		CHECK(!c_off.empty());
		CHECK(c_off == c_on);
		printf("    ok  VLEN 512 (k = 1): %zu host bytes identical, QIR identical\n",
		       c_on.size());
	}
	// (b) THE BOUND-INVERSION REGIME. Four `.vx` members are LEGALLY separable, but their
	//     component-resident bound is the LARGER one (7 vs 6), so the scan declines the decision
	//     and the descriptor carries no bit. The run is formed, the frame is emitted, and the
	//     demand switch is on -- and it must still be a no-op, because it is gated on the
	//     descriptor's decision and not on the legality or on the config switch.
	//
	//     (`--rvv-run-component-separable=0` is NOT tested here: the emitter refuses that
	//     combination with demand placement on, and elfrun/elfaot refuse it at parse time. The
	//     "feature entirely off" no-op is the one the P7O-1 Stage 2 test already pins.)
	{
		std::vector<u32> const w = {Vmvx(dbt::rv32::VF6_VMUL, 8, 8, 11),
					    Vmvx(dbt::rv32::VF6_VMUL, 8, 8, 12),
					    Vmvx(dbt::rv32::VF6_VMUL, 8, 8, 13),
					    Vmvx(dbt::rv32::VF6_VMUL, 8, 8, 14)};
		Env off = EVx();
		Env on = off;
		on.demand_placement = true;
		auto const d = Admit(w, off);
		CHECK_EQ((unsigned)d.n_members, 4u);
		// Legally separable, but the decision is NO -- if this inverted, the row would be
		// testing an unreached arm.
		CHECK(rvvrun::RvvRunComponentSeparable(d));
		CHECK(!d.component_separable);
		auto const words = WithVsetvli(w);
		Built b_off, b_on;
		Build(b_off, words, off, /*emit=*/false);
		Build(b_on, words, on, /*emit=*/false);
		CHECK(PrinterPass::run(b_off.region) == PrinterPass::run(b_on.region));
		auto const c_off = EmitBytes(words, off);
		auto const c_on = EmitBytes(words, on);
		CHECK(!c_off.empty());
		CHECK(c_off == c_on);
		printf("    ok  bound-inversion run (legal, decision NO): %zu host bytes identical, "
		       "QIR identical\n",
		       c_on.size());
	}
	// (c) A run P1-P11 refuses -- a whole-register LOAD member sets `has_mem`, which P4 cuts.
	//     The run still FORMS, so this is a run the emitter sees and declines to place, not an
	//     absent frame.
	{
		std::vector<u32> const w = {VlNre32(1, /*rs1=*/14, /*vd=*/8),
					    Vvv(F6_VADD, 9, 8, 1), Vvv(F6_VXOR, 10, 9, 8)};
		Env off = EInt();
		off.route_mem = true;
		Env on = off;
		on.demand_placement = true;
		auto const d = Admit(w, off);
		CHECK(d.has_mem);
		CHECK(d.n_members >= 2);
		CHECK(!rvvrun::RvvRunComponentSeparable(d));
		CHECK(!d.component_separable);
		auto const words = WithVsetvli(w);
		Built b_off, b_on;
		Build(b_off, words, off, /*emit=*/false);
		Build(b_on, words, on, /*emit=*/false);
		CHECK(PrinterPass::run(b_off.region) == PrinterPass::run(b_on.region));
		auto const c_off = EmitBytes(words, off);
		auto const c_on = EmitBytes(words, on);
		CHECK(!c_off.empty());
		CHECK(c_off == c_on);
		printf("    ok  P4-refused run (%u members, has_mem): %zu host bytes identical\n",
		       (unsigned)d.n_members, c_on.size());
	}
}

// ---------------------------------------------------------------------------------------------
// [3] + [4] Single factor and the six placement obligations, over the whole shape table.
// ---------------------------------------------------------------------------------------------
void CheckShapes()
{
	printf("[3]+[4] single factor and obligations I1-I6, over every admitted member class\n");
	for (auto const &s : Shapes()) {
		Env off = s.env;
		off.demand_placement = false;
		Env on = off;
		on.demand_placement = true;

		auto const d = Admit(s.words, off);
		// Every row must actually be an admitted component-separable multi-member run, or
		// its assertions would pass on a frame the switch never reaches.
		CHECK(d.component_separable);
		CHECK(d.n_members >= 2);
		CHECK_EQ((unsigned)d.nchunks, 2u);
		if (!d.component_separable) {
			printf("    FAIL %s: not admitted component-separable\n", s.name);
			continue;
		}
		u8 const k = d.nchunks;
		u32 const stride = d.chunk_bytes;

		auto const words = WithVsetvli(s.words);
		Built b_off, b_on;
		Build(b_off, words, off, /*emit=*/false);
		Build(b_on, words, on, /*emit=*/false);
		Frame const w_off = WidestFrame(b_off.region);
		Frame const w_on = WidestFrame(b_on.region);
		CHECK(w_off.begin && w_on.begin);
		if (!w_off.begin || !w_on.begin)
			continue;

		// --- [3] SINGLE FACTOR ---------------------------------------------------------
		// Same run: same members, same guard, same declared typed-op window. The declared
		// count is what the guard-miss arm branches over, so an emitter that added or lost
		// one node would Panic in Emit_rvvtypedchunkend rather than reach this line -- the
		// assertion is here so the reader does not have to know that.
		CHECK_EQ((unsigned)w_on.begin->n_members, (unsigned)w_off.begin->n_members);
		CHECK_EQ((unsigned)w_on.begin->guard_kind, (unsigned)w_off.begin->guard_kind);
		CHECK_EQ((unsigned)w_on.begin->n_typed, (unsigned)w_off.begin->n_typed);
		CHECK_EQ(w_on.body.size(), w_off.body.size());

		std::map<unsigned, unsigned> h_off, h_on;
		for (auto *i : w_off.body)
			h_off[(unsigned)i->GetOpcode()]++;
		for (auto *i : w_on.body)
			h_on[(unsigned)i->GetOpcode()]++;
		CHECK(h_off == h_on);

		auto const p_off = BuildProvProgram(w_off);
		auto const p_on = BuildProvProgram(w_on);
		// THE ARITHMETIC IS THE SAME PROGRAM: same nodes, same order, same operands.
		CHECK_EQ(p_on.arith.size(), p_off.arith.size());
		bool arith_same = p_on.arith.size() == p_off.arith.size();
		for (size_t i = 0; arith_same && i < p_on.arith.size(); ++i)
			arith_same = p_on.arith[i] == p_off.arith[i];
		CHECK(arith_same);
		// I5/I6 AS A CHECK: every live-out slot receives the same produced value.
		CHECK(p_on.stores == p_off.stores);

		// State accesses are the same SET, and the same COUNT -- popcount of each mask
		// times k, exactly, so the switch neither adds nor removes a CPUState access.
		std::multiset<u32> lo_off(p_off.load_offs.begin(), p_off.load_offs.end());
		std::multiset<u32> lo_on(p_on.load_offs.begin(), p_on.load_offs.end());
		std::multiset<u32> so_off(p_off.store_offs.begin(), p_off.store_offs.end());
		std::multiset<u32> so_on(p_on.store_offs.begin(), p_on.store_offs.end());
		CHECK(lo_off == lo_on);
		CHECK(so_off == so_on);
		CHECK_EQ(p_on.load_offs.size(), (size_t)Pop(d.live_in_mask) * k);
		CHECK_EQ(p_on.store_offs.size(), (size_t)Pop(d.live_out_mask) * k);

		// --- [4] I1-I6 ON THE DEMAND ARM'S NODE STREAM ---------------------------------
		// I1 at most one load per (r, c); I2 at most one store; I3 never a load after that
		// (r, c) was stored; I4 exactly one store per live-out (r, c).
		std::map<u32, unsigned> n_load, n_store;
		std::set<u32> stored;
		bool i3 = true;
		for (auto *ins : w_on.body) {
			if (!IsStateAccess(ins))
				continue;
			u32 const offs = AccessOffs(ins);
			if (IsStateLoad(ins)) {
				n_load[offs]++;
				if (stored.count(offs))
					i3 = false;
			} else {
				n_store[offs]++;
				stored.insert(offs);
			}
		}
		bool i1 = true, i2 = true;
		for (auto const &e : n_load)
			i1 = i1 && e.second == 1;
		for (auto const &e : n_store)
			i2 = i2 && e.second == 1;
		CHECK(i1);
		CHECK(i2);
		CHECK(i3);
		unsigned i4 = 0;
		for (u32 r = 0; r < dbt::rv32::VREG_NUM; ++r) {
			if (!(d.live_out_mask & (1u << r)))
				continue;
			for (u8 c = 0; c < k; ++c) {
				u32 const offs =
				    dbt::rv32::group_chunk_state_offset(VregBase(), r, d.vlen_bits,
									stride, c);
				i4 += n_store.count(offs) == 1 && n_store[offs] == 1;
			}
		}
		CHECK_EQ(i4, (unsigned)Pop(d.live_out_mask) * k);
		// Every load names a live-in register and every store a live-out one -- the masks
		// and the emitted stream cannot disagree.
		bool masks_agree = true;
		for (auto const &e : n_load)
			masks_agree = masks_agree && (d.live_in_mask & (1u << StateReg(e.first)));
		for (auto const &e : n_store)
			masks_agree = masks_agree && (d.live_out_mask & (1u << StateReg(e.first)));
		CHECK(masks_agree);

		// --- PEAK LIVENESS: never above the accepted arm's, never above the bound -------
		unsigned const peak_off = PeakLiveV512(w_off);
		unsigned const peak_on = PeakLiveV512(w_on);
		CHECK(peak_on <= peak_off);
		CHECK(peak_on <= (unsigned)d.peak_live_bound);
		CHECK(peak_on <= (unsigned)rvvrun::kHostVectorRegs);

		Bursts const b0 = MeasureBursts(w_off, stride);
		Bursts const b1 = MeasureBursts(w_on, stride);
		printf("    ok  %-38s m=%2u typed=%3u nodes=%3zu  ld/st %zu/%zu  peak %2u->%2u "
		       "(bound %2u)  burst mem %2u->%2u ld %2u->%2u st %2u->%2u bnd %2u->%2u\n",
		       s.name, (unsigned)d.n_members, (unsigned)w_on.begin->n_typed,
		       w_on.body.size(), p_on.load_offs.size(), p_on.store_offs.size(), peak_off,
		       peak_on, (unsigned)d.peak_live_bound, b0.mem, b1.mem, b0.load, b1.load,
		       b0.store, b1.store, b0.boundary, b1.boundary);
	}
}

// ---------------------------------------------------------------------------------------------
// [5] Placement, measured against the offline model's predictions.
// ---------------------------------------------------------------------------------------------
void CheckPlacement()
{
	printf("[5] the ChaCha20-shaped frame: bursts against the offline model\n");
	auto const words = ChaChaShapedWords();
	Env off = EInt();
	Env on = off;
	on.demand_placement = true;

	auto const d = Admit(words, off);
	CHECK_EQ((unsigned)d.n_members, 60u);
	CHECK(d.component_separable);
	u32 const stride = d.chunk_bytes;
	u8 const k = d.nchunks;
	unsigned const nin = Pop(d.live_in_mask), nout = Pop(d.live_out_mask);
	// No member of this shape is a Mov, so the design's one weakened claim (section 5.3) does
	// not apply to it and the store bound below is the strict one.
	for (u8 i = 0; i < d.n_members; ++i)
		CHECK(d.members[i].op != RunOp::Mov);

	Built b_off, b_on;
	Build(b_off, WithVsetvli(words), off, /*emit=*/false);
	Build(b_on, WithVsetvli(words), on, /*emit=*/false);
	Frame const w_off = WidestFrame(b_off.region);
	Frame const w_on = WidestFrame(b_on.region);
	CHECK(w_off.begin && w_on.begin);
	if (!w_off.begin || !w_on.begin)
		return;

	Bursts const b0 = MeasureBursts(w_off, stride);
	Bursts const b1 = MeasureBursts(w_on, stride);

	// THE ACCEPTED ARM, pinned so the contrast is not against an unmeasured baseline. Pass 1
	// issues every live-in of the component back to back and pass 3 every live-out, and the two
	// blocks MEET at the component boundary -- which is the whole 33-instruction burst the
	// design set out to remove.
	CHECK_EQ(b0.load, nin);
	CHECK_EQ(b0.store, nout);
	CHECK_EQ(b0.mem, nout + nin);
	CHECK_EQ(b0.boundary, nout + nin);

	// THE DEMAND ARM, against the offline model's structural predictions:
	//   * max consecutive STORE == 1, because each member defines exactly one vd and therefore
	//     anchors at most one store (design section 3.2);
	//   * max consecutive LOAD <= the largest number of vector sources any member of this shape
	//     has, which for .vv / .vi rows is 2;
	//   * max consecutive MEMORY <= 1 + that, i.e. one anchored store followed by the next
	//     member's loads;
	//   * the c0 -> c1 boundary burst obeys the same bound instead of being |live_out| +
	//     |live_in|.
	CHECK_EQ(b1.store, 1u);
	CHECK(b1.load <= 2u);
	CHECK(b1.mem <= 3u);
	CHECK(b1.boundary <= 3u);
	CHECK(b1.mem < b0.mem);
	CHECK(b1.boundary < b0.boundary);

	// The state-access TOTAL is unchanged, which is the requirement the burst reduction had to
	// meet: this is a placement, not a rematerialisation.
	auto const p_off = BuildProvProgram(w_off);
	auto const p_on = BuildProvProgram(w_on);
	CHECK_EQ(p_on.load_offs.size(), p_off.load_offs.size());
	CHECK_EQ(p_on.store_offs.size(), p_off.store_offs.size());
	CHECK_EQ(p_on.load_offs.size() + p_on.store_offs.size(), (size_t)(nin + nout) * k);

	// NON-VACUITY: the two arms must emit DIFFERENT host bytes, or every assertion above is
	// about the same body twice.
	auto const c_off = EmitBytes(WithVsetvli(words), off);
	auto const c_on = EmitBytes(WithVsetvli(words), on);
	CHECK(c_off.size() == c_on.size());
	CHECK(c_off != c_on);

	printf("    ok  60 members, live_in %u live_out %u, k %u, %zu state accesses in both arms\n",
	       nin, nout, (unsigned)k, p_on.load_offs.size() + p_on.store_offs.size());
	printf("    ok  max consecutive  memory %2u -> %2u   load %2u -> %2u   store %2u -> %2u\n",
	       b0.mem, b1.mem, b0.load, b1.load, b0.store, b1.store);
	printf("    ok  c0 -> c1 boundary burst %u -> %u; %zu host bytes, differing\n", b0.boundary,
	       b1.boundary, c_on.size());
}

// ---------------------------------------------------------------------------------------------
// [6] Peak liveness on the frame the design measured.
// ---------------------------------------------------------------------------------------------
void CheckPeakLive()
{
	printf("[6] peak live V512 values: demand <= component-major <= the admitted bound\n");
	for (auto const &s : Shapes()) {
		Env off = s.env;
		Env on = off;
		on.demand_placement = true;
		auto const d = Admit(s.words, off);
		if (!d.component_separable)
			continue;
		Built b_off, b_on;
		Build(b_off, WithVsetvli(s.words), off, /*emit=*/false);
		Build(b_on, WithVsetvli(s.words), on, /*emit=*/false);
		Frame const w_off = WidestFrame(b_off.region);
		Frame const w_on = WidestFrame(b_on.region);
		if (!w_off.begin || !w_on.begin)
			continue;
		unsigned const p0 = PeakLiveV512(w_off), p1 = PeakLiveV512(w_on);
		u8 const bound = rvvrun::RvvRunPeakLiveBoundCS(Pop(d.touched_mask),
							      Pop(d.f_live_in_mask),
							      Pop(d.x_live_in_mask),
							      d.n_fused_members != 0);
		CHECK_EQ((unsigned)d.peak_live_bound, (unsigned)bound);
		CHECK(p1 <= p0);
		CHECK(p0 <= (unsigned)bound);
		CHECK(p1 <= (unsigned)bound);
		CHECK((unsigned)bound <= (unsigned)rvvrun::kHostVectorRegs);
	}
	// And the number the design predicted for the 60-member frame: strictly lower, not merely
	// not-higher, so "the peak falls" is falsifiable on at least one real frame.
	Env off = EInt();
	Env on = off;
	on.demand_placement = true;
	Built b_off, b_on;
	Build(b_off, WithVsetvli(ChaChaShapedWords()), off, /*emit=*/false);
	Build(b_on, WithVsetvli(ChaChaShapedWords()), on, /*emit=*/false);
	Frame const w_off = WidestFrame(b_off.region);
	Frame const w_on = WidestFrame(b_on.region);
	CHECK(w_off.begin && w_on.begin);
	if (w_off.begin && w_on.begin) {
		unsigned const p0 = PeakLiveV512(w_off), p1 = PeakLiveV512(w_on);
		auto const d = Admit(ChaChaShapedWords(), off);
		CHECK(p1 < p0);
		printf("    ok  60-member frame: peak %u -> %u against the admitted bound %u "
		       "(pool %u)\n",
		       p0, p1, (unsigned)d.peak_live_bound, (unsigned)rvvrun::kHostVectorRegs);
	}
}

// ---------------------------------------------------------------------------------------------
// [7] The FP bracket stays single and outermost; frame-scope broadcasts stay out of the loop.
// ---------------------------------------------------------------------------------------------
void CheckFrameScopeUnmoved()
{
	printf("[7] FP bracket single and outermost; frame-scope broadcasts outside the loop\n");
	struct Row {
		char const *name;
		std::vector<u32> words;
		Env env;
	};
	std::vector<Row> const rows = {
	    {"vfadd.vv + vfsub.vv",
	     {Vvv(F6_VADD, 3, 1, 2), Vfvv(F6_VFADD, 8, 8, 9), Vfvv(F6_VFSUB, 9, 8, 9)}, EFalu()},
	    {"vfadd.vf + vfsub.vv",
	     {Vvv(F6_VADD, 3, 1, 2), Vfvf(F6_VFADD, 8, 8, /*fs1=*/12), Vfvv(F6_VFSUB, 9, 8, 10)},
	     EFalu()},
	    {"vfmacc.vv x2",
	     {Vvv(F6_VADD, 3, 1, 2), Vfvv(F6_VFMACC, 9, 10, 8), Vfvv(F6_VFMACC, 11, 12, 8)},
	     EFma()},
	};
	for (auto const &r : rows) {
		Env on = r.env;
		on.demand_placement = true;
		auto const d = Admit(r.words, on);
		CHECK(d.component_separable);
		CHECK(d.needs_fp_bracket);
		Built b;
		Build(b, WithVsetvli(r.words), on, /*emit=*/false);
		Frame const w = WidestFrame(b.region);
		CHECK(w.begin != nullptr);
		if (!w.begin)
			continue;
		int begin_at = -1, end_at = -1, n_begin = 0, n_end = 0;
		int first_body = -1, last_body = -1;
		int last_bcast = -1;
		int first_state = -1;
		for (size_t i = 0; i < w.body.size(); ++i) {
			auto const op = w.body[i]->GetOpcode();
			if (op == Op::_rvvqcgfpbegin) {
				++n_begin;
				begin_at = (int)i;
				continue;
			}
			if (op == Op::_rvvqcgfpend) {
				++n_end;
				end_at = (int)i;
				continue;
			}
			if (op == Op::_vchunkfbroadcast || op == Op::_vchunkbroadcast)
				last_bcast = (int)i;
			if (IsStateAccess(w.body[i]) && first_state < 0)
				first_state = (int)i;
			if (first_body < 0)
				first_body = (int)i;
			last_body = (int)i;
		}
		// ONE bracket, and it encloses every body op -- a bracket moved inside the component
		// loop would change the ROUNDING MODE's scope, which sticky OR-accumulated fflags do
		// NOT make order-independent.
		CHECK_EQ(n_begin, 1);
		CHECK_EQ(n_end, 1);
		CHECK(begin_at >= 0 && end_at >= 0);
		CHECK(begin_at < first_body);
		CHECK(end_at > last_body);
		// The frame-scope broadcasts are created once, before any CPUState access of the
		// first component -- i.e. they did not follow the loads into the component loop.
		if (last_bcast >= 0 && first_state >= 0)
			CHECK(last_bcast < first_state);
		printf("    ok  %-22s bracket [%d, %d] around body [%d, %d]%s\n", r.name, begin_at,
		       end_at, first_body, last_body,
		       last_bcast >= 0 ? ", broadcasts before the first state access" : "");
	}
}

// ---------------------------------------------------------------------------------------------
// [8] After the real QSel + QRegAlloc.
// ---------------------------------------------------------------------------------------------
void CheckAllocatorPool()
{
	printf("[8] after QSel + QRegAlloc on the demand arm: no spill, pool not exceeded\n");
	auto const words = ChaChaShapedWords();
	Env on = EInt();
	on.demand_placement = true;

	Built b;
	Build(b, WithVsetvli(words), on, /*emit=*/false);
	qcg::MachineRegionInfo mri;
	qcg::QSelPass::run(b.region, &mri);
	qcg::QRegAllocPass::run(b.region);

	Frame const w = WidestFrame(b.region);
	CHECK(w.begin != nullptr);
	if (!w.begin)
		return;
	CHECK_EQ((unsigned)w.begin->n_members, 60u);

	unsigned movs = 0, bad_operands = 0;
	std::vector<unsigned> pregs;
	for (auto *ins : w.body) {
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
		auto in = ins->inputs();
		for (u8 i = 0; i < in.size(); ++i)
			scan(in[i]);
	}
	CHECK_EQ(movs, 0u);
	CHECK_EQ(bad_operands, 0u);
	std::sort(pregs.begin(), pregs.end());
	pregs.erase(std::unique(pregs.begin(), pregs.end()), pregs.end());
	CHECK(pregs.size() <= (size_t)qcg::ArchTraits::VPR_POOL.count());
	printf("    ok  60-member demand-placed frame: %zu distinct pool ZMMs, 0 allocator movs\n",
	       pregs.size());
}

} // namespace

int main()
{
	printf("P7O-2: demand-driven CPUState placement in the component-major vector-run body\n");
	CheckLastDefAnchorPrecondition();
	CheckNoOpSet();
	CheckShapes();
	CheckPlacement();
	CheckPeakLive();
	CheckFrameScopeUnmoved();
	CheckAllocatorPool();
	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("PASS\n");
	return 0;
}
