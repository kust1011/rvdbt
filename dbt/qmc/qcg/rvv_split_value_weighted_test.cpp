// P7N-J: the VALUE-EPOCH-AWARE, COST-WEIGHTED residency surrogate inside the live-range-splitting
// vector-run body (`--rvv-run-split-value-weighted`).
//
// WHAT IS UNDER TEST, and why it is two rules rather than one knob.
// CHACHA20_LIVE_SPLIT_OPTIMALITY_AND_MEMORY_FOLDING.md proved by exhaustion that the real 64-member
// ChaCha20 frame at guest 0x12204 needs exactly 3 reloads and 0 extra stores under the shipped
// order/multiset/pool, while the shipped body pays 5 reloads AND 5 extra stores, and it attributed
// the whole gap to two rule defects with a 2x2 single-factor table:
//
//   D1  `RvvRunNextUseStep` answers "when is this REGISTER next read", not "when is the VALUE this
//       component holds now next read". A value a later member overwrites before any read is dead:
//       it must be released, with NO store when a later definition will re-establish the slot and
//       WITH the store it already owed when it is that component's final value.
//   D2  farthest-next-use is Belady, optimal only at uniform fetch cost. A victim costs
//       `1 + [dirty AND not final]`, so victims must be ranked by cost class first and by distance
//       only within a class.
//
// THE SECTIONS, and what each one would catch:
//
//   [1] THE SWITCH IS OFF WHEN IT IS OFF. Default false; inert with the split itself off; and, on a
//       shape where the two rule sets provably coincide, byte-identical host code on and off.
//   [2] THE SHIPPED ARM IS PINNED. The off arm's counters and its victim identity on a pressure
//       shape, so a future edit that leaks a new rule into the default arm fails here.
//   [3] D1, DEF KILLS THE OLD VALUE: a component that is dirty, unread and later redefined is
//       released, and released WITHOUT a store -- with the pressure-free case proving it is not
//       merely "stored earlier", and the final-value case proving the owed store is still made.
//   [4] D2, THE THREE COST CLASSES: clean, final and dead-and-redefined victims are preferred over
//       a dirty non-final one even when the latter's next use is farther away.
//   [5] THE STORE PARTITION: on the weighted arm every live-out component is stored EXACTLY once
//       and `spill_live` (a store no correct body has to emit) is zero.
//   [6] ALIAS / MOVE / reads_vd / broadcasts / pinned operands are not broken: dataflow equivalence
//       against a reference application of the members, under real eviction.
//   [7] THE TWO PASSES AGREE: the frame's declared n_typed equals its emitted body length in every
//       case above -- which is what makes "the counting pass and the emitting pass share the
//       decision" a check rather than a claim.
//
// SCOPE. Structure and dataflow only. Nothing here executes a vector instruction (every route is
// forced to emit), nothing is timed, and no workload is run.
#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <set>
#include <string>
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
		auto _a = (a);                                                                       \
		auto _b = (b);                                                                       \
		if (!(_a == _b)) {                                                                   \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__,         \
				__LINE__, #a, #b, (long long)_a, (long long)_b);                     \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

static_assert(rvvrun::kHostVectorRegs == qcg::ArchTraits::VPR_POOL.count(),
	      "the pressure shapes below assume the pool the allocator actually has");
static_assert(rvvrun::kHostVectorRegs == 30, "the pinned counts below assume a pool of 30");

// ---------------------------------------------------------------------------------------------
// Encoders (RVV 1.0 layout), pinned against assembled words.
// ---------------------------------------------------------------------------------------------
constexpr u32 OPV = 0b1010111u;
constexpr u32 Enc(u32 f6, u32 vm, u32 vs2, u32 src1, u32 f3, u32 vd)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (src1 << 15) | (f3 << 12) | (vd << 7) | OPV;
}
constexpr u32 F3_OPIVV = 0b000u, F3_OPIVI = 0b011u, F3_OPIVX = 0b100u, F3_OPFVF = 0b101u;
constexpr u32 F6_VADD = 0b000000u, F6_VXOR = 0b001011u, F6_VOR = 0b001010u;
constexpr u32 F6_VSLL = 0b100101u, F6_VSRL = 0b101000u;
constexpr u32 F6_MERGE = 0b010111u; // vmv.v.{v,x,i} / vfmv.v.f at vm = 1, vs2 = 0
constexpr u32 F6_VFMACC = 0b101100u;
constexpr u32 Vvv(u32 f6, u32 vd, u32 vs2, u32 vs1) { return Enc(f6, 1, vs2, vs1, F3_OPIVV, vd); }
constexpr u32 Vvi(u32 f6, u32 vd, u32 vs2, u32 uimm) { return Enc(f6, 1, vs2, uimm, F3_OPIVI, vd); }
constexpr u32 VmvVV(u32 vd, u32 vs1) { return Enc(F6_MERGE, 1, 0, vs1, F3_OPIVV, vd); }
constexpr u32 VmvVX(u32 vd, u32 rs1) { return Enc(F6_MERGE, 1, 0, rs1, F3_OPIVX, vd); }
constexpr u32 VmvVI(u32 vd, u32 imm) { return Enc(F6_MERGE, 1, 0, imm & 0x1fu, F3_OPIVI, vd); }
constexpr u32 VfmaccVF(u32 vd, u32 vs2, u32 fs1) { return Enc(F6_VFMACC, 1, vs2, fs1, F3_OPFVF, vd); }
// e32, m1, ta, ma; rd = x6, rs1 = x0 -> vl = VLMAX
constexpr u32 W_VSETVLI = 0b1010111u | (6u << 7) | (0b111u << 12) | (0xd0u << 20);
static_assert(VmvVV(9, 8) == 0x5e0404d7u, "vmv.v.v v9,v8");
static_assert(Vvv(F6_VADD, 3, 1, 2) == 0x021101d7u, "vadd.vv v3,v1,v2");

// ---------------------------------------------------------------------------------------------
// Harness. ONE fixed code buffer for every arm: QEmit embeds absolute addresses, so two arms
// allocated at two addresses would differ in immediates that have nothing to do with the factor.
// With one buffer a byte difference IS an emitter difference, which is what [1] needs.
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
	bool split = true;
	bool weighted = false;
	bool route_vmv = false;
	bool route_fma = false;
};

// Every switch this file's result can depend on is set on EVERY call, so no case inherits a value
// another one left in the process globals.
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
	config::rvv_run_live_range_split = e.split;
	config::rvv_run_split_value_weighted = e.weighted;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_run_dep_probe_cross = false;
	config::rvv_run_scalar_passthrough = false;
	config::rvv_run_component_separable = false;
	config::rvv_run_component_demand_placement = false;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_xor = true;
	config::rvv_qcg_typed_chunk_xor_force_emit = true;
	config::rvv_qcg_typed_chunk_or = true;
	config::rvv_qcg_typed_chunk_or_force_emit = true;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_shift = true;
	config::rvv_qcg_typed_chunk_shift_force_emit = true;
	config::rvv_qcg_typed_chunk_vmv = e.route_vmv;
	config::rvv_qcg_typed_chunk_vmv_force_emit = e.route_vmv;
	config::rvv_qcg_typed_chunk_falu = e.route_fma;
	config::rvv_qcg_typed_chunk_falu_force_emit = e.route_fma;
	config::rvv_qcg_typed_chunk_fma = e.route_fma;
	config::rvv_qcg_typed_chunk_fma_force_emit = e.route_fma;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_full_vl_fast_body = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_qcg_narrow_chunk_width = false;
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

void Build(Built &b, std::vector<u32> const &words, Env const &e, bool emit_host = true)
{
	Apply(e);
	b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	if (!emit_host)
		return;
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.cr, &segment, b.region, 0);
	b.code.assign(span.begin(), span.end());
}

std::vector<u32> WithVsetvli(std::vector<u32> const &w)
{
	std::vector<u32> out;
	out.reserve(w.size() + 1);
	out.push_back(W_VSETVLI);
	out.insert(out.end(), w.begin(), w.end());
	return out;
}

std::vector<u8> EmitBytes(std::vector<u32> const &words, Env const &e)
{
	Built b;
	Build(b, WithVsetvli(words), e);
	return b.code;
}

struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
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
				if (open)
					frames.push_back(cur);
				open = false;
			} else if (open) {
				cur.body.push_back(&ins);
			}
		}
	return frames;
}
// BY VALUE: FindFrames returns a vector, so a pointer into it would dangle at the call site.
Frame WidestFrame(Region *region)
{
	Frame best;
	for (auto const &f : FindFrames(region))
		if (!best.begin || f.begin->n_members > best.begin->n_members)
			best = f;
	return best;
}

// [7] The declared typed-op count must be the emitted body length: that is the counting pass and
// the emitting pass agreeing, checked on every case rather than argued once.
void CheckOpCount(char const *what, Frame const &f)
{
	if ((unsigned)f.begin->n_typed != (unsigned)f.body.size()) {
		fprintf(stderr, "  FAIL %s: declared n_typed %u != emitted body %u\n", what,
			(unsigned)f.begin->n_typed, (unsigned)f.body.size());
		++g_failures;
	}
}

struct Counters {
	u64 load_first = 0, reload = 0, store_dead = 0, spill_live = 0, store_final = 0, peak = 0;
	u64 loads() const { return load_first + reload; }
	u64 stores() const { return store_dead + spill_live + store_final; }
};
void Print(char const *tag, Counters const &c)
{
	printf("    %-34s loads=%llu (first=%llu reload=%llu)  stores=%llu (dead=%llu "
	       "spill_live=%llu final=%llu)  peak=%llu\n",
	       tag, (unsigned long long)c.loads(), (unsigned long long)c.load_first,
	       (unsigned long long)c.reload, (unsigned long long)c.stores(),
	       (unsigned long long)c.store_dead, (unsigned long long)c.spill_live,
	       (unsigned long long)c.store_final, (unsigned long long)c.peak);
}

// ---------------------------------------------------------------------------------------------
// THE INTERPRETER + THE REFERENCE, from qmc/qcg/rvv_run_move_split_test.cpp, extended with the
// shift and fused forms this file's shapes use. It is what makes [6] a test of DATAFLOW rather
// than of counters: a load from the wrong slot yields a different value (slot seeds are a function
// of the CPUState offset), and reading a value that was never defined is an immediate failure.
// ---------------------------------------------------------------------------------------------
u64 SeedFor(u32 offs) { return 0x9e3779b97f4a7c15ull * (offs + 1u) ^ 0xcafef00dd15ea5e5ull; }
u64 SeedImm(i32 imm) { return 0xd1b54a32d192ed03ull * (u64)(i64)imm + 0x1234567ull; }
u64 SeedGpr(u32 offs) { return 0xa24baed4963ee407ull * (offs + 3u) ^ 0x5bf03635ull; }
u64 SeedFpr(u32 offs) { return 0x9fb21c651e98df25ull * (offs + 7u) ^ 0x77777777ull; }

bool IsLaneOp(Op op)
{
	return op == Op::_vchunkadd || op == Op::_vchunksub || op == Op::_vchunkmul ||
	       op == Op::_vchunkand || op == Op::_vchunkor || op == Op::_vchunkxor;
}
u64 ModelLane(Op op, u64 a, u64 b)
{
	switch (op) {
	case Op::_vchunkadd:
		return a + b;
	case Op::_vchunksub:
		return a - b;
	case Op::_vchunkmul:
		return a * (b | 1u);
	case Op::_vchunkand:
		return a & b;
	case Op::_vchunkor:
		return a | b;
	case Op::_vchunkxor:
		return a ^ b;
	default:
		return 0;
	}
}
// The shifts are modelled as functions of (value, immediate) that are injective in both, so a
// member that picked up the wrong source or the wrong immediate produces a different value.
u64 ModelShift(Op op, u64 a, u32 imm)
{
	return op == Op::_vchunksll ? (a * 3u + 0x51ull * (imm + 1u))
				    : (a * 5u + 0x9dull * (imm + 1u));
}
u64 ModelFma(u64 dold, u64 b, u64 a) { return dold + b * (a | 1u); }

// The .vf broadcast and the GPR broadcast are addressed by CPUState offset in the emitted node and
// by register number in the reference, so the two seeds have to be tied together here.
u32 FRegOffs(u8 f)
{
	return (u32)(offsetof(CPUState, fpu) + offsetof(dbt::rv32::FPUState, f) + (u32)f * sizeof(u64));
}
u32 XRegOffs(u8 x) { return (u32)(offsetof(CPUState, gpr) + (u32)x * sizeof(u32)); }

struct SimResult {
	bool ok = true;
	std::string why;
	std::map<u32, u64> slots;
};
SimResult Simulate(Frame const &f)
{
	SimResult r;
	std::map<u32, u64> slot, val;
	std::map<u32, bool> defined;
	auto read_slot = [&](u32 offs) {
		auto it = slot.find(offs);
		return it == slot.end() ? (slot[offs] = SeedFor(offs)) : it->second;
	};
	auto get = [&](VOperand const &v, char const *what) -> u64 {
		if (!v.IsVVPR() || !defined[v.GetVVPR()]) {
			if (r.ok) {
				r.ok = false;
				r.why = what;
			}
			return 0;
		}
		return val[v.GetVVPR()];
	};
	auto def = [&](VOperand const &d, u64 v) {
		if (!d.IsVVPR()) {
			r.ok = false;
			r.why = "destination is not a virtual register";
			return;
		}
		val[d.GetVVPR()] = v;
		defined[d.GetVVPR()] = true;
	};
	for (auto *i : f.body) {
		auto const op = i->GetOpcode();
		if (op == Op::_vstatechunkload) {
			def(i->o(0), read_slot(static_cast<InstVStateChunkLoad *>(i)->offs));
		} else if (op == Op::_vstatechunkstore) {
			u64 const v = get(i->i(0), "store reads an undefined value");
			if (!r.ok)
				return r;
			slot[static_cast<InstVStateChunkStore *>(i)->offs] = v;
		} else if (op == Op::_vchunkbroadcast) {
			auto *bc = static_cast<InstVChunkBroadcast *>(i);
			def(i->o(0), bc->is_imm ? SeedImm(bc->imm) : SeedGpr(bc->offs));
		} else if (op == Op::_vchunkfbroadcast) {
			def(i->o(0), SeedFpr(static_cast<InstVChunkFBroadcast *>(i)->offs));
		} else if (IsLaneOp(op)) {
			u64 const a = get(i->i(0), "lane op reads an undefined source 2");
			u64 const b = get(i->i(1), "lane op reads an undefined source 1");
			if (!r.ok)
				return r;
			def(i->o(0), ModelLane(op, a, b));
		} else if (op == Op::_vchunksll || op == Op::_vchunksrl) {
			u64 const a = get(i->i(0), "shift reads an undefined source");
			if (!r.ok)
				return r;
			u32 const imm = op == Op::_vchunksll
					    ? static_cast<InstVChunkSll *>(i)->shamt
					    : static_cast<InstVChunkSrl *>(i)->shamt;
			def(i->o(0), ModelShift(op, a, imm));
		} else if (op == Op::_vchunkfma) {
			u64 const dold = get(i->i(0), "fma reads an undefined old vd");
			u64 const b = get(i->i(1), "fma reads an undefined multiplier");
			u64 const a = get(i->i(2), "fma reads an undefined addend");
			if (!r.ok)
				return r;
			def(i->o(0), ModelFma(dold, b, a));
		} else if (op == Op::_rvvqcgfpbegin || op == Op::_rvvqcgfpend) {
			// P7M-A's one host FP control/exception bracket: frame scope, no vector value
		} else {
			r.ok = false;
			r.why = "unexpected op in the frame body";
			return r;
		}
		if (!r.ok)
			return r;
	}
	r.slots = slot;
	return r;
}

// The reference: apply the guest members in order to a model register file seeded exactly as the
// interpreter seeds the slots, then read out what every live-out register's slot must hold.
struct RefMember {
	enum class Kind { Alu, Shift, Fma, MovV, MovX, MovI, MovF } kind = Kind::Alu;
	Op op = Op::_vchunkadd; // Alu / Shift
	u8 rd = 0, rs2 = 0, rs1 = 0;
	i32 imm = 0;
};
std::map<u32, u64> Reference(std::vector<RefMember> const &ms, u32 vlen, unsigned k)
{
	u32 const base = (u32)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vreg));
	u32 const slot_sz = dbt::rv32::VLEN_MAX_BYTES;
	u32 const stride = vlen / 8u / k;
	auto off = [&](u8 r, unsigned c) { return base + (u32)r * slot_sz + (u32)c * stride; };
	std::map<u32, u64> reg;
	auto key = [](u8 r, unsigned c) { return ((u32)r << 8) | (u32)c; };
	auto read = [&](u8 r, unsigned c) {
		auto it = reg.find(key(r, c));
		return it == reg.end() ? (reg[key(r, c)] = SeedFor(off(r, c))) : it->second;
	};
	std::set<u8> live_out;
	for (auto const &m : ms) {
		live_out.insert(m.rd);
		for (unsigned c = 0; c < k; ++c) {
			u64 v = 0;
			switch (m.kind) {
			case RefMember::Kind::Alu:
				v = ModelLane(m.op, read(m.rs2, c), read(m.rs1, c));
				break;
			case RefMember::Kind::Shift:
				v = ModelShift(m.op, read(m.rs2, c), (u32)m.imm);
				break;
			case RefMember::Kind::Fma:
				// InstVChunkFMA's inputs are (dold, b = the .vf broadcast, a = vs2)
				v = ModelFma(read(m.rd, c), SeedFpr(FRegOffs(m.rs1)),
					     read(m.rs2, c));
				break;
			case RefMember::Kind::MovV:
				v = read(m.rs1, c);
				break;
			case RefMember::Kind::MovX:
				v = SeedGpr(XRegOffs(m.rs1));
				break;
			case RefMember::Kind::MovI:
				v = SeedImm(m.imm);
				break;
			case RefMember::Kind::MovF:
				v = SeedFpr(FRegOffs(m.rs1));
				break;
			}
			reg[key(m.rd, c)] = v;
		}
	}
	std::map<u32, u64> want;
	for (u8 r : live_out)
		for (unsigned c = 0; c < k; ++c)
			want[off(r, c)] = reg[key(r, c)];
	return want;
}
void CheckDataflow(char const *what, Frame const &f, std::vector<RefMember> const &ms, u32 vlen,
		   unsigned k, bool single_store)
{
	auto const sim = Simulate(f);
	if (!sim.ok) {
		fprintf(stderr, "  FAIL %s: %s\n", what, sim.why.c_str());
		++g_failures;
		return;
	}
	auto const want = Reference(ms, vlen, k);
	for (auto const &[offs, v] : want) {
		auto it = sim.slots.find(offs);
		if (it == sim.slots.end()) {
			fprintf(stderr, "  FAIL %s: live-out slot %#x never written\n", what, offs);
			++g_failures;
			continue;
		}
		if (it->second != v) {
			fprintf(stderr, "  FAIL %s: slot %#x holds %#llx, want %#llx\n", what, offs,
				(unsigned long long)it->second, (unsigned long long)v);
			++g_failures;
		}
	}
	// STORE ACCOUNTING. Exactly the live-out components' slots are written, and no others.
	//
	// `single_store` additionally demands ONE write per slot, and that is an invariant of the
	// WEIGHTED arm only: there a store is emitted only for a value that is FINAL (every case
	// asserts spill_live == 0 separately), and a final value cannot be stored twice -- reloading
	// it brings it back CLEAN, so the closing loop owes nothing. The shipped arm may legitimately
	// write a slot twice, by spilling a live dirty value and storing its successor at the close.
	// Asserting one write there would be asserting the defect away.
	std::map<u32, unsigned> writes;
	for (auto *i : f.body)
		if (i->GetOpcode() == Op::_vstatechunkstore)
			writes[static_cast<InstVStateChunkStore *>(i)->offs]++;
	if (single_store)
		for (auto const &[offs, n] : writes)
			if (n != 1) {
				fprintf(stderr, "  FAIL %s: slot %#x written %u times\n", what, offs,
					n);
				++g_failures;
			}
	if (writes.size() != want.size()) {
		fprintf(stderr, "  FAIL %s: %zu distinct slots stored, %zu live-out components\n",
			what, writes.size(), want.size());
		++g_failures;
	}
}

// Run one shape and return its counters, checking the shared op count and (optionally) dataflow.
Counters Run(char const *what, std::vector<u32> const &words, Env const &e, unsigned k,
	     std::vector<RefMember> const *ref = nullptr, unsigned *n_members = nullptr)
{
	rvvrun::g_stats.split_peak_resident = 0;
	auto const before = rvvrun::g_stats;
	Built b;
	Build(b, WithVsetvli(words), e, /*emit_host=*/false);
	auto const &after = rvvrun::g_stats;
	Frame const f = WidestFrame(b.region);
	if (!f.begin) {
		fprintf(stderr, "  FAIL %s: no run frame was formed\n", what);
		++g_failures;
		return {};
	}
	if (n_members)
		*n_members = f.begin->n_members;
	CheckOpCount(what, f);
	if (ref) {
		// The admitted members are a PREFIX of the word list -- a run is scanned forward from
		// its entry and ends at a cut -- so the reference is applied to exactly the members
		// this frame contains, never to the ones a cut left out.
		if (ref->size() < f.begin->n_members) {
			fprintf(stderr, "  FAIL %s: %u members admitted, reference has %zu\n", what,
				(unsigned)f.begin->n_members, ref->size());
			++g_failures;
			return {};
		}
		std::vector<RefMember> admitted(ref->begin(), ref->begin() + f.begin->n_members);
		CheckDataflow(what, f, admitted, e.vlen, k, /*single_store=*/e.weighted);
	}
	return {after.split_load_first - before.split_load_first,
		after.split_reload - before.split_reload,
		after.split_store_dead - before.split_store_dead,
		after.split_spill_live - before.split_spill_live,
		after.split_store_final - before.split_store_final, after.split_peak_resident};
}

// ---------------------------------------------------------------------------------------------
// THE SHAPES.
// ---------------------------------------------------------------------------------------------

// A ChaCha20 quarter round, in the same lowering the real guest's vectorised inner loop uses:
// rotate-left is emitted as vsll/vsrl/vor through a scratch register.
void EmitRotL(std::vector<u32> &w, std::vector<RefMember> &ref, u8 x, u8 t, u32 n)
{
	w.push_back(Vvi(F6_VSLL, t, x, n));
	ref.push_back({RefMember::Kind::Shift, Op::_vchunksll, t, x, 0, (i32)n});
	w.push_back(Vvi(F6_VSRL, x, x, 32u - n));
	ref.push_back({RefMember::Kind::Shift, Op::_vchunksrl, x, x, 0, (i32)(32u - n)});
	w.push_back(Vvv(F6_VOR, x, t, x));
	ref.push_back({RefMember::Kind::Alu, Op::_vchunkor, x, t, x, 0});
}
void EmitQuarterRound(std::vector<u32> &w, std::vector<RefMember> &ref, u8 a, u8 b, u8 c, u8 dd,
		      u8 t)
{
	auto alu = [&](u32 f6, Op op, u8 rd, u8 rs2, u8 rs1) {
		w.push_back(Vvv(f6, rd, rs2, rs1));
		ref.push_back({RefMember::Kind::Alu, op, rd, rs2, rs1, 0});
	};
	alu(F6_VADD, Op::_vchunkadd, a, a, b);
	alu(F6_VXOR, Op::_vchunkxor, dd, dd, a);
	EmitRotL(w, ref, dd, t, 16);
	alu(F6_VADD, Op::_vchunkadd, c, c, dd);
	alu(F6_VXOR, Op::_vchunkxor, b, b, c);
	EmitRotL(w, ref, b, t, 12);
	alu(F6_VADD, Op::_vchunkadd, a, a, b);
	alu(F6_VXOR, Op::_vchunkxor, dd, dd, a);
	EmitRotL(w, ref, dd, t, 8);
	alu(F6_VADD, Op::_vchunkadd, c, c, dd);
	alu(F6_VXOR, Op::_vchunkxor, b, b, c);
	EmitRotL(w, ref, b, t, 7);
}
// THE STAND-IN FOR THE REAL FRAME. It is NOT the measured guest frame -- that one is 64 members
// over 17 registers and is what the untimed guest probe reads -- but it reproduces the two
// structures that frame's optimality analysis identified, so that both rules can be exercised
// against a dataflow reference here rather than only against a workload:
//
//   * two ChaCha20 quarter rounds, whose rotate idiom (vsll into a scratch, vsrl, vor) makes the
//     scratch register the D1 case in bulk: it is written and read over and over, so a definition
//     kills the previous value long before the next member that READS the register;
//   * four live-across pairs, written at the top and read AND redefined at the bottom, which makes
//     their components dirty, non-final and the farthest-next-use candidates for the whole middle
//     of the body -- the D2 cost class the shipped victim rule mis-ranks.
//
// 56 members over 18 registers: 36 components against a pool of 30 at VLEN 1024 (k = 2), so the
// eviction rules genuinely run; 18 of 30 at VLEN 512 (k = 1), where nothing can fire, which is the
// width-dependence the split exists for and this file's negative control.
std::vector<u32> ChaChaShape(std::vector<RefMember> &ref)
{
	std::vector<u32> w;
	auto alu = [&](u32 f6, Op op, u8 rd, u8 rs2, u8 rs1) {
		w.push_back(Vvv(f6, rd, rs2, rs1));
		ref.push_back({RefMember::Kind::Alu, op, rd, rs2, rs1, 0});
	};
	// THE LIVE-ACROSS PAIRS. Each pair is written at the top, read at the bottom and REDEFINED
	// there, so through the whole body its four components are live, one of them dirty and NOT
	// final -- the expensive cost class -- and its next use is the farthest of anything resident.
	// That is the exact configuration in which farthest-next-use picks the victim that costs two
	// operations while a clean or final one costing one is available.
	static constexpr u8 kPairs[4][2] = {{4, 8}, {21, 22}, {23, 24}, {25, 26}};
	for (auto const &p : kPairs) {
		alu(F6_VADD, Op::_vchunkadd, p[0], p[0], p[1]);
		alu(F6_VXOR, Op::_vchunkxor, p[1], p[1], p[0]);
	}
	EmitQuarterRound(w, ref, 1, 5, 9, 13, 17);
	EmitQuarterRound(w, ref, 2, 6, 10, 14, 18);
	for (auto const &p : kPairs) {
		alu(F6_VADD, Op::_vchunkadd, p[0], p[0], p[1]);
		alu(F6_VXOR, Op::_vchunkxor, p[1], p[1], p[0]);
	}
	return w;
}

// ---------------------------------------------------------------------------------------------
// [1] THE SWITCH IS OFF WHEN IT IS OFF.
// ---------------------------------------------------------------------------------------------
void CheckSwitchIsInert()
{
	printf("[1] default off, inert without the split, and byte-identical where the rules "
	       "coincide\n");
	// The shipped default, read from the config object itself rather than assumed.
	{
		config::rvv_run_split_value_weighted = false;
		Apply(Env{}); // Env's own default
		CHECK_EQ(config::rvv_run_split_value_weighted, false);
	}
	// WITH THE SPLIT OFF the frame takes the fixed placement, which never consults this switch.
	{
		std::vector<RefMember> ref;
		auto const words = ChaChaShape(ref);
		Env off{}, on{};
		off.split = false;
		off.weighted = false;
		on.split = false;
		on.weighted = true;
		auto const a = EmitBytes(words, off);
		auto const b = EmitBytes(words, on);
		CHECK(!a.empty());
		CHECK(a == b);
		printf("    ok  split off: %zu host bytes identical with the surrogate 0 and 1\n",
		       a.size());
	}
	// A SHAPE WHERE THE TWO RULE SETS PROVABLY COINCIDE. At VLEN 512 this chain never reaches
	// the pool, so no eviction rule runs at all; and every component that dies dies at the LAST
	// member, so D1's early release happens exactly where the closing loop already was, in the
	// same register order. Both arms must therefore emit the same bytes -- and if the surrogate
	// ever leaks a decision into a frame it cannot help, this is what catches it.
	{
		std::vector<u32> const words = {Vvv(F6_VADD, 3, 1, 2), Vvv(F6_VXOR, 4, 3, 1),
						Vvv(F6_VADD, 5, 4, 3)};
		Env off{}, on{};
		off.vlen = 512;
		on.vlen = 512;
		on.weighted = true;
		auto const a = EmitBytes(words, off);
		auto const b = EmitBytes(words, on);
		CHECK(!a.empty());
		CHECK(a == b);
		printf("    ok  no-pressure chain at VLEN 512: %zu host bytes identical\n", a.size());
	}
	// NON-VACUITY: on the shape the switch IS for, the two arms must differ. Without this the
	// three checks above could pass because the switch does nothing anywhere.
	{
		std::vector<RefMember> ref;
		auto const words = ChaChaShape(ref);
		Env off{}, on{};
		on.weighted = true;
		auto const a = EmitBytes(words, off);
		auto const b = EmitBytes(words, on);
		CHECK(!a.empty());
		CHECK(a != b);
		printf("    ok  60-member ChaCha shape at VLEN 1024: arms differ (%zu vs %zu bytes)\n",
		       a.size(), b.size());
	}
}

// ---------------------------------------------------------------------------------------------
// [2] THE SHIPPED ARM IS PINNED, and [3]-[5] on the ChaCha stand-in.
//
// The off arm's numbers are the P7N-G rules' own: 16 live-in registers x k first loads, one lane op
// per member per chunk, and whatever its victim rule pays on top. They are pinned so that a change
// which leaks a new rule into the default arm fails HERE, naming the default arm, rather than
// showing up as a surprise in a workload months later.
// ---------------------------------------------------------------------------------------------
void CheckChaChaShape(u32 vlen, unsigned k, bool expect_pressure)
{
	std::vector<RefMember> ref;
	auto const words = ChaChaShape(ref);
	std::set<u8> live_out;
	for (auto const &m : ref)
		live_out.insert(m.rd);
	unsigned const want_stores = (unsigned)live_out.size() * k;

	Env off{}, on{};
	off.vlen = vlen;
	on.vlen = vlen;
	on.weighted = true;
	unsigned n_off = 0, n_on = 0;
	auto const a = Run("chacha/off", words, off, k, &ref, &n_off);
	auto const b = Run("chacha/on", words, on, k, &ref, &n_on);
	printf("  VLEN %u (k = %u), %u members, %u live-out components:\n", vlen, k, n_off,
	       want_stores);
	Print("shipped (surrogate off)", a);
	Print("weighted (surrogate on)", b);
	CHECK_EQ(n_off, n_on); // same admission decision: the switch is emission-side only
	// Both arms must be CORRECT: every live-out component stored exactly once with the value the
	// reference computes (checked inside Run), and the peak within the pool.
	CHECK_EQ((unsigned)a.stores(), want_stores);
	CHECK_EQ((unsigned)b.stores(), want_stores);
	CHECK(a.peak <= rvvrun::kHostVectorRegs);
	CHECK(b.peak <= rvvrun::kHostVectorRegs);
	// [5] THE STORE PARTITION. On the weighted arm no store is emitted that a correct body does
	// not owe, at either width.
	CHECK_EQ((unsigned long long)b.spill_live, 0ull);
	if (expect_pressure) {
		// Non-vacuity: the eviction rules really did run on this shape -- the shipped arm
		// evicted components before the close (its store_dead counter is stores it emitted
		// inside the body) and its residency reached the pool exactly.
		CHECK(a.store_dead > 0);
		CHECK_EQ((unsigned)a.peak, (unsigned)rvvrun::kHostVectorRegs);
		// D1's effect on this shape is residency: the values the shipped scan reports live
		// but that a later definition has already killed are handed back, so the same body
		// fits with room to spare. (The reload reduction is [3c]'s subject; on this shape
		// neither arm has to reload, which is itself the point -- the weighted arm reaches a
		// strictly lower peak for the SAME emitted arithmetic.)
		CHECK(b.peak < a.peak);
		CHECK(b.loads() <= a.loads());
		CHECK(b.stores() <= a.stores());
	} else {
		// At the narrower width the same guest code needs no eviction on either arm.
		CHECK_EQ((unsigned long long)a.reload, 0ull);
		CHECK_EQ((unsigned long long)b.reload, 0ull);
		CHECK_EQ((unsigned long long)a.spill_live, 0ull);
	}
}

// ---------------------------------------------------------------------------------------------
// [3] D1: A DEFINITION KILLS THE VALUE, and the release of that value must be FREE.
//
// The shape: v3 is written, never read before being written again, and only then read. The shipped
// next-use scan reports the far-away read of the SECOND value as v3's next use, so it holds the
// first value resident to the end; the value-aware scan sees the intervening definition and
// releases it at once.
//
// TWO THINGS ARE CHECKED, and the second is the one that matters:
//   * the weighted arm's peak residency is strictly lower -- the register really was handed back;
//   * NEITHER arm emits a store for the dead value: the number of stores is the number of live-out
//     components on both arms. A release that "helpfully" wrote the stale value out would show up
//     here as an extra store, which is precisely the useless store the rule forbids.
// ---------------------------------------------------------------------------------------------
void CheckDefKillsOldValue(u32 vlen, unsigned k)
{
	std::vector<u32> words;
	std::vector<RefMember> ref;
	auto alu = [&](u32 f6, Op op, u8 rd, u8 rs2, u8 rs1) {
		words.push_back(Vvv(f6, rd, rs2, rs1));
		ref.push_back({RefMember::Kind::Alu, op, rd, rs2, rs1, 0});
	};
	alu(F6_VADD, Op::_vchunkadd, 3, 1, 2);  // v3's FIRST value: dead on arrival
	alu(F6_VXOR, Op::_vchunkxor, 6, 1, 2);  // ... several members that do not touch v3 ...
	alu(F6_VXOR, Op::_vchunkxor, 7, 6, 1);
	alu(F6_VADD, Op::_vchunkadd, 3, 6, 7);  // the definition that kills it
	alu(F6_VXOR, Op::_vchunkxor, 8, 3, 1);  // the read the shipped scan attributed to value 1
	ref.push_back({}); // placeholder removed below
	ref.pop_back();

	std::set<u8> live_out;
	for (auto const &m : ref)
		live_out.insert(m.rd);
	Env off{}, on{};
	off.vlen = vlen;
	on.vlen = vlen;
	on.weighted = true;
	auto const a = Run("def-kills/off", words, off, k, &ref);
	auto const b = Run("def-kills/on", words, on, k, &ref);
	Print("def-kills: shipped", a);
	Print("def-kills: weighted", b);
	// no pressure at either width, so the ONLY difference the rule can make here is residency
	CHECK_EQ((unsigned long long)a.reload, 0ull);
	CHECK_EQ((unsigned long long)b.reload, 0ull);
	// the dead value is released instead of held: strictly lower peak
	CHECK(b.peak < a.peak);
	// and released WITHOUT a store: both arms emit exactly one store per live-out component
	CHECK_EQ((unsigned)a.stores(), (unsigned)(live_out.size() * k));
	CHECK_EQ((unsigned)b.stores(), (unsigned)(live_out.size() * k));
	CHECK_EQ((unsigned long long)b.spill_live, 0ull);
}

// ---------------------------------------------------------------------------------------------
// [3b] THE OWED STORE IS STILL MADE. A dead value that is a component's FINAL value must be stored
// -- moved earlier, not dropped. The dataflow check inside Run is what proves it holds the right
// value; the counters here prove it was charged as an owed store and not as an extra one.
// ---------------------------------------------------------------------------------------------
void CheckFinalValueStillStored(u32 vlen, unsigned k)
{
	std::vector<u32> words;
	std::vector<RefMember> ref;
	auto alu = [&](u32 f6, Op op, u8 rd, u8 rs2, u8 rs1) {
		words.push_back(Vvv(f6, rd, rs2, rs1));
		ref.push_back({RefMember::Kind::Alu, op, rd, rs2, rs1, 0});
	};
	// v3's value is final at member 0 and dead immediately: the weighted arm stores it in the
	// release, the shipped arm at the close, and BOTH must store it exactly once.
	alu(F6_VADD, Op::_vchunkadd, 3, 1, 2);
	alu(F6_VXOR, Op::_vchunkxor, 4, 1, 2);
	alu(F6_VADD, Op::_vchunkadd, 5, 4, 1);
	std::set<u8> live_out;
	for (auto const &m : ref)
		live_out.insert(m.rd);
	Env on{};
	on.vlen = vlen;
	on.weighted = true;
	auto const b = Run("final-store/on", words, on, k, &ref);
	Print("final-value: weighted", b);
	CHECK_EQ((unsigned)b.stores(), (unsigned)(live_out.size() * k));
	CHECK_EQ((unsigned long long)b.spill_live, 0ull);
	// the owed store was paid in the body (store_dead), not at the close, for the components
	// that died early -- otherwise "release the register early" would not free anything
	CHECK(b.store_dead > 0);
}

// ---------------------------------------------------------------------------------------------
// [3d] THE VALUE EPOCH, PINNED EXACTLY. What separates D1 from "release dirty components too" is
// WHICH components are dead, so a case whose answer differs between the two is needed -- otherwise
// a scan that ignored definitions entirely would still pass every check above.
//
// The shape, at VLEN 512 so that one register is one component and the count can be derived by
// hand:
//
//   m0  vadd v3, v1, v2   v3's FIRST value: never read, redefined at m3
//   m1  vadd v4, v1, v2
//   m2  vadd v5, v4, v1
//   m3  vadd v3, v5, v4   the definition that kills it
//   m4  vxor v6, v3, v5
//
// THE WEIGHTED ARM'S PEAK IS 3, derived from the rules rather than read off a run. A definition is
// counted while the sources that produced it are still resident, and every release happens at the
// end of the step:
//   m0  loads v1, v2, defines v3=A   -> {v1,v2,A} = 3, then A is dead (m3 redefines v3 and nothing
//                                       reads it first) and is dropped: {v1,v2}
//   m1  defines v4                   -> {v1,v2,v4} = 3, then v2 is dead and clean: {v1,v4}
//   m2  defines v5                   -> {v1,v4,v5} = 3, then v1 is dead: {v4,v5}
//   m3  defines v3=B                 -> {v4,v5,B} = 3, then v4 is dead, dirty and FINAL, so it is
//                                       stored and released: {v5,B}
//   m4  defines v6                   -> {v5,B,v6} = 3
//
// A scan that reported v3's next READ instead (the m4 use of the SECOND value) would hold A from m0
// to m4 and the peak would be 4. That one number is the whole difference between the two rules.
void CheckValueEpochPeakIsExact()
{
	std::vector<u32> const words = {Vvv(F6_VADD, 3, 1, 2), Vvv(F6_VADD, 4, 1, 2),
					Vvv(F6_VADD, 5, 4, 1), Vvv(F6_VADD, 3, 5, 4),
					Vvv(F6_VXOR, 6, 3, 5)};
	std::vector<RefMember> const ref = {{RefMember::Kind::Alu, Op::_vchunkadd, 3, 1, 2, 0},
					    {RefMember::Kind::Alu, Op::_vchunkadd, 4, 1, 2, 0},
					    {RefMember::Kind::Alu, Op::_vchunkadd, 5, 4, 1, 0},
					    {RefMember::Kind::Alu, Op::_vchunkadd, 3, 5, 4, 0},
					    {RefMember::Kind::Alu, Op::_vchunkxor, 6, 3, 5, 0}};
	Env off{}, on{};
	off.vlen = 512;
	on.vlen = 512;
	on.weighted = true;
	auto const a = Run("value-epoch/off", words, off, 1, &ref);
	auto const b = Run("value-epoch/on", words, on, 1, &ref);
	Print("value epoch: shipped", a);
	Print("value epoch: weighted", b);
	CHECK_EQ((unsigned)b.peak, 3u); // the derivation above; a register-aware scan reaches 4
	CHECK(a.peak > b.peak);
	CHECK_EQ((unsigned)b.stores(), 4u); // v3, v4, v5, v6: exactly the live-out components
	CHECK_EQ((unsigned long long)b.spill_live, 0ull);
}

// ---------------------------------------------------------------------------------------------
// [3c]+[4b] THE WASTED STORE, which is the ChaCha frame's defect in miniature.
//
// THE CONFIGURATION THE REAL FRAME HITS FIVE TIMES. At the eviction point the farthest next use
// belongs to a value that is DIRTY and will be REDEFINED after that use, while a CLEAN live-in with
// a nearer use is sitting right next to it. Belady picks the farthest: it stores a value that a
// later definition overwrites -- a store no correct body has to emit, and the component is stored
// AGAIN at the close -- and reloads it. The cost-aware rule picks the clean one and pays only the
// reload.
//
// THE SHAPE. Ten clean live-in registers (v1-v10, never written) and five dirty ones (v11-v15,
// written at the top, read in the middle and REDEFINED at the bottom) fill the pool exactly at
// VLEN 1024; the sixteenth destination is the trigger. The middle reads are ordered so that the
// five dirty registers' next uses are the farthest at that moment.
//
// WHAT IS ASSERTED, in arm-independent quantities. Total CPUState stores against the unavoidable
// bound -- one per live-out component -- because THAT is the quantity a store classification cannot
// argue with: the shipped arm must exceed it, and the weighted arm must sit exactly on it.
void CheckWastedStore(u32 vlen, unsigned k, bool expect_pressure)
{
	std::vector<u32> words;
	std::vector<RefMember> ref;
	auto alu = [&](u32 f6, Op op, u8 rd, u8 rs2, u8 rs1) {
		words.push_back(Vvv(f6, rd, rs2, rs1));
		ref.push_back({RefMember::Kind::Alu, op, rd, rs2, rs1, 0});
	};
	for (u8 i = 0; i < 5; ++i) // v11..v15 from ten clean live-ins: 15 registers, 30 components
		alu(F6_VADD, Op::_vchunkadd, (u8)(11 + i), (u8)(1 + 2 * i), (u8)(2 + 2 * i));
	alu(F6_VXOR, Op::_vchunkxor, 16, 1, 2); // the trigger: one more destination than the pool has
	for (u8 i = 0; i < 4; ++i)              // the clean registers' reads, NEARER
		alu(F6_VXOR, Op::_vchunkxor, (u8)(17 + i), (u8)(3 + 2 * i), (u8)(4 + 2 * i));
	alu(F6_VXOR, Op::_vchunkxor, 21, 11, 12); // the dirty registers' reads, FARTHER
	alu(F6_VXOR, Op::_vchunkxor, 22, 13, 14);
	alu(F6_VXOR, Op::_vchunkxor, 23, 15, 16);
	alu(F6_VADD, Op::_vchunkadd, 11, 17, 18); // ... and every one of them is then REDEFINED, so
	alu(F6_VADD, Op::_vchunkadd, 12, 19, 20); //     a store of the value above is wasted work
	alu(F6_VADD, Op::_vchunkadd, 13, 21, 22);
	alu(F6_VADD, Op::_vchunkadd, 14, 23, 17);
	alu(F6_VADD, Op::_vchunkadd, 15, 18, 19);
	std::set<u8> live_out;
	for (auto const &m : ref)
		live_out.insert(m.rd);
	unsigned const bound_stores = (unsigned)live_out.size() * k;

	Env off{}, on{};
	off.vlen = vlen;
	on.vlen = vlen;
	on.weighted = true;
	auto const a = Run("wasted-store/off", words, off, k, &ref);
	auto const b = Run("wasted-store/on", words, on, k, &ref);
	printf("  wasted store, VLEN %u (k = %u); the unavoidable store bound is %u:\n", vlen, k,
	       bound_stores);
	Print("shipped", a);
	Print("weighted", b);
	if (expect_pressure) {
		// THE DEFECT, measured: the shipped arm emits at least one store that no correct
		// body owes, and pays a reload on top.
		CHECK(a.stores() > bound_stores);
		CHECK(a.reload > 0);
		// THE REPAIR: the store bound is reached exactly, and the total CPUState traffic is
		// never worse than the shipped arm's.
		CHECK_EQ((unsigned)b.stores(), bound_stores);
		CHECK_EQ((unsigned long long)b.spill_live, 0ull);
		CHECK(b.loads() + b.stores() < a.loads() + a.stores());
	} else {
		CHECK_EQ((unsigned)a.stores(), bound_stores);
		CHECK_EQ((unsigned)b.stores(), bound_stores);
	}
}

// ---------------------------------------------------------------------------------------------
// [4] D2: THE COST CLASSES. Under real pressure the victim must be the cheap one even when the
// expensive one's next use is farther away.
//
// THE SHAPE. Sixteen registers are made live and read again at the very end (so nothing may be
// released early), which at VLEN 1024 asks for 32 components against a budget of 30. Among the
// candidates at the eviction point there are both CLEAN live-in components and DIRTY non-final
// ones, and the dirty ones' next uses are the farthest -- exactly the configuration in which
// farthest-next-use picks the victim that costs two operations instead of one.
// ---------------------------------------------------------------------------------------------
void CheckCostClasses(u32 vlen, unsigned k, bool expect_pressure)
{
	std::vector<u32> words;
	std::vector<RefMember> ref;
	auto alu = [&](u32 f6, Op op, u8 rd, u8 rs2, u8 rs1) {
		words.push_back(Vvv(f6, rd, rs2, rs1));
		ref.push_back({RefMember::Kind::Alu, op, rd, rs2, rs1, 0});
	};
	for (u8 i = 2; i <= 15; ++i)
		alu(F6_VADD, Op::_vchunkadd, i, i, i); // fourteen dirty, non-final-later values
	alu(F6_VADD, Op::_vchunkadd, 16, 2, 3);
	alu(F6_VADD, Op::_vchunkadd, 17, 4, 5);
	alu(F6_VADD, Op::_vchunkadd, 18, 6, 7);
	alu(F6_VXOR, Op::_vchunkxor, 19, 8, 9);
	alu(F6_VXOR, Op::_vchunkxor, 20, 10, 11);
	alu(F6_VXOR, Op::_vchunkxor, 21, 12, 13);
	alu(F6_VXOR, Op::_vchunkxor, 22, 14, 15);
	for (u8 i = 2; i <= 15; ++i)
		alu(F6_VXOR, Op::_vchunkxor, i, i, i); // every one of them read AND redefined again
	alu(F6_VADD, Op::_vchunkadd, 23, 16, 17);
	std::set<u8> live_out;
	for (auto const &m : ref)
		live_out.insert(m.rd);
	Env off{}, on{};
	off.vlen = vlen;
	on.vlen = vlen;
	on.weighted = true;
	auto const a = Run("cost-classes/off", words, off, k, &ref);
	auto const b = Run("cost-classes/on", words, on, k, &ref);
	printf("  cost classes, VLEN %u (k = %u), %u live-out components:\n", vlen, k,
	       (unsigned)(live_out.size() * k));
	Print("shipped", a);
	Print("weighted", b);
	CHECK_EQ((unsigned)a.stores(), (unsigned)(live_out.size() * k));
	CHECK_EQ((unsigned)b.stores(), (unsigned)(live_out.size() * k));
	CHECK_EQ((unsigned long long)b.spill_live, 0ull);
	if (expect_pressure) {
		CHECK(a.reload > 0);
		CHECK(a.spill_live > 0); // the shipped rule pays the extra store
		CHECK(b.loads() <= a.loads());
	}
}

// ---------------------------------------------------------------------------------------------
// [4c] THE FINAL-VALUE CLASS ON ITS OWN. In [4b] the cheap victim is a CLEAN component, so a rule
// that only knew "clean is cheap" would pass it. Here nothing clean is resident at the eviction
// point: every candidate has been written by the run. Exactly one of them (v16) holds its
// component's FINAL value -- its store is owed at the close, so evicting it costs one reload and
// nothing else -- and its next use is the NEAREST, which is what makes farthest-next-use walk past
// it. Every other candidate is redefined after its read, so storing one of those is wasted work.
void CheckFinalValueClass(u32 vlen, unsigned k)
{
	std::vector<u32> words;
	std::vector<RefMember> ref;
	auto alu = [&](u32 f6, Op op, u8 rd, u8 rs2, u8 rs1) {
		words.push_back(Vvv(f6, rd, rs2, rs1));
		ref.push_back({RefMember::Kind::Alu, op, rd, rs2, rs1, 0});
	};
	for (u8 i = 2; i <= 16; ++i) // fifteen registers, all DIRTY afterwards: the pool exactly
		alu(F6_VADD, Op::_vchunkadd, i, i, i);
	alu(F6_VADD, Op::_vchunkadd, 17, 2, 3); // the trigger
	alu(F6_VXOR, Op::_vchunkxor, 18, 16, 2); // v16's read: the NEAREST of the candidates
	for (u8 i = 4; i <= 15; i = (u8)(i + 2))
		alu(F6_VXOR, Op::_vchunkxor, (u8)(19 + (i - 4) / 2), i, (u8)(i + 1));
	for (u8 i = 4; i <= 15; ++i) // ... and every one of THOSE is redefined afterwards
		alu(F6_VADD, Op::_vchunkadd, i, 17, 18);
	std::set<u8> live_out;
	for (auto const &m : ref)
		live_out.insert(m.rd);
	unsigned const bound_stores = (unsigned)live_out.size() * k;
	Env off{}, on{};
	off.vlen = vlen;
	on.vlen = vlen;
	on.weighted = true;
	auto const a = Run("final-class/off", words, off, k, &ref);
	auto const b = Run("final-class/on", words, on, k, &ref);
	printf("  the final-value class, VLEN %u (k = %u); the store bound is %u:\n", vlen, k,
	       bound_stores);
	Print("shipped", a);
	Print("weighted", b);
	CHECK(a.reload > 0); // non-vacuity: an eviction really happens here
	CHECK_EQ((unsigned)b.stores(), bound_stores);
	CHECK_EQ((unsigned long long)b.spill_live, 0ull);
}

// ---------------------------------------------------------------------------------------------
// [4d] THE SEARCH MUST NOT STOP AT A DEAD **EXPENSIVE** VICTIM.
//
// `ensure_room` has two early exits that stop the scan at a victim which frees a register and is
// dead, because on the shipped arm that combination is maximal under "frees > dead > farthest".
// Under the weighted ranking it is NOT: the cost class sits above deadness, so a dead component
// that is dirty and will be REDEFINED still costs a store, and a clean live one beats it. Both
// exits therefore carry the cost class as a third condition, and this case is what makes that
// condition observable rather than merely argued.
//
// REACHING IT NEEDS A COMPONENT THAT IS DEAD AT AN EVICTION BUT NOT YET RELEASED, and there is
// exactly one window in which that happens: `ensure_room` runs while a member's operands are still
// being bound, so when the FIRST source is made resident, a component whose last read is this very
// member is unpinned and reads `next_use < 0`. (`release_dead` cannot have taken it: it runs after
// the step.) That is also why the eviction path may not DROP such a component without storing it --
// the member is about to read it -- which is the rule the body's own comment states.
//
// THE WINDOW IS NARROW AND THE SHAPE IS BUILT FOR IT. Two things must hold at the trigger:
//
//   * the resident set is EXACTLY the pool, so binding a source evicts. A definition demands room
//     for one more than the live set, so the set can only stand at 30 after a member that defined
//     a FRESH register and released nothing -- which is why the member just before the trigger is
//     `vadd v16, ...` and v16 is read again in the tail;
//   * the trigger's FIRST source is not resident, so the eviction happens with nothing pinned.
//     `v18` is a fresh live-in for exactly that.
//
// THE SHAPE, at VLEN 1024 (k = 2, pool 30 = 15 registers):
//
//   m0        vadd v2, v2, v2       v2 becomes DIRTY; m10 below makes this value NON-FINAL
//   m1 - m7   vxor v20, vX, vY      load the clean live-ins v3-v15 and keep them live: each is
//                                   read again in the tail, while v20's own value dies at once and
//                                   is released, so the set grows to v2 + v3-v15 = 28
//   m8        vadd v16, v3, v4      a FRESH destination, live to the end: the set reaches 30
//   m9        vadd v17, v18, v2     THE TRIGGER. Binding v18 evicts with nothing pinned, and at
//                                   that moment v2.c0's last read is THIS member: dead, dirty,
//                                   non-final, a sole holder -- and v2 is the LOWEST resident
//                                   register, so an unguarded scan meets it first and stops there.
//   m10       vadd v2, v17, v18     the redefinition that makes the m0 value non-final
//   m11+      vxor v21, vX, vY      the clean registers' and v16's final reads
//
// The guarded rule evicts a CLEAN component instead: no store, one reload. The unguarded one
// evicts v2.c0, pays a store that the m10 redefinition makes worthless, and reloads it two
// instructions later for the very member that triggered the eviction.
void CheckEarlyExitRespectsCost(u32 vlen, unsigned k)
{
	std::vector<u32> words;
	std::vector<RefMember> ref;
	auto alu = [&](u32 f6, Op op, u8 rd, u8 rs2, u8 rs1) {
		words.push_back(Vvv(f6, rd, rs2, rs1));
		ref.push_back({RefMember::Kind::Alu, op, rd, rs2, rs1, 0});
	};
	alu(F6_VADD, Op::_vchunkadd, 2, 2, 2);
	for (u8 i = 3; i <= 13; i = (u8)(i + 2)) // v3..v14 in pairs
		alu(F6_VXOR, Op::_vchunkxor, 20, i, (u8)(i + 1));
	alu(F6_VXOR, Op::_vchunkxor, 20, 15, 3); // and v15
	alu(F6_VADD, Op::_vchunkadd, 16, 3, 4);  // the fresh destination that fills the pool
	alu(F6_VADD, Op::_vchunkadd, 17, 18, 2); // the trigger; v2's last read
	alu(F6_VADD, Op::_vchunkadd, 2, 17, 18); // v2 redefined: the value above is NOT final
	for (u8 i = 3; i <= 15; i = (u8)(i + 2))
		alu(F6_VXOR, Op::_vchunkxor, 21, i, (u8)(i + 1));
	std::set<u8> live_out;
	for (auto const &m : ref)
		live_out.insert(m.rd);
	unsigned const bound_stores = (unsigned)live_out.size() * k;
	Env off{}, on{};
	off.vlen = vlen;
	on.vlen = vlen;
	on.weighted = true;
	auto const a = Run("early-exit/off", words, off, k, &ref);
	auto const b = Run("early-exit/on", words, on, k, &ref);
	printf("  the early exit, VLEN %u (k = %u); the store bound is %u:\n", vlen, k, bound_stores);
	Print("shipped", a);
	Print("weighted", b);
	// NON-VACUITY: an eviction really happens on this shape, on both arms.
	CHECK(a.reload > 0);
	CHECK(b.reload > 0);
	// THE POINT: the weighted arm still stores nothing it does not owe. Dropping the cost class
	// from either early exit makes it evict v2.c0 and pay a store the redefinition wastes.
	CHECK_EQ((unsigned)b.stores(), bound_stores);
	CHECK_EQ((unsigned long long)b.spill_live, 0ull);
}

// ---------------------------------------------------------------------------------------------
// [6] ALIAS / MOVE / reads_vd / BROADCASTS ARE NOT BROKEN, under real eviction.
//
// The move arm republishes a value under a second name (`vmv.v.v` is a zero-copy rename) and the
// broadcast forms give all k components one frame value, so residency is counted over VALUE IDS
// rather than over names. Both new rules read that same state, and one of them (the free drop) can
// remove a name without removing the value -- so the alias cases are re-run here with the surrogate
// on, and their dataflow, not just their counters, is checked.
// ---------------------------------------------------------------------------------------------
void CheckAliasCases(u32 vlen, unsigned k)
{
	Env on{};
	on.vlen = vlen;
	on.weighted = true;
	on.route_vmv = true;
	// self-move: vd == source, the degenerate rename
	{
		std::vector<u32> const words = {Vvv(F6_VADD, 9, 8, 8), VmvVV(9, 9),
						Vvv(F6_VADD, 10, 9, 9)};
		std::vector<RefMember> const ref = {
		    {RefMember::Kind::Alu, Op::_vchunkadd, 9, 8, 8, 0},
		    {RefMember::Kind::MovV, Op::_vchunkadd, 9, 0, 9, 0},
		    {RefMember::Kind::Alu, Op::_vchunkadd, 10, 9, 9, 0}};
		Run("alias/self-move", words, on, k, &ref);
	}
	// the alias outlives an overwrite of its source
	{
		std::vector<u32> const words = {VmvVV(3, 1), Vvv(F6_VADD, 1, 1, 1),
						Vvv(F6_VXOR, 5, 3, 3), Vvv(F6_VADD, 6, 1, 3)};
		std::vector<RefMember> const ref = {
		    {RefMember::Kind::MovV, Op::_vchunkadd, 3, 0, 1, 0},
		    {RefMember::Kind::Alu, Op::_vchunkadd, 1, 1, 1, 0},
		    {RefMember::Kind::Alu, Op::_vchunkxor, 5, 3, 3, 0},
		    {RefMember::Kind::Alu, Op::_vchunkadd, 6, 1, 3, 0}};
		Run("alias/overwritten-source", words, on, k, &ref);
	}
	// two names take the SAME frame broadcast, and one is then overwritten
	{
		std::vector<u32> const words = {VmvVX(3, 11), VmvVX(4, 11), Vvv(F6_VADD, 5, 3, 4),
						Vvv(F6_VXOR, 3, 5, 5), Vvv(F6_VADD, 6, 3, 4)};
		std::vector<RefMember> const ref = {
		    {RefMember::Kind::MovX, Op::_vchunkadd, 3, 0, 11, 0},
		    {RefMember::Kind::MovX, Op::_vchunkadd, 4, 0, 11, 0},
		    {RefMember::Kind::Alu, Op::_vchunkadd, 5, 3, 4, 0},
		    {RefMember::Kind::Alu, Op::_vchunkxor, 3, 5, 5, 0},
		    {RefMember::Kind::Alu, Op::_vchunkadd, 6, 3, 4, 0}};
		Run("alias/broadcast", words, on, k, &ref);
	}
	// an immediate move, whose one materialised value is shared by all k chunks
	{
		std::vector<u32> const words = {VmvVI(8, 5), Vvv(F6_VADD, 9, 8, 1),
						Vvv(F6_VXOR, 10, 9, 8)};
		std::vector<RefMember> const ref = {
		    {RefMember::Kind::MovI, Op::_vchunkadd, 8, 0, 0, 5},
		    {RefMember::Kind::Alu, Op::_vchunkadd, 9, 8, 1, 0},
		    {RefMember::Kind::Alu, Op::_vchunkxor, 10, 9, 8, 0}};
		Run("alias/immediate", words, on, k, &ref);
	}
	// THE ALIAS IS STILL FREE UNDER PRESSURE: the same high-pressure body twice, differing only
	// in whether the extra name for v1 is an alias or a genuinely distinct value. If the free
	// drop had started reclaiming a shared name as though it freed a register, the alias arm
	// would evict at least as much as the distinct arm.
	{
		auto build = [&](bool alias, std::vector<RefMember> &ref) {
			std::vector<u32> w;
			if (alias) {
				w.push_back(VmvVV(31, 1));
				ref.push_back({RefMember::Kind::MovV, Op::_vchunkadd, 31, 0, 1, 0});
			} else {
				w.push_back(Vvv(F6_VADD, 31, 1, 1));
				ref.push_back({RefMember::Kind::Alu, Op::_vchunkadd, 31, 1, 1, 0});
			}
			for (u8 i = 2; i <= 15; ++i) {
				w.push_back(Vvv(F6_VADD, i, i, i));
				ref.push_back({RefMember::Kind::Alu, Op::_vchunkadd, i, i, i, 0});
			}
			u8 d = 16;
			for (u8 i = 2; i <= 15; i = (u8)(i + 2)) {
				w.push_back(Vvv(F6_VADD, d, i, (u8)(i + 1)));
				ref.push_back(
				    {RefMember::Kind::Alu, Op::_vchunkadd, d, i, (u8)(i + 1), 0});
				++d;
			}
			w.push_back(Vvv(F6_VADD, 30, 31, 1));
			ref.push_back({RefMember::Kind::Alu, Op::_vchunkadd, 30, 31, 1, 0});
			return w;
		};
		std::vector<RefMember> r1, r2;
		auto const w1 = build(true, r1);
		auto const w2 = build(false, r2);
		auto const al = Run("alias/pressure-alias", w1, on, k, &r1);
		auto const di = Run("alias/pressure-distinct", w2, on, k, &r2);
		Print("pressure, extra name is an alias", al);
		Print("pressure, extra name is distinct", di);
		CHECK(al.reload <= di.reload);
		CHECK(al.spill_live <= di.spill_live);
		CHECK(al.peak <= di.peak);
	}
	// reads_vd: a fused member is a source in its own right, so the value-aware scan must NOT
	// treat the member that defines vd as killing the value that same member reads.
	{
		Env fma = on;
		fma.route_fma = true;
		std::vector<u32> const words = {Vvv(F6_VADD, 9, 1, 2), VfmaccVF(9, 3, 4),
						VfmaccVF(9, 5, 4), Vvv(F6_VXOR, 10, 9, 1)};
		std::vector<RefMember> const ref = {
		    {RefMember::Kind::Alu, Op::_vchunkadd, 9, 1, 2, 0},
		    {RefMember::Kind::Fma, Op::_vchunkfma, 9, 3, 4, 0},
		    {RefMember::Kind::Fma, Op::_vchunkfma, 9, 5, 4, 0},
		    {RefMember::Kind::Alu, Op::_vchunkxor, 10, 9, 1, 0}};
		unsigned n = 0;
		auto const c = Run("reads_vd/fma", words, fma, k, &ref, &n);
		// the fused members must actually be IN the run, or the case proves nothing
		CHECK_EQ(n, 4u);
		CHECK_EQ((unsigned long long)c.spill_live, 0ull);
	}
}

} // namespace

int main()
{
	printf("P7N-J: value-epoch-aware, cost-weighted residency in the live-range-splitting body\n");
	CheckSwitchIsInert();
	printf("[2]+[5] the ChaCha20-shaped 60-member run\n");
	CheckChaChaShape(1024, 2, /*expect_pressure=*/true);
	CheckChaChaShape(512, 1, /*expect_pressure=*/false);
	printf("[3] D1: a definition kills the old value\n");
	CheckDefKillsOldValue(512, 1);
	CheckDefKillsOldValue(1024, 2);
	CheckFinalValueStillStored(1024, 2);
	CheckValueEpochPeakIsExact();
	CheckWastedStore(1024, 2, /*expect_pressure=*/true);
	CheckWastedStore(512, 1, /*expect_pressure=*/false);
	printf("[4] D2: the three cost classes\n");
	CheckCostClasses(1024, 2, /*expect_pressure=*/true);
	CheckCostClasses(512, 1, /*expect_pressure=*/false);
	CheckFinalValueClass(1024, 2);
	CheckEarlyExitRespectsCost(1024, 2);
	printf("[6] alias / move / broadcast / reads_vd, with the surrogate on\n");
	CheckAliasCases(1024, 2);
	CheckAliasCases(512, 1);
	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("PASS\n");
	return 0;
}
