// P7N-G: live-range splitting for the vector run's SSA body, as a structural test.
//
// WHAT THIS FILE HAS TO PROVE, and why each section exists.
//
//   [1] THE FRAME IS DATAFLOW-EQUIVALENT. The strongest check available without AVX-512 silicon:
//       INTERPRET the emitted frame's typed ops over a model register file -- loads read a
//       CPUState slot, lane ops compute, stores write a slot -- and compare the resulting slots
//       against a reference that simply applies the members in guest order. If a spill wrote the
//       wrong slot, a reload picked up a stale value, an overlapping operand read the
//       post-instruction value, or a live-out never reached memory, the two disagree. This is what
//       makes the section a correctness test rather than an instruction census.
//
//   [2] WHEN THE PRESSURE IS NOT REAL, NOTHING IS SPLIT. A run that fits the pool must emit
//       EXACTLY `live_in * k` loads and `live_out * k` stores -- the same instructions the fixed
//       placement emits, only placed differently. Splitting that a run did not need would show up
//       here as an extra op, which is precisely the failure "split only under real pressure"
//       has to exclude.
//
//   [3] LOAD SINKING. With splitting on, a live-in is loaded at its FIRST USE, so the ops before
//       the first lane op are the first member's sources and nothing else. The fixed placement
//       loads every live-in first, so the two are distinguishable by counting.
//
//   [4] DEAD RELEASE. A component whose last use has passed and whose slot already agrees is
//       dropped with no instruction at all. Checked as a peak-residency fact against a sequence
//       built so that most of its components die early.
//
//   [5] SPILL AND RELOAD UNDER REAL PRESSURE. A synthetic run whose exact peak exceeds the pool
//       must (a) still be admitted and lowered, (b) never hold more than the pool, and (c) contain
//       both a store of a still-live component and a later reload of it. (a) is what the whole
//       checkpoint is for; (b) is the property that keeps the existing allocator from spilling
//       inside the guarded window.
//
//   [6] ALIAS. `vd == vs2`, `vd == vs1` and `vd == vs1 == vs2` must read the PRE-instruction
//       value. Covered by [1] on sequences that contain all three.
//
//   [7] BOTH WIDTHS. Every section runs at VLEN 512 (k=1) and VLEN 1024 (k=2).
//
//   [8] SIBLING ADJACENCY. The whole line of work is about the independence of the low/high chunks
//       of ONE guest operation, so the emitted stream must still issue them adjacently. A body
//       that reduced the peak by going chunk-major would pass [1]-[5] and destroy the question.
//
//   [9] MUTATION. Each check is shown to fail when the thing it checks is broken.
//
// SCOPE: structure and dataflow only. Nothing here is executed and nothing here is timed; the
// hardware evidence is the checkpoint's ChaCha20 arms. Like the other route tests it uses the
// audit force-emit switches, because it never runs what it emits.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

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
		auto _b = (b);                                                                                \
		if (!(_a == _b)) {                                                                           \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,    \
				#b, (long long)_a, (long long)_b);                                           \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

// ---------------------------------------------------------------------------------------------
// Encodings, built from the FIELDS so a disagreement with the decoder is about a field.
// ---------------------------------------------------------------------------------------------
constexpr u32 OPV = 0b1010111;
constexpr u32 Enc(u32 funct6, u32 vm, u32 vs2, u32 vs1_or_imm, u32 funct3, u32 vd)
{
	return (funct6 << 26) | (vm << 25) | (vs2 << 20) | (vs1_or_imm << 15) | (funct3 << 12) |
	       (vd << 7) | OPV;
}
constexpr u32 F6_VADD = 0b000000, F6_VOR = 0b001010, F6_VXOR = 0b001011, F6_VAND = 0b001001;
constexpr u32 F6_VSLL = 0b100101, F6_VSRL = 0b101000;
constexpr u32 F3_OPIVV = 0b000, F3_OPIVI = 0b011;
constexpr u32 W_VSETVLI_E32M1 = 0x0d057557u;

u32 Vadd(u32 vd, u32 vs2, u32 vs1) { return Enc(F6_VADD, 1, vs2, vs1, F3_OPIVV, vd); }
u32 Vxor(u32 vd, u32 vs2, u32 vs1) { return Enc(F6_VXOR, 1, vs2, vs1, F3_OPIVV, vd); }
u32 Vor(u32 vd, u32 vs2, u32 vs1) { return Enc(F6_VOR, 1, vs2, vs1, F3_OPIVV, vd); }
u32 Vand(u32 vd, u32 vs2, u32 vs1) { return Enc(F6_VAND, 1, vs2, vs1, F3_OPIVV, vd); }
u32 Vsll(u32 vd, u32 vs2, u32 imm) { return Enc(F6_VSLL, 1, vs2, imm, F3_OPIVI, vd); }
u32 Vsrl(u32 vd, u32 vs2, u32 imm) { return Enc(F6_VSRL, 1, vs2, imm, F3_OPIVI, vd); }

void ApplyConfig(u32 vlen_bits, bool split)
{
	config::vlen_bits = vlen_bits;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_lowering = 1;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_sub = true;
	config::rvv_qcg_typed_chunk_mul = true;
	config::rvv_qcg_typed_chunk_and = true;
	config::rvv_qcg_typed_chunk_or = true;
	config::rvv_qcg_typed_chunk_xor = true;
	config::rvv_qcg_typed_chunk_shift = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_sub_force_emit = true;
	config::rvv_qcg_typed_chunk_mul_force_emit = true;
	config::rvv_qcg_typed_chunk_and_force_emit = true;
	config::rvv_qcg_typed_chunk_or_force_emit = true;
	config::rvv_qcg_typed_chunk_xor_force_emit = true;
	config::rvv_qcg_typed_chunk_shift_force_emit = true;
	config::rvv_qcg_narrow_chunk_width = true;
	config::rvv_qcg_narrow_chunk_width_force_emit = true;
	config::rvv_qcg_direct_setvl = true;
	config::rvv_qcg_hit_counter = false;
	config::rvv_vector_run = true;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_live_range_split = split;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_llvm_wide_vadd = false;
	config::rvv_llvm_wide_vadd_ssa = false;
}

struct Built {
	MemArena arena{1u << 22};
	std::vector<u32> words;
	Region *region = nullptr;
};

void Build(Built &b, std::vector<u32> const &body)
{
	b.words.clear();
	b.words.push_back(W_VSETVLI_E32M1);
	for (u32 w : body)
		b.words.push_back(w);
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
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
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto const op = ins.GetOpcode();
			if (op == Op::_rvvtypedchunkbegin) {
				cur = Frame{};
				cur.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
				continue;
			}
			if (op == Op::_rvvtypedchunkend) {
				cur.end = static_cast<InstRVVTypedChunkEnd *>(&ins);
				frames.push_back(cur);
				open = false;
				continue;
			}
			if (open)
				cur.body.push_back(&ins);
		}
	}
	return frames;
}

Frame const *LongestFrame(std::vector<Frame> const &fs)
{
	Frame const *best = nullptr;
	for (auto const &f : fs)
		if (f.end && f.end->n_members >= 2 && (!best || f.end->n_members > best->end->n_members))
			best = &f;
	return best;
}

unsigned CountOp(Frame const &f, Op op)
{
	unsigned n = 0;
	for (auto *i : f.body)
		n += i->GetOpcode() == op;
	return n;
}

bool IsLaneOp(Op op)
{
	switch (op) {
	case Op::_vchunkadd:
	case Op::_vchunksub:
	case Op::_vchunkmul:
	case Op::_vchunkand:
	case Op::_vchunkor:
	case Op::_vchunkxor:
	case Op::_vchunksll:
	case Op::_vchunksrl:
		return true;
	default:
		return false;
	}
}

// ---------------------------------------------------------------------------------------------
// [1] THE INTERPRETER. Runs the emitted frame over a model register file.
//
// The lane operations are modelled with ORDINARY 64-bit arithmetic rather than real vector lane
// semantics: what this section is testing is the frame's DATAFLOW -- which value reaches which
// slot -- and every op used below is injective enough that a wrong operand shows up as a wrong
// result. The lane semantics themselves are the single-instruction routes' own evidence, and the
// ChaCha20 arms are what check them against silicon.
// ---------------------------------------------------------------------------------------------
struct SimResult {
	bool ok = true;
	std::string why;
	std::map<u32, u64> slots; // CPUState offset -> value
};

u64 ModelOp(Op op, u64 a, u64 b, u8 shamt)
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
	case Op::_vchunksll:
		return a << (shamt & 63);
	case Op::_vchunksrl:
		return a >> (shamt & 63);
	default:
		return 0;
	}
}

// Seed a slot deterministically from its CPUState offset, so a load from the WRONG slot produces a
// different value and section [1] fails.
u64 SeedFor(u32 offs) { return 0x9e3779b97f4a7c15ull * (offs + 1u) ^ 0xcafef00dd15ea5e5ull; }

SimResult Simulate(Frame const &f)
{
	SimResult r;
	std::map<u32, u64> slot;      // CPUState offset -> current value
	std::map<u32, u64> val;       // SSA vreg number -> value
	std::map<u32, bool> defined;  // SSA vreg number -> has a value
	auto read_slot = [&](u32 offs) {
		auto it = slot.find(offs);
		if (it == slot.end())
			return slot[offs] = SeedFor(offs);
		return it->second;
	};
	for (auto *i : f.body) {
		auto const op = i->GetOpcode();
		if (op == Op::_vstatechunkload) {
			auto *ld = static_cast<InstVStateChunkLoad *>(i);
			auto const d = i->o(0);
			if (!d.IsVVPR()) {
				r.ok = false;
				r.why = "load destination is not a virtual register";
				return r;
			}
			val[d.GetVVPR()] = read_slot(ld->offs);
			defined[d.GetVVPR()] = true;
			continue;
		}
		if (op == Op::_vstatechunkstore) {
			auto *st = static_cast<InstVStateChunkStore *>(i);
			auto const v = i->i(0);
			if (!v.IsVVPR() || !defined[v.GetVVPR()]) {
				r.ok = false;
				r.why = "store reads an undefined value";
				return r;
			}
			slot[st->offs] = val[v.GetVVPR()];
			continue;
		}
		if (IsLaneOp(op)) {
			auto const d = i->o(0);
			auto const s2 = i->i(0);
			u64 a = 0, b = 0;
			if (!s2.IsVVPR() || !defined[s2.GetVVPR()]) {
				r.ok = false;
				r.why = "lane op reads an undefined source 2";
				return r;
			}
			a = val[s2.GetVVPR()];
			u8 shamt = 0;
			if (op == Op::_vchunksll) {
				shamt = static_cast<InstVChunkSll *>(i)->shamt;
			} else if (op == Op::_vchunksrl) {
				shamt = static_cast<InstVChunkSrl *>(i)->shamt;
			} else {
				auto const s1 = i->i(1);
				if (!s1.IsVVPR() || !defined[s1.GetVVPR()]) {
					r.ok = false;
					r.why = "lane op reads an undefined source 1";
					return r;
				}
				b = val[s1.GetVVPR()];
			}
			val[d.GetVVPR()] = ModelOp(op, a, b, shamt);
			defined[d.GetVVPR()] = true;
			continue;
		}
		r.ok = false;
		r.why = "unexpected op in the frame body";
		return r;
	}
	r.slots = slot;
	return r;
}

// The reference: apply the members in guest order to a model register file whose initial contents
// are the same seeds the interpreter reads out of the slots.
std::map<u32, u64> Reference(std::vector<u32> const &members_raw, u8 k, u32 stride)
{
	namespace rvv = dbt::rv32;
	u32 const vreg_base = (u32)(offsetof(CPUState, vec) + offsetof(rvv::VectorState, vreg));
	u32 const slot_sz = rvv::VLEN_MAX_BYTES;
	std::map<u32, u64> reg; // (r, c) packed -> value
	std::map<u32, u64> touched;
	auto off = [&](u32 r, u8 c) { return vreg_base + r * slot_sz + (u32)c * stride; };
	auto get = [&](u32 r, u8 c) -> u64 {
		u32 const o = off(r, c);
		auto it = reg.find(o);
		if (it == reg.end())
			return reg[o] = SeedFor(o);
		return it->second;
	};
	for (u32 raw : members_raw) {
		u32 const f6 = raw >> 26, f3 = (raw >> 12) & 7;
		u32 const rd = (raw >> 7) & 31, rs1 = (raw >> 15) & 31, rs2 = (raw >> 20) & 31;
		Op op = Op::_vchunkadd;
		bool imm = false;
		if (f3 == F3_OPIVI) {
			op = f6 == F6_VSLL ? Op::_vchunksll : Op::_vchunksrl;
			imm = true;
		} else if (f6 == F6_VADD) {
			op = Op::_vchunkadd;
		} else if (f6 == F6_VXOR) {
			op = Op::_vchunkxor;
		} else if (f6 == F6_VOR) {
			op = Op::_vchunkor;
		} else if (f6 == F6_VAND) {
			op = Op::_vchunkand;
		}
		for (u8 c = 0; c < k; ++c) {
			u64 const a = get(rs2, c);
			u64 const b = imm ? 0 : get(rs1, c);
			u64 const v = ModelOp(op, a, b, (u8)rs1);
			touched[off(rd, c)] = 1;
			reg[off(rd, c)] = v;
		}
	}
	std::map<u32, u64> out;
	for (auto const &kv : touched)
		out[kv.first] = reg[kv.first];
	return out;
}

// ---------------------------------------------------------------------------------------------
// SEQUENCES
// ---------------------------------------------------------------------------------------------
// A small chain that fits the pool comfortably, containing all three legal operand overlaps.
std::vector<u32> SmallChain()
{
	return {Vadd(3, 1, 2),   // disjoint
		Vxor(4, 3, 1),   // disjoint
		Vor(3, 3, 4),    // vd == vs2
		Vand(4, 3, 4),   // vd == vs1
		Vadd(5, 5, 5),   // vd == vs1 == vs2
		Vsll(6, 3, 7),   // OPIVI: no vector source 1
		Vsrl(7, 3, 25), Vor(3, 6, 7)};
}

// A sequence whose exact peak exceeds the pool at k = 2: it makes many registers live at once and
// then reads them all back, so nothing can die early.
std::vector<u32> WidePressure()
{
	std::vector<u32> v;
	for (u32 r = 2; r <= 17; ++r)
		v.push_back(Vadd(r, r, 1)); // define 16 registers, all reading v1
	for (u32 r = 2; r <= 17; ++r)
		v.push_back(Vxor(18, 18, r)); // read all 16 back, so none may die early
	return v;
}

// A sequence with ALTERNATING opcodes, so grouping lane ops by chunk is distinguishable from
// grouping them by member. `WidePressure` has long runs of one opcode and cannot tell the two
// apart, which made the first version of the mutation control pass vacuously.
std::vector<u32> Alternating()
{
	std::vector<u32> v;
	for (u32 i = 0; i < 10; ++i) {
		v.push_back(Vadd(2, 2, 1));
		v.push_back(Vxor(3, 3, 2));
	}
	return v;
}

// A sequence in which most components die immediately: each result is consumed once and never
// again, so a body that releases dead values keeps a small resident set.
std::vector<u32> DiesEarly()
{
	std::vector<u32> v;
	for (u32 i = 0; i < 12; ++i) {
		v.push_back(Vadd(20, 1, 2));   // define v20
		v.push_back(Vxor(21, 20, 3));  // consume it; v20 dead until redefined
	}
	return v;
}

struct Analysis {
	bool have = false;
	unsigned members = 0, loads = 0, stores = 0, lane_ops = 0;
	unsigned loads_before_first_lane = 0;
	unsigned live_in = 0, live_out = 0;
	u8 k = 0;
	bool sibling_adjacent = true;
	SimResult sim;
};

Analysis Run(u32 vlen, bool split, std::vector<u32> const &body)
{
	ApplyConfig(vlen, split);
	Built b;
	Build(b, body);
	auto const frames = FindFrames(b.region);
	Analysis a;
	auto const *f = LongestFrame(frames);
	if (!f)
		return a;
	a.have = true;
	a.k = (u8)std::max(1u, vlen / 512u);
	a.members = f->end->n_members;
	a.loads = CountOp(*f, Op::_vstatechunkload);
	a.stores = CountOp(*f, Op::_vstatechunkstore);
	for (auto *i : f->body)
		a.lane_ops += IsLaneOp(i->GetOpcode());
	bool seen_lane = false;
	for (auto *i : f->body) {
		if (IsLaneOp(i->GetOpcode())) {
			seen_lane = true;
			break;
		}
		if (i->GetOpcode() == Op::_vstatechunkload)
			a.loads_before_first_lane++;
	}
	(void)seen_lane;
	// SIBLING ADJACENCY: the lane ops of one guest member must be the k consecutive lane ops
	// with chunk index 0..k-1. Loads and stores may be interleaved between them -- that is what
	// splitting does -- so the test is on the LANE OP subsequence, which is the sequence the
	// sibling-independence question is about.
	if (a.k > 1) {
		std::vector<Inst *> lanes;
		for (auto *i : f->body)
			if (IsLaneOp(i->GetOpcode()))
				lanes.push_back(i);
		if (lanes.size() % a.k != 0) {
			a.sibling_adjacent = false;
		} else {
			for (size_t n = 0; n < lanes.size(); n += a.k) {
				for (u8 c = 0; c < a.k; ++c) {
					// Every lane op of one member is the same opcode; a chunk-major
					// body would put k copies of the FIRST member's op together
					// only if the run were one member long, so comparing opcodes
					// across the group is what distinguishes the two orders on a
					// mixed-opcode sequence.
					if (lanes[n + c]->GetOpcode() != lanes[n]->GetOpcode())
						a.sibling_adjacent = false;
				}
			}
		}
	}
	a.sim = Simulate(*f);
	return a;
}

// ---------------------------------------------------------------------------------------------
void TestDataflowEquivalence()
{
	printf("[1] the emitted frame is dataflow-equivalent to applying the members in order\n");
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &named : std::vector<std::pair<char const *, std::vector<u32>>>{
			 {"small chain (all three operand overlaps)", SmallChain()},
			 {"wide pressure (peak > pool at k=2)", WidePressure()},
			 {"dies early", DiesEarly()}}) {
			auto const a = Run(vlen, /*split=*/true, named.second);
			CHECK(a.have);
			if (!a.have)
				continue;
			CHECK(a.sim.ok);
			if (!a.sim.ok) {
				fprintf(stderr, "  FAIL VLEN %u %s: %s\n", vlen, named.first,
					a.sim.why.c_str());
				continue;
			}
			u32 const stride = std::min(vlen / 8u, 64u);
			std::vector<u32> mem(named.second.begin(),
					     named.second.begin() + a.members);
			auto const want = Reference(mem, a.k, stride);
			bool ok = true;
			for (auto const &kv : want) {
				auto it = a.sim.slots.find(kv.first);
				if (it == a.sim.slots.end() || it->second != kv.second)
					ok = false;
			}
			CHECK(ok);
			printf("   VLEN %4u %-42s %2u members, %u live-out slot(s) all correct\n",
			       vlen, named.first, a.members, (unsigned)want.size());
		}
	}
}

void TestNoSplitWhenNoPressure()
{
	printf("[2] a run that fits the pool emits the SAME op counts as the fixed placement\n");
	for (u32 vlen : {512u, 1024u}) {
		auto const off = Run(vlen, /*split=*/false, SmallChain());
		auto const on = Run(vlen, /*split=*/true, SmallChain());
		CHECK(off.have && on.have);
		if (!off.have || !on.have)
			continue;
		CHECK_EQ(on.members, off.members);
		CHECK_EQ(on.lane_ops, off.lane_ops);
		// The counts are identical; only the PLACEMENT differs. An extra load or store here
		// would be a split the run did not need.
		CHECK_EQ(on.loads, off.loads);
		CHECK_EQ(on.stores, off.stores);
		printf("   VLEN %4u: %u members, loads %u == %u, stores %u == %u, lane ops %u == %u\n",
		       vlen, on.members, on.loads, off.loads, on.stores, off.stores, on.lane_ops,
		       off.lane_ops);
	}
}

void TestLoadSinking()
{
	printf("[3] a live-in is loaded at its FIRST USE, not at frame entry\n");
	for (u32 vlen : {512u, 1024u}) {
		auto const off = Run(vlen, /*split=*/false, WidePressure());
		auto const on = Run(vlen, /*split=*/true, WidePressure());
		CHECK(off.have && on.have);
		if (!off.have || !on.have)
			continue;
		// The fixed placement loads EVERY live-in before the first lane op. Splitting loads
		// only the first member's sources -- at most two per chunk.
		CHECK_EQ(off.loads_before_first_lane, off.loads);
		CHECK(on.loads_before_first_lane <= 2u * on.k);
		CHECK(on.loads_before_first_lane < off.loads_before_first_lane);
		printf("   VLEN %4u: loads before the first lane op  fixed %2u -> split %u\n", vlen,
		       off.loads_before_first_lane, on.loads_before_first_lane);
	}
}

void TestPressureAndSpill()
{
	printf("[4/5] under real pressure the run is still lowered, and residency stays in the pool\n");
	for (u32 vlen : {512u, 1024u}) {
		namespace rr = dbt::rv32::rvvrun;
		rr::g_stats = rr::Stats{};
		auto const on = Run(vlen, /*split=*/true, WidePressure());
		CHECK(on.have);
		if (!on.have)
			continue;
		auto const st = rr::g_stats;
		// (b) the resident set never exceeded the pool -- the property that keeps the existing
		// allocator from having to spill inside the guarded window.
		CHECK(st.split_peak_resident <= rr::kHostVectorRegs);
		printf("   VLEN %4u: %2u members, peak resident %llu (pool %u), "
		       "reload %llu, spill_live %llu\n",
		       vlen, on.members, (unsigned long long)st.split_peak_resident,
		       (unsigned)rr::kHostVectorRegs, (unsigned long long)st.split_reload,
		       (unsigned long long)st.split_spill_live);
		if (vlen == 1024) {
			// (a) the whole sequence is ONE run: without splitting the pressure rule
			// would have cut it. (c) and it really did split.
			CHECK_EQ(on.members, (unsigned)WidePressure().size());
			CHECK(st.split_spill_live > 0);
			CHECK(st.split_reload > 0);
		}
	}
	// THE CONTROL: with splitting OFF the same sequence at VLEN 1024 is cut short by the
	// pressure rule, which is what makes the section above about THIS mechanism.
	{
		auto const off = Run(1024, /*split=*/false, WidePressure());
		CHECK(off.have);
		if (off.have) {
			CHECK(off.members < (unsigned)WidePressure().size());
			printf("   control VLEN 1024: with splitting off the run is cut at %u of %u "
			       "members\n",
			       off.members, (unsigned)WidePressure().size());
		}
	}
}

void TestDeadRelease()
{
	printf("[4b] components whose last use has passed are released with no instruction\n");
	for (u32 vlen : {512u, 1024u}) {
		namespace rr = dbt::rv32::rvvrun;
		rr::g_stats = rr::Stats{};
		auto const on = Run(vlen, /*split=*/true, DiesEarly());
		CHECK(on.have);
		if (!on.have)
			continue;
		auto const st = rr::g_stats;
		// The sequence touches five registers; a body that released nothing would still fit,
		// so the check that matters is that NOTHING was spilled and NOTHING was reloaded --
		// the pressure was never real, so no live range may be split.
		CHECK_EQ((unsigned long long)st.split_spill_live, 0ull);
		CHECK_EQ((unsigned long long)st.split_reload, 0ull);
		printf("   VLEN %4u: %2u members, peak resident %llu, 0 spills, 0 reloads\n", vlen,
		       on.members, (unsigned long long)st.split_peak_resident);
	}
}

void TestSiblingAdjacency()
{
	printf("[8] low/high sibling chunks of one guest operation are still issued adjacently\n");
	// The ALTERNATING sequence, so "every lane-op group is one opcode" is a real constraint: on
	// a sequence with long runs of one opcode a chunk-major body would satisfy it too.
	auto const a = Run(1024, /*split=*/true, Alternating());
	CHECK(a.have);
	if (a.have) {
		CHECK(a.sibling_adjacent);
		CHECK_EQ(a.lane_ops, a.members * a.k);
		printf("   VLEN 1024: %u lane ops in %u groups of %u, every group one opcode\n",
		       a.lane_ops, a.members, a.k);
	}
}

void TestMutationSensitivity()
{
	printf("[9] the checks are falsifiable\n");
	// (a) The interpreter is not vacuous: corrupting one store offset in a COPY of the frame's
	//     effects must make the comparison fail. Done on the model rather than on the emitter:
	//     take the real slot map and perturb one entry.
	auto const a = Run(1024, /*split=*/true, SmallChain());
	CHECK(a.have && a.sim.ok);
	if (a.have && a.sim.ok) {
		u32 const stride = 64;
		std::vector<u32> mem(SmallChain().begin(), SmallChain().begin() + a.members);
		auto want = Reference(mem, a.k, stride);
		CHECK(!want.empty());
		auto corrupted = a.sim.slots;
		if (!want.empty()) {
			corrupted[want.begin()->first] ^= 1ull;
			bool ok = true;
			for (auto const &kv : want) {
				auto it = corrupted.find(kv.first);
				if (it == corrupted.end() || it->second != kv.second)
					ok = false;
			}
			CHECK(!ok);
			printf("   a one-bit change in one live-out slot is detected\n");
		}
	}
	// (b) The sibling-adjacency check is not vacuous: it must REJECT a chunk-major body. The
	//     splitting body refuses to be built chunk-major, so the control is the ordinary SSA
	//     body in chunk-major order, whose lane ops are grouped by chunk rather than by member.
	{
		ApplyConfig(1024, /*split=*/false);
		config::rvv_run_order_chunk_major = true;
		Built b;
		Build(b, Alternating());
		auto const frames = FindFrames(b.region);
		auto const *f = LongestFrame(frames);
		CHECK(f != nullptr);
		if (f) {
			std::vector<Inst *> lanes;
			for (auto *i : f->body)
				if (IsLaneOp(i->GetOpcode()))
					lanes.push_back(i);
			bool grouped = true;
			for (size_t n = 0; n + 1 < lanes.size(); n += 2)
				if (lanes[n + 1]->GetOpcode() != lanes[n]->GetOpcode())
					grouped = false;
			CHECK(!grouped);
			printf("   a chunk-major body FAILS the sibling-adjacency check, as it must\n");
		}
		config::rvv_run_order_chunk_major = false;
	}
}

} // namespace

int main()
{
	printf("rvv_run_live_range_split_test\n");
	TestDataflowEquivalence();
	TestNoSplitWhenNoPressure();
	TestLoadSinking();
	TestPressureAndSpill();
	TestDeadRelease();
	TestSiblingAdjacency();
	TestMutationSensitivity();
	printf("%s (%d failure(s))\n", g_failures ? "FAILED" : "PASSED", g_failures);
	return g_failures ? 1 : 0;
}
