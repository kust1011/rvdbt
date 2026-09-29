// G9 (2026-09-07): the move/broadcast members inside the LIVE-RANGE-SPLITTING SSA body.
//
// G8 measured the structural defect this repairs: with --rvv-run-live-range-split on, the run
// classifier refused every RunOp::Mov member, so a stack that also has --rvv-qcg-typed-chunk-vmv
// silently gave up 54 run members on the frozen Blackscholes kernel and paid ~20% for it. The
// split body now has its own move arm. What has to be true, and is checked here:
//
//   [1] all four unmasked move forms (vmv.v.v / vmv.v.x / vmv.v.i / vfmv.v.f) are admitted as run
//       members with the split on, at VLEN 512 and 1024, in one frame with an arithmetic member;
//   [2] the move emits NO per-chunk lane operation -- it republishes a value under vd -- with one
//       broadcast per distinct scalar source and one per immediate member, exactly as the
//       fixed-placement body does;
//   [3] the emitted frame is DATAFLOW-EQUIVALENT to applying the members in guest order, which is
//       what covers the zero-copy vmv.v.v rename, vd == source, an alias whose source is later
//       overwritten, and every live-out register's final value reaching its own slot;
//   [4] the planning pass and the emitting pass agree on the typed-op count (the frame's declared
//       n_typed is exactly the number of body ops), for every case;
//   [5] a run with NO move member emits the identical body it emitted before G9, pinned against a
//       literal op sequence, so the RvvRunMemberReads repair cannot have moved an existing frame;
//   [6] the forms that must still fail closed do: the merge encodings (vm = 0), a reserved
//       non-zero vs2, and the materialize / chunk-major bodies.
//
// SCOPE: structure and dataflow. Nothing here executes a vector instruction -- the host this runs
// on need not have AVX-512, which is why every case sets the routes' `force_emit` audit switches.
// The hardware evidence is a separate untimed run of the frozen guest on the AVX-512 machine.
#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

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
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__,          \
				__LINE__, #a, #b, (long long)_a, (long long)_b);                     \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

constexpr u32 F6_MERGE = 0b010111u, F6_ADD = 0b000000u, F6_XOR = 0b001011u;
constexpr u32 OpV(u32 f6, u32 vm, u32 vs2, u32 rs1, u32 f3, u32 vd)
{
	return 0b1010111u | (vd << 7) | (f3 << 12) | (rs1 << 15) | (vs2 << 20) | (vm << 25) | (f6 << 26);
}
constexpr u32 VmvVV(u32 vd, u32 vs1) { return OpV(F6_MERGE, 1, 0, vs1, 0b000, vd); }
constexpr u32 VmvVX(u32 vd, u32 rs1) { return OpV(F6_MERGE, 1, 0, rs1, 0b100, vd); }
constexpr u32 VmvVI(u32 vd, u32 imm) { return OpV(F6_MERGE, 1, 0, imm & 0x1fu, 0b011, vd); }
constexpr u32 VfmvVF(u32 vd, u32 fs1) { return OpV(F6_MERGE, 1, 0, fs1, 0b101, vd); }
constexpr u32 VmergeVVM(u32 vd, u32 vs2, u32 vs1) { return OpV(F6_MERGE, 0, vs2, vs1, 0b000, vd); }
constexpr u32 VmvBadVs2(u32 vd, u32 vs1) { return OpV(F6_MERGE, 1, 3, vs1, 0b000, vd); }
constexpr u32 VaddVV(u32 vd, u32 vs2, u32 vs1) { return OpV(F6_ADD, 1, vs2, vs1, 0b000, vd); }
constexpr u32 VxorVV(u32 vd, u32 vs2, u32 vs1) { return OpV(F6_XOR, 1, vs2, vs1, 0b000, vd); }
constexpr u32 VmulVX(u32 vd, u32 vs2, u32 rs1) { return OpV(0b100101, 1, vs2, rs1, 0b110, vd); }
constexpr u32 VmaccVX(u32 vd, u32 vs2, u32 rs1) { return OpV(0b101101, 1, vs2, rs1, 0b110, vd); }
constexpr u32 VSetVli(u32 rd) { return 0b1010111u | (rd << 7) | (0b111u << 12) | (0xd0u << 20); }
static_assert(VmvVV(9, 8) == 0x5e0404d7u, "vmv.v.v v9,v8");
static_assert(VmvVI(8, 5) == 0x5e02b457u, "vmv.v.i v8,5");

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	std::vector<u8> buf;
};

// Every case runs with the SPLIT ON unless it deliberately does not; `split` is the only knob a
// case changes, so a difference between two cases is attributable to it.
void ApplyEnv(u32 vlen, bool split, bool vmv = true)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::rvv_lowering = 1;
	config::rvv_vector_run = true;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_live_range_split = split;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_vmv = vmv;
	config::rvv_qcg_typed_chunk_vmv_force_emit = true;
	config::rvv_qcg_typed_chunk_xor = true;
	config::rvv_qcg_typed_chunk_xor_force_emit = true;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
}
struct Built {
	MemArena arena{1u << 21};
	std::vector<u32> words;
	Region *region = nullptr;
};
void Translate(Built &b, std::vector<u32> const &words, u32 vlen, bool split, bool vmv = true,
	       bool vx = false)
{
	ApplyEnv(vlen, split, vmv);
	config::rvv_qcg_vx_mulacc = vx;
	config::rvv_qcg_vx_mulacc_force_emit = vx;
	b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	config::rvv_run_live_range_split = false;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
}
struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
	std::vector<Inst *> body;
};
std::vector<Frame> FindFrames(Region *r)
{
	std::vector<Frame> out;
	Frame cur;
	bool open = false;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				cur = Frame{};
				cur.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
			} else if (ins.GetOpcode() == Op::_rvvtypedchunkend) {
				if (open) {
					out.push_back(cur);
					open = false;
				}
			} else if (open) {
				cur.body.push_back(&ins);
			}
		}
	return out;
}
unsigned CountOp(Frame const &f, Op op)
{
	unsigned n = 0;
	for (auto *i : f.body)
		n += i->GetOpcode() == op;
	return n;
}
Frame const *Widest(std::vector<Frame> const &fs)
{
	Frame const *best = nullptr;
	for (auto const &f : fs)
		if (!best || f.begin->n_members > best->begin->n_members)
			best = &f;
	return best;
}
bool IsLaneOp(Op op)
{
	return op == Op::_vchunkadd || op == Op::_vchunksub || op == Op::_vchunkmul ||
	       op == Op::_vchunkand || op == Op::_vchunkor || op == Op::_vchunkxor;
}

// ---------------------------------------------------------------------------------------------
// THE INTERPRETER. Runs the emitted frame over a model register file, and is the instrument that
// makes [3] a test of dataflow rather than of op counts.
//
// It is deliberately strict in two ways. A load from the WRONG slot yields a different value,
// because slot seeds are a function of the CPUState offset. And a value that was never defined is
// an immediate failure rather than a zero, so an alias that lost its producer cannot pass.
// ---------------------------------------------------------------------------------------------
struct SimResult {
	bool ok = true;
	std::string why;
	std::map<u32, u64> slots;
};
u64 ModelOp(Op op, u64 a, u64 b)
{
	switch (op) {
	case Op::_vchunkadd:
		return a + b;
	case Op::_vchunksub:
		return a - b;
	case Op::_vchunkmul:
		return a * b;
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
u64 SeedFor(u32 offs) { return 0x9e3779b97f4a7c15ull * (offs + 1u) ^ 0xcafef00dd15ea5e5ull; }
// A broadcast's value is a function of WHAT it broadcasts, so a member that picked up the wrong
// frame broadcast (the x table instead of the f table, say) produces a different value.
u64 SeedImm(i32 imm) { return 0xd1b54a32d192ed03ull * (u64)(i64)imm + 0x1234567ull; }
u64 SeedGpr(u32 offs) { return 0xa24baed4963ee407ull * (offs + 3u) ^ 0x5bf03635ull; }
u64 SeedFpr(u32 offs) { return 0x9fb21c651e98df25ull * (offs + 7u) ^ 0x77777777ull; }

SimResult Simulate(Frame const &f)
{
	SimResult r;
	std::map<u32, u64> slot;
	std::map<u32, u64> val;
	std::map<u32, bool> defined;
	auto read_slot = [&](u32 offs) {
		auto it = slot.find(offs);
		if (it == slot.end())
			return slot[offs] = SeedFor(offs);
		return it->second;
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
			u64 const v = get(i->i(0), "store reads an undefined value");
			if (!r.ok)
				return r;
			slot[st->offs] = v;
			continue;
		}
		if (op == Op::_vchunkbroadcast) {
			auto *bc = static_cast<InstVChunkBroadcast *>(i);
			auto const d = i->o(0);
			if (!d.IsVVPR()) {
				r.ok = false;
				r.why = "broadcast destination is not a virtual register";
				return r;
			}
			val[d.GetVVPR()] = bc->is_imm ? SeedImm(bc->imm) : SeedGpr(bc->offs);
			defined[d.GetVVPR()] = true;
			continue;
		}
		if (op == Op::_vchunkfbroadcast) {
			auto *bc = static_cast<InstVChunkFBroadcast *>(i);
			auto const d = i->o(0);
			if (!d.IsVVPR()) {
				r.ok = false;
				r.why = "f broadcast destination is not a virtual register";
				return r;
			}
			val[d.GetVVPR()] = SeedFpr(bc->offs);
			defined[d.GetVVPR()] = true;
			continue;
		}
		if (IsLaneOp(op)) {
			u64 const a = get(i->i(0), "lane op reads an undefined source 2");
			u64 const b = get(i->i(1), "lane op reads an undefined source 1");
			if (!r.ok)
				return r;
			auto const d = i->o(0);
			val[d.GetVVPR()] = ModelOp(op, a, b);
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

// THE REFERENCE. Apply the guest members in order to a model register file seeded exactly as the
// interpreter seeds the slots, then read out what every live-out register's slot must hold.
struct RefMember {
	Op op;        // _vchunkadd / _vchunkxor for arithmetic, or one of the four move markers
	u8 rd, rs2, rs1;
	enum class Kind { Alu, MovV, MovX, MovI, MovF, MulX, MAccX } kind = Kind::Alu;
	i32 imm = 0;
};
std::map<u32, u64> Reference(std::vector<RefMember> const &ms, u32 vlen, unsigned k)
{
	u32 const base = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));
	u32 const slot_sz = rv32::VLEN_MAX_BYTES;
	u32 const stride = vlen / 8u / k;
	auto off = [&](u8 r, unsigned c) { return base + (u32)r * slot_sz + (u32)c * stride; };
	std::map<u32, u64> reg; // (reg,chunk) packed -> value
	auto key = [](u8 r, unsigned c) { return ((u32)r << 8) | (u32)c; };
	auto read = [&](u8 r, unsigned c) {
		auto it = reg.find(key(r, c));
		if (it == reg.end())
			return reg[key(r, c)] = SeedFor(off(r, c));
		return it->second;
	};
	std::map<u8, bool> written;
	for (auto const &m : ms) {
		for (unsigned c = 0; c < k; ++c) {
			u64 v = 0;
			switch (m.kind) {
			case RefMember::Kind::Alu:
				v = ModelOp(m.op, read(m.rs2, c), read(m.rs1, c));
				break;
			case RefMember::Kind::MovV:
				v = read(m.rs1, c);
				break;
			case RefMember::Kind::MovX:
				v = SeedGpr((u32)(offsetof(CPUState, gpr) + 4u * m.rs1));
				break;
			case RefMember::Kind::MulX:
			case RefMember::Kind::MAccX:
				v = read(m.rs2, c) *
				    SeedGpr((u32)(offsetof(CPUState, gpr) + 4u * m.rs1));
				if (m.kind == RefMember::Kind::MAccX)
					v += read(m.rd, c);
				break;
			case RefMember::Kind::MovI:
				v = SeedImm(m.imm);
				break;
			case RefMember::Kind::MovF:
				v = SeedFpr((u32)(offsetof(CPUState, fpu) +
						  offsetof(rv32::FPUState, f) + m.rs1 * sizeof(u64)));
				break;
			}
			reg[key(m.rd, c)] = v;
		}
		written[m.rd] = true;
	}
	std::map<u32, u64> out;
	for (auto const &w : written)
		for (unsigned c = 0; c < k; ++c)
			out[off(w.first, c)] = reg[key(w.first, c)];
	return out;
}

// Compare the interpreter's final slots against the reference for every live-out slot.
void CheckDataflow(char const *name, Frame const &f, std::vector<RefMember> const &ms, u32 vlen,
		   unsigned k)
{
	SimResult const sim = Simulate(f);
	if (!sim.ok) {
		fprintf(stderr, "  FAIL %s (vlen=%u): %s\n", name, vlen, sim.why.c_str());
		++g_failures;
		return;
	}
	auto const want = Reference(ms, vlen, k);
	for (auto const &kv : want) {
		auto const it = sim.slots.find(kv.first);
		if (it == sim.slots.end()) {
			fprintf(stderr, "  FAIL %s (vlen=%u): live-out slot 0x%x was never stored\n",
				name, vlen, kv.first);
			++g_failures;
			continue;
		}
		if (it->second != kv.second) {
			fprintf(stderr,
				"  FAIL %s (vlen=%u): slot 0x%x holds %016llx, want %016llx\n", name,
				vlen, kv.first, (unsigned long long)it->second,
				(unsigned long long)kv.second);
			++g_failures;
		}
	}
}
// [4] the frame's declared typed-op count must be exactly what the body contains: that is the
// planning pass and the emitting pass agreeing, checked at the QIR level rather than trusting
// Emit_rvvtypedchunkend's Panic to have been reached.
void CheckOpCount(char const *name, Frame const &f)
{
	if ((unsigned)f.begin->n_typed != (unsigned)f.body.size()) {
		fprintf(stderr, "  FAIL %s: declared n_typed %u but body has %u ops\n", name,
			(unsigned)f.begin->n_typed, (unsigned)f.body.size());
		++g_failures;
	}
}

// ---------------------------------------------------------------------------------------------
// [1] + [2] + [3] + [4]: all four move forms in one split frame.
// ---------------------------------------------------------------------------------------------
void CheckAllFourForms(u32 vlen, unsigned k)
{
	Built b;
	Translate(b,
		  {VSetVli(6), VmvVI(8, 5), VmvVX(9, 11), VfmvVF(10, 12), VmvVV(11, 9),
		   VaddVV(12, 8, 11)},
		  vlen, /*split=*/true);
	auto const frames = FindFrames(b.region); // keep the vector alive: Widest points into it
	auto const *f = Widest(frames);
	if (!f) {
		fprintf(stderr, "  FAIL all-four-forms vlen=%u: no frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)f->begin->n_members, 5u);
	CHECK(f->begin->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeVlVstart);
	// [2] one broadcast per distinct scalar source; NO per-chunk op for a move, so the only lane
	// ops are the single arithmetic member's k
	CHECK_EQ(CountOp(*f, Op::_vchunkbroadcast), 2u);  // vmv.v.i and vmv.v.x
	CHECK_EQ(CountOp(*f, Op::_vchunkfbroadcast), 1u); // vfmv.v.f
	CHECK_EQ(CountOp(*f, Op::_vchunkadd), (unsigned)k);
	CheckOpCount("all-four-forms", *f);
	CheckDataflow("all-four-forms", *f,
		      {{Op::_vchunkadd, 8, 0, 5, RefMember::Kind::MovI, 5},
		       {Op::_vchunkadd, 9, 0, 11, RefMember::Kind::MovX, 0},
		       {Op::_vchunkadd, 10, 0, 12, RefMember::Kind::MovF, 0},
		       {Op::_vchunkadd, 11, 0, 9, RefMember::Kind::MovV, 0},
		       {Op::_vchunkadd, 12, 8, 11, RefMember::Kind::Alu, 0}},
		      vlen, k);
}

// ---------------------------------------------------------------------------------------------
// [3] OVERLAP: vd == source. `vmv.v.v v9, v9` re-binds a name to the value it already holds, which
// is the degenerate case of the zero-copy rename and the one most likely to be mishandled by a
// residency scheme that assumed a destination is always a fresh register.
// ---------------------------------------------------------------------------------------------
void CheckSelfMove(u32 vlen, unsigned k)
{
	Built b;
	Translate(b, {VSetVli(6), VaddVV(9, 8, 8), VmvVV(9, 9), VaddVV(10, 9, 9)}, vlen,
		  /*split=*/true);
	auto const frames = FindFrames(b.region); // keep the vector alive: Widest points into it
	auto const *f = Widest(frames);
	if (!f) {
		fprintf(stderr, "  FAIL self-move vlen=%u: no frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)f->begin->n_members, 3u);
	CHECK_EQ(CountOp(*f, Op::_vchunkadd), (unsigned)(2 * k)); // the move adds no lane op
	CheckOpCount("self-move", *f);
	CheckDataflow("self-move", *f,
		      {{Op::_vchunkadd, 9, 8, 8, RefMember::Kind::Alu, 0},
		       {Op::_vchunkadd, 9, 0, 9, RefMember::Kind::MovV, 0},
		       {Op::_vchunkadd, 10, 9, 9, RefMember::Kind::Alu, 0}},
		      vlen, k);
}

// ---------------------------------------------------------------------------------------------
// [3] OVERWRITTEN ALIAS: the move publishes vs1's value under vd, then vs1 is written again. The
// alias must keep the OLD value -- this is the case an id-blind residency scheme gets wrong,
// because vd and vs1 share a host register right up to the moment vs1 is redefined.
// ---------------------------------------------------------------------------------------------
void CheckOverwrittenAlias(u32 vlen, unsigned k)
{
	Built b;
	Translate(b, {VSetVli(6), VmvVV(3, 1), VaddVV(1, 1, 1), VxorVV(5, 3, 3), VaddVV(6, 1, 3)},
		  vlen, /*split=*/true);
	auto const frames = FindFrames(b.region); // keep the vector alive: Widest points into it
	auto const *f = Widest(frames);
	if (!f) {
		fprintf(stderr, "  FAIL overwritten-alias vlen=%u: no frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)f->begin->n_members, 4u);
	CheckOpCount("overwritten-alias", *f);
	CheckDataflow("overwritten-alias", *f,
		      {{Op::_vchunkadd, 3, 0, 1, RefMember::Kind::MovV, 0},
		       {Op::_vchunkadd, 1, 1, 1, RefMember::Kind::Alu, 0},
		       {Op::_vchunkxor, 5, 3, 3, RefMember::Kind::Alu, 0},
		       {Op::_vchunkadd, 6, 1, 3, RefMember::Kind::Alu, 0}},
		      vlen, k);
}

// ---------------------------------------------------------------------------------------------
// [3] BROADCAST ALIAS ACROSS CHUNKS AND MEMBERS: two registers take the SAME frame broadcast and
// one of them is then overwritten. All k components of each are the one broadcast value, so this
// is the widest aliasing the body can produce.
// ---------------------------------------------------------------------------------------------
void CheckBroadcastAlias(u32 vlen, unsigned k)
{
	Built b;
	Translate(b, {VSetVli(6), VmvVX(3, 11), VmvVX(4, 11), VaddVV(5, 3, 4), VxorVV(3, 5, 5),
		      VaddVV(6, 3, 4)},
		  vlen, /*split=*/true);
	auto const frames = FindFrames(b.region); // keep the vector alive: Widest points into it
	auto const *f = Widest(frames);
	if (!f) {
		fprintf(stderr, "  FAIL broadcast-alias vlen=%u: no frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)f->begin->n_members, 5u);
	// ONE broadcast for the one distinct GPR source, shared by both moves and by every chunk
	CHECK_EQ(CountOp(*f, Op::_vchunkbroadcast), 1u);
	CheckOpCount("broadcast-alias", *f);
	CheckDataflow("broadcast-alias", *f,
		      {{Op::_vchunkadd, 3, 0, 11, RefMember::Kind::MovX, 0},
		       {Op::_vchunkadd, 4, 0, 11, RefMember::Kind::MovX, 0},
		       {Op::_vchunkadd, 5, 3, 4, RefMember::Kind::Alu, 0},
		       {Op::_vchunkxor, 3, 5, 5, RefMember::Kind::Alu, 0},
		       {Op::_vchunkadd, 6, 3, 4, RefMember::Kind::Alu, 0}},
		      vlen, k);
}

// ---------------------------------------------------------------------------------------------
// [3] TRUE EVICTION: a run whose DEMAND exceeds the residency budget, so the manager must evict.
//
// G9A replaced a weaker case here. The old one peaked at 20 of the 30-register budget, so it was
// labelled a pressure test while never taking an eviction branch: it proved live-out placement and
// nothing about what happens when the pool runs out. The sequence below is built to overflow at
// VLEN 1024 and, deliberately, NOT at VLEN 512, which is the same width-dependence the split exists
// for.
//
// THE SHAPE, and why each part is there:
//
//   vmv.v.v v31, v1     the alias, read for the LAST time by the final member, so its next use is
//                       the farthest of any live component -- which makes it the eviction rule's
//                       preferred victim among live ones, i.e. the case that produces a spill of a
//                       component that is still needed, and then a reload of it;
//   vadd    v1, v1, v1  overwrites the alias's source, so the alias must survive an overwrite
//                       WHILE being spilled and reloaded;
//   vadd v(i), v(i), v(i) for i in 2..15
//                       fourteen more registers made live, each written (so live out) and read
//                       again below, so they cannot be released early;
//   vadd v16..v22, pairs of the above
//                       the consumers whose destinations add still more live-out components;
//   vadd v30, v31, v1   the alias's final read.
//
// At VLEN 1024 each guest register is two components, so sixteen simultaneously live registers ask
// for 32 against a budget of 30. The manager cannot exceed the budget by construction -- it evicts
// to stay at it -- so the OBSERVABLE evidence that demand went above 30 is that evictions actually
// happened, which is what the counters below assert.
void CheckTrueEviction(u32 vlen, unsigned k, bool expect_eviction)
{
	std::vector<u32> words = {VSetVli(6), VmvVV(31, 1), VaddVV(1, 1, 1)};
	std::vector<RefMember> ref = {{Op::_vchunkadd, 31, 0, 1, RefMember::Kind::MovV, 0},
				      {Op::_vchunkadd, 1, 1, 1, RefMember::Kind::Alu, 0}};
	for (u8 i = 2; i <= 15; ++i) {
		words.push_back(VaddVV(i, i, i));
		ref.push_back({Op::_vchunkadd, i, i, i, RefMember::Kind::Alu, 0});
	}
	u8 d = 16;
	for (u8 i = 2; i <= 15; i = (u8)(i + 2)) {
		words.push_back(VaddVV(d, i, (u8)(i + 1)));
		ref.push_back({Op::_vchunkadd, d, i, (u8)(i + 1), RefMember::Kind::Alu, 0});
		++d;
	}
	words.push_back(VaddVV(30, 31, 1));
	ref.push_back({Op::_vchunkadd, 30, 31, 1, RefMember::Kind::Alu, 0});

	// split_peak_resident is a RUNNING MAX over the process, so it is zeroed here to make the
	// reading below this case's own peak rather than the largest any earlier case reached. That
	// also makes the assertion independent of the order main() calls these cases in.
	rv32::rvvrun::g_stats.split_peak_resident = 0;
	auto const before = rv32::rvvrun::g_stats;
	Built b;
	Translate(b, words, vlen, /*split=*/true);
	auto const &after = rv32::rvvrun::g_stats;
	u64 const reload = after.split_reload - before.split_reload;
	u64 const spill_live = after.split_spill_live - before.split_spill_live;
	u64 const store_dead = after.split_store_dead - before.split_store_dead;
	u64 const frames = after.split_frames - before.split_frames;
	auto const frames_v = FindFrames(b.region);
	auto const *f = Widest(frames_v);
	if (!f) {
		fprintf(stderr, "  FAIL eviction vlen=%u: no frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)f->begin->n_members, 24u);
	CHECK_EQ((unsigned)frames, 1u);
	printf("    vlen=%u: peak_resident=%llu of budget %u, reload=%llu spill_live=%llu "
	       "store_dead=%llu\n",
	       vlen, (unsigned long long)after.split_peak_resident,
	       (unsigned)rv32::rvvrun::kHostVectorRegs, (unsigned long long)reload,
	       (unsigned long long)spill_live, (unsigned long long)store_dead);
	if (expect_eviction) {
		// demand above the budget, proved by the eviction branches actually being taken:
		// a component still needed was written out (spill_live) and later read back (reload),
		// and dead components were written out early (store_dead) rather than at the close.
		CHECK(spill_live > 0);
		CHECK(reload > 0);
		CHECK(store_dead > 0);
		// the manager held residency AT the budget: it may reach it, never pass it
		CHECK_EQ((unsigned)after.split_peak_resident, (unsigned)rv32::rvvrun::kHostVectorRegs);
	} else {
		// the SAME guest code at the narrower width needs no eviction at all
		CHECK_EQ((unsigned long long)spill_live, 0ull);
		CHECK_EQ((unsigned long long)reload, 0ull);
		CHECK(after.split_peak_resident < rv32::rvvrun::kHostVectorRegs);
	}
	// a reload must read a slot the body itself wrote, and an eviction store must appear BEFORE
	// the closing block: both are visible in the emitted order.
	if (expect_eviction) {
		bool store_before_last_lane = false;
		size_t last_lane = 0;
		for (size_t i = 0; i < f->body.size(); ++i)
			if (IsLaneOp(f->body[i]->GetOpcode()))
				last_lane = i;
		for (size_t i = 0; i < last_lane; ++i)
			if (f->body[i]->GetOpcode() == Op::_vstatechunkstore)
				store_before_last_lane = true;
		CHECK(store_before_last_lane);
	}
	CheckOpCount("eviction", *f);
	// STORE ACCOUNTING. Every live-out component must be written to its slot EXACTLY once, and
	// the three store counters must partition those writes: an eviction store of a dead
	// component, a spill of a live one, or the closing store. Equality holds for this sequence
	// because no register is written again after being spilled -- a spilled component is
	// reloaded clean and the closing loop then owes it nothing -- so a double store or a missing
	// store shows up here as an inequality.
	std::set<u8> live_out;
	for (auto const &m : ref)
		live_out.insert(m.rd);
	unsigned const want_stores = (unsigned)live_out.size() * k;
	CHECK_EQ(CountOp(*f, Op::_vstatechunkstore), want_stores);
	CHECK_EQ((unsigned)(store_dead + spill_live + (after.split_store_final -
						       before.split_store_final)),
		 want_stores);
	// THE POINT OF THE CASE: every live-out value must still be right, including the alias that
	// was spilled, reloaded, and whose source was overwritten in between.
	CheckDataflow("eviction", *f, ref, vlen, k);
}

// ---------------------------------------------------------------------------------------------
// [3] THE ALIAS IS FREE, MEASURED UNDER EVICTION. The claim the id-based accounting makes is that
// a republished component costs NO host register. Under pressure that claim is testable rather
// than asserted: run the same high-pressure body twice, differing only in whether the extra name
// for v1 is an ALIAS (`vmv.v.v v31, v1`) or a genuinely distinct value (`vadd v31, v1, v1`). If
// the alias were charged a register, the alias arm would evict at least as much as the distinct
// arm; it must in fact evict strictly less.
// ---------------------------------------------------------------------------------------------
struct EvictionCounts {
	u64 reload, spill_live, store_dead, peak;
};
EvictionCounts RunPressure(u32 vlen, unsigned k, bool alias, std::vector<RefMember> &ref_out,
			   char const *name)
{
	std::vector<u32> words = {VSetVli(6)};
	std::vector<RefMember> ref;
	if (alias) {
		words.push_back(VmvVV(31, 1));
		ref.push_back({Op::_vchunkadd, 31, 0, 1, RefMember::Kind::MovV, 0});
	} else {
		words.push_back(VaddVV(31, 1, 1));
		ref.push_back({Op::_vchunkadd, 31, 1, 1, RefMember::Kind::Alu, 0});
	}
	for (u8 i = 2; i <= 15; ++i) {
		words.push_back(VaddVV(i, i, i));
		ref.push_back({Op::_vchunkadd, i, i, i, RefMember::Kind::Alu, 0});
	}
	u8 d = 16;
	for (u8 i = 2; i <= 15; i = (u8)(i + 2)) {
		words.push_back(VaddVV(d, i, (u8)(i + 1)));
		ref.push_back({Op::_vchunkadd, d, i, (u8)(i + 1), RefMember::Kind::Alu, 0});
		++d;
	}
	words.push_back(VaddVV(30, 31, 1)); // both names read at the very end
	ref.push_back({Op::_vchunkadd, 30, 31, 1, RefMember::Kind::Alu, 0});

	rv32::rvvrun::g_stats.split_peak_resident = 0;
	auto const before = rv32::rvvrun::g_stats;
	Built b;
	Translate(b, words, vlen, /*split=*/true);
	auto const &after = rv32::rvvrun::g_stats;
	auto const frames = FindFrames(b.region);
	auto const *f = Widest(frames);
	if (f) {
		CheckOpCount(name, *f);
		CheckDataflow(name, *f, ref, vlen, k);
	} else {
		fprintf(stderr, "  FAIL %s vlen=%u: no frame\n", name, vlen);
		++g_failures;
	}
	ref_out = ref;
	return {after.split_reload - before.split_reload,
		after.split_spill_live - before.split_spill_live,
		after.split_store_dead - before.split_store_dead, after.split_peak_resident};
}
void CheckAliasIsFree(u32 vlen, unsigned k)
{
	std::vector<RefMember> r1, r2;
	auto const with_alias = RunPressure(vlen, k, /*alias=*/true, r1, "alias-free/alias");
	auto const distinct = RunPressure(vlen, k, /*alias=*/false, r2, "alias-free/distinct");
	printf("    vlen=%u alias   : peak=%llu reload=%llu spill_live=%llu store_dead=%llu\n", vlen,
	       (unsigned long long)with_alias.peak, (unsigned long long)with_alias.reload,
	       (unsigned long long)with_alias.spill_live, (unsigned long long)with_alias.store_dead);
	printf("    vlen=%u distinct: peak=%llu reload=%llu spill_live=%llu store_dead=%llu\n", vlen,
	       (unsigned long long)distinct.peak, (unsigned long long)distinct.reload,
	       (unsigned long long)distinct.spill_live, (unsigned long long)distinct.store_dead);
	// the alias arm must never evict MORE than the distinct-value arm, at either width
	CHECK(with_alias.reload <= distinct.reload);
	CHECK(with_alias.spill_live <= distinct.spill_live);
	CHECK(with_alias.store_dead <= distinct.store_dead);
}

// ---------------------------------------------------------------------------------------------
// [5] A RUN WITH NO MOVE MEMBER MUST BE UNCHANGED. The RvvRunMemberReads repair touched the
// next-use scan every split frame uses, so the body of a pure-ALU split run is pinned here against
// a literal op sequence. If that repair had altered an existing frame, this fails.
// ---------------------------------------------------------------------------------------------
char const *OpName(Op op)
{
	switch (op) {
	case Op::_vstatechunkload:
		return "ld";
	case Op::_vstatechunkstore:
		return "st";
	case Op::_vchunkadd:
		return "add";
	case Op::_vchunkxor:
		return "xor";
	case Op::_vchunkbroadcast:
		return "bcast";
	case Op::_vchunkfbroadcast:
		return "fbcast";
	default:
		return "?";
	}
}
// The expectation is DERIVED from the split body's documented rules, not pasted from a run, so a
// future change that alters the ALU path fails here for a stated reason:
//
//   `vadd v3,v1,v2 ; vxor v4,v3,v1 ; vadd v5,v4,v3` has live-ins {v1, v2} and live-outs
//   {v3, v4, v5}. Per chunk the body loads each live-in ONCE at its first use (2 loads), emits one
//   lane op per member (3), and stores each live-out once in the closing loop (3). Members are the
//   outer loop and chunks the inner one, so for k = 1 the body is
//       ld ld add   xor   add   | st st st
//   and for k = 2 the member-major order repeats each member's two chunks before the next member,
//   with the closing stores last:
//       ld ld add   ld ld add   xor xor   add add   | st st st st st st
//   No reload and no eviction store appears at either width because the peak (5 and 10 values)
//   is far below the pool.
std::string ExpectedAluBody(unsigned k)
{
	std::vector<std::string> ops;
	for (unsigned c = 0; c < k; ++c) { // member 0: two first-use loads then the lane op
		ops.push_back("ld");
		ops.push_back("ld");
		ops.push_back("add");
	}
	for (unsigned c = 0; c < k; ++c) // member 1: both sources already resident
		ops.push_back("xor");
	for (unsigned c = 0; c < k; ++c) // member 2: likewise
		ops.push_back("add");
	for (unsigned r = 0; r < 3; ++r) // the three live-outs, all chunks
		for (unsigned c = 0; c < k; ++c)
			ops.push_back("st");
	std::string out;
	for (auto const &o : ops) {
		if (!out.empty())
			out += " ";
		out += o;
	}
	return out;
}
void CheckAluRunUnchanged(u32 vlen, unsigned k)
{
	Built b;
	// vmv is OFF, so this is exactly the run the split body formed before G9
	Translate(b, {VSetVli(6), VaddVV(3, 1, 2), VxorVV(4, 3, 1), VaddVV(5, 4, 3)}, vlen,
		  /*split=*/true, /*vmv=*/false);
	auto const frames = FindFrames(b.region); // keep the vector alive: Widest points into it
	auto const *f = Widest(frames);
	if (!f) {
		fprintf(stderr, "  FAIL alu-unchanged vlen=%u: no frame\n", vlen);
		++g_failures;
		return;
	}
	CHECK_EQ((unsigned)f->begin->n_members, 3u);
	std::string got;
	for (auto *i : f->body) {
		if (!got.empty())
			got += " ";
		got += OpName(i->GetOpcode());
	}
	std::string const want = ExpectedAluBody(k);
	if (got != want) {
		fprintf(stderr, "  FAIL alu-unchanged vlen=%u:\n    got  %s\n    want %s\n", vlen,
			got.c_str(), want.c_str());
		++g_failures;
	}
	CheckOpCount("alu-unchanged", *f);
}

// ---------------------------------------------------------------------------------------------
// [6] fail-closed: the merge encodings and a reserved non-zero vs2 are not members with the split
// on either, so widening the split body did not widen ADMISSION.
// ---------------------------------------------------------------------------------------------
void CheckFailClosed(u32 vlen)
{
	struct Case {
		char const *name;
		u32 word;
	} const cases[] = {
	    {"vmerge.vvm (vm=0)", VmergeVVM(8, 12, 9)},
	    {"vmv.v.v with reserved non-zero vs2", VmvBadVs2(8, 9)},
	    {"vfmerge.vfm (vm=0)", OpV(F6_MERGE, 0, 8, 12, 0b101, 9)},
	};
	for (auto const &c : cases) {
		Built b;
		Translate(b, {VSetVli(6), c.word, VaddVV(10, 9, 9)}, vlen, /*split=*/true);
		auto const frames = FindFrames(b.region); // keep the vector alive: Widest points into it
	auto const *f = Widest(frames);
		if (f && f->begin->n_members >= 2) {
			fprintf(stderr, "  FAIL fail-closed vlen=%u: %s became a run member\n", vlen,
				c.name);
			++g_failures;
		}
	}
}
void CheckVxArithmetic(u32 vlen, unsigned k)
{
	using K = RefMember::Kind;
	// GPR x9 must not be mistaken for vector v9. The copied old v8 must also
	// survive the multiply that overwrites v8, including vd == vs2 on vmacc.
	std::vector<u32> words = {VSetVli(6), VmvVV(10, 8), VmulVX(8, 8, 9),
		VmaccVX(9, 8, 9), VmaccVX(8, 8, 11), VaddVV(12, 10, 9)};
	std::vector<RefMember> refs = {
		{Op::_vchunkadd, 10, 0, 8, K::MovV},
		{Op::_vchunkmul, 8, 8, 9, K::MulX},
		{Op::_vchunkmul, 9, 8, 9, K::MAccX},
		{Op::_vchunkmul, 8, 8, 11, K::MAccX},
		{Op::_vchunkadd, 12, 10, 9, K::Alu},
	};
	for (bool split : {false, true}) {
		Built b;
		Translate(b, words, vlen, split, true, true);
		auto const frames = FindFrames(b.region);
		auto const *f = Widest(frames);
		CHECK(f);
		if (!f)
			continue;
		CHECK_EQ(f->begin->n_members, 5u);
		CHECK_EQ(CountOp(*f, Op::_vchunkbroadcast), 2u);
		CHECK_EQ(CountOp(*f, Op::_vchunkmul), 3u * k);
		CHECK_EQ(CountOp(*f, Op::_vchunkadd), 3u * k);
		CheckDataflow("vx arithmetic and aliases", *f, refs, vlen, k);
		CheckOpCount("vx arithmetic and aliases", *f);
		TestCompilerRuntime cr;
		CodeSegment segment(0u, 0x1000u);
		CHECK(!qcg::GenerateCode(&cr, &segment, b.region, 0).empty());
	}
}

void CheckVxPressure(u32 vlen, unsigned k)
{
	using K = RefMember::Kind;
	std::vector<u32> words{VSetVli(6)};
	std::vector<RefMember> refs;
	for (u8 r = 1; r <= 14; ++r) {
		words.push_back(VmaccVX(r, 31, 5));
		refs.push_back({Op::_vchunkmul, r, 31, 5, K::MAccX});
	}
	for (u8 r = 1; r <= 14; ++r) {
		words.push_back(VmulVX(r, r, 5));
		refs.push_back({Op::_vchunkmul, r, r, 5, K::MulX});
	}
	Built b;
	Translate(b, words, vlen, true, true, true);
	auto const frames = FindFrames(b.region);
	auto const *f = Widest(frames);
	CHECK(f);
	if (!f)
		return;
	CHECK_EQ(f->begin->n_members, refs.size());
	CHECK_EQ(CountOp(*f, Op::_vchunkmul), 28u * k);
	CHECK_EQ(CountOp(*f, Op::_vchunkadd), 14u * k);
	CheckDataflow("vx arithmetic under pressure", *f, refs, vlen, k);
	CheckOpCount("vx arithmetic under pressure", *f);
	TestCompilerRuntime cr;
	CodeSegment segment(0u, 0x1000u);
	CHECK(!qcg::GenerateCode(&cr, &segment, b.region, 0).empty());
}
} // namespace

int main()
{
	printf("[W25] vmul.vx/vmacc.vx: aliases, pressure, typed-op count, and host emission\n");
	CheckVxArithmetic(512, 1);
	CheckVxArithmetic(1024, 2);
	CheckVxPressure(512, 1);
	CheckVxPressure(1024, 2);
	printf("[1][2][3][4] all four move forms in one split frame\n");
	CheckAllFourForms(512, 1);
	CheckAllFourForms(1024, 2);
	printf("[3] overlap: vd == source\n");
	CheckSelfMove(512, 1);
	CheckSelfMove(1024, 2);
	printf("[3] overwritten alias\n");
	CheckOverwrittenAlias(512, 1);
	CheckOverwrittenAlias(1024, 2);
	printf("[3] broadcast alias across chunks and members\n");
	CheckBroadcastAlias(512, 1);
	CheckBroadcastAlias(1024, 2);
	printf("[3] true eviction: demand above the residency budget\n");
	CheckTrueEviction(512, 1, /*expect_eviction=*/false);
	CheckTrueEviction(1024, 2, /*expect_eviction=*/true);
	printf("[3] the alias is free, measured under eviction\n");
	CheckAliasIsFree(512, 1);
	CheckAliasIsFree(1024, 2);
	printf("[5] a pure-ALU split run is byte-identical to its pre-G9 shape\n");
	CheckAluRunUnchanged(512, 1);
	CheckAluRunUnchanged(1024, 2);
	printf("[6] the merge and reserved encodings still fail closed\n");
	CheckFailClosed(512);
	CheckFailClosed(1024);
	printf("%s rvv_run_move_split (%d failures)\n", g_failures ? "FAIL" : "PASS", g_failures);
	return g_failures ? 1 : 0;
}
