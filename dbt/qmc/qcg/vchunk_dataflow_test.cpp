// Phase 3: typed V512 QIR dataflow (vchunkload -> vchunkadd -> vchunkstore) through
// QSel -> QRegAlloc -> emitted AVX-512.
//
// SCOPE.  Nothing here is routed from a guest instruction.  These three opcodes have no producer
// anywhere in the translator; the only regions that contain them are the ones built below.  This
// says nothing about RVV lowering and nothing about performance.  What it does establish is that a
// 512-bit host value can exist as an ordinary QIR value: defined by one instruction, consumed by
// another, allocated a ZMM by the register allocator on the same terms as a GPR, spilled and
// refilled across pressure and across a call, and executed on real data.
//
// The contrast that motivates the file is the diagnostic arm (InstRVVDiagChunk*): there the chunk
// data lives at a fixed CPUState offset and the emitter hardcodes zmm<index>, so no pass can see
// the value at all.  Every assertion below is chosen to fail if this path degenerated back to that.
//
//   D1  the three ops survive selection and allocation with real def-use: the add reads exactly the
//       two load results, its result is a third register, the store reads that result, and no
//       chunk operand is zmm0/zmm1 (the emitter's reserved scratch).
//   D2  under register pressure the values are evicted to the frame and reloaded, and the dataflow
//       the QIR declared is still the dataflow the physical registers carry.
//   D3  the same across an hcall, where SysV preserves no ZMM at all -- so there BOTH inputs are
//       forced through the frame, by a rule rather than by a tuned amount of pressure.
//   D4  the emitted bytes are, instruction for instruction, exactly what an independent assembler
//       produces for the ALLOCATED registers, at exactly the expected offsets -- and SEW selects
//       vpaddb/w/d/q.
//   E1  executed on an AVX-512 host: 16 nontrivial i32 lanes, guest-memory addressing through both
//       a GPR-held address and an immediate one.  Lane data is chosen so that vpaddb, vpaddw and
//       vpaddq each produce a different answer than vpaddd.
//   E2  the same, executed, but with enough pressure that both inputs are spilled to the JIT frame
//       and refilled before the add -- so the vmovdqu64 round trip is verified against data.
//   E3  all four SEWs executed against a reference that adds at that element width, and shown to
//       disagree with each other on this data -- so SEW -> opcode is settled by hardware, not by
//       this test and asmjit happening to pick the same mnemonic.
//
// D1-D4 run on any host.  E1/E2/E3 need AVX-512F+BW and are SKIPPED (loudly, counted, and reported
// in the summary) otherwise -- this workstation is Ivy Bridge and cannot execute a ZMM instruction.
//
// Set VCHUNK_DUMP=1 to print each region's post-RA listing.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qcg/qemit.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"
#include "dbt/qmc/qir_printer.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include <unordered_map>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
using namespace dbt::qcg;

namespace
{

int g_failures = 0;
int g_skipped = 0;

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
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,   \
				#b, (long long)_a, (long long)_b);                                           \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

void Dump(char const *tag, Region *r)
{
	if (getenv("VCHUNK_DUMP")) {
		fprintf(stderr, "--- %s ---\n%s\n", tag, PrinterPass::run(r).c_str());
	}
}

// ---------------------------------------------------------------------------------------------
// Guest address space.
//
// This build defines DBT_ZERO_MMU_BASE (dbt/config.h:16), so mmu::base is null and a guest address
// IS a host virtual address.  Every guest address used below therefore has to be a real, mapped,
// sub-4GiB host address -- both because make_vmem emits it as an absolute [disp32] (sign-extended
// from 32 bits) or as [reg32] (a 32-bit effective address), and because the native tests actually
// dereference it.  Nothing here depends on rvdbt's own mmu; the region is mapped locally.
// ---------------------------------------------------------------------------------------------

constexpr u32 GUEST_BASE = 0x30000000u;
constexpr size_t GUEST_SZ = 64u << 10;

constexpr u32 GA_A = GUEST_BASE + 0x100;
constexpr u32 GA_B = GUEST_BASE + 0x140;
constexpr u32 GA_OUT = GUEST_BASE + 0x1000;
constexpr u32 GA_FILLER = GUEST_BASE + 0x2000;

// D5's second, independent chain -- disjoint from GA_A/GA_B/GA_OUT and from GA_FILLER's range.
constexpr u32 GA_A2 = GUEST_BASE + 0x180;
constexpr u32 GA_B2 = GUEST_BASE + 0x1C0;
constexpr u32 GA_OUT2 = GUEST_BASE + 0x1100;

// ---------------------------------------------------------------------------------------------
// Region construction
// ---------------------------------------------------------------------------------------------

// Two scalar globals, used as guest-address holders so that a chunk op can be given an address that
// lives in a GPR rather than an immediate: that is the mixed-class case (one I32 operand and one
// V512 operand on the same instruction) that nothing in the tree exercised before.
enum GlobalId : RegN {
	G_ADDR0 = 0,
	G_ADDR1,
	G_COUNT,
};

constexpr u16 STATE_OFF_ADDR0 = 0x10;
constexpr u16 STATE_OFF_ADDR1 = 0x14;

StateReg g_state_regs[] = {
    {STATE_OFF_ADDR0, VType::I32, "a0"},
    {STATE_OFF_ADDR1, VType::I32, "a1"},
};
StateInfo g_state_info{g_state_regs, G_COUNT};

VOperand GlobAddr(RegN id)
{
	return VOperand::MakeVGPR(VType::I32, id);
}

VOperand Addr(u32 v)
{
	return VOperand::MakeConst(VType::I32, v);
}

struct TestRegion {
	explicit TestRegion(size_t arena_sz = 4u << 20) : arena(arena_sz)
	{
		region = arena.New<Region>(&arena, &g_state_info);
		bb = region->CreateBlock();
		qb = Builder(bb);
	}

	VOperand NewV()
	{
		return VOperand::MakeVVPR(VType::V512, qb.CreateVGPR(VType::V512));
	}

	MemArena arena;
	Region *region{};
	Block *bb{};
	Builder qb{nullptr};
};

// ---------------------------------------------------------------------------------------------
// The dataflow checker.
//
// QRegAlloc rewrites operands IN PLACE, so after it runs the vreg numbers are gone and only
// physical registers remain.  The QIR-level intent therefore has to be captured first, keyed by
// instruction pointer (stable: the allocator inserts movs but never moves or replaces an existing
// instruction).  Then the post-RA listing is replayed as an abstract machine over ZMMs and frame
// slots, and every typed operand is checked to be carrying the value the QIR said it should.
//
// This is what makes the test independent of which registers the allocator happens to pick, and
// what makes it survive spills: a spill/refill pair is just a value moving between two locations of
// the abstract machine.  A dropped, duplicated or crossed value fails it.
// ---------------------------------------------------------------------------------------------

constexpr i32 VAL_NONE = -1;

struct ChunkIntent {
	i32 def{VAL_NONE};		   // V512 vreg defined by this instruction
	i32 use[2] = {VAL_NONE, VAL_NONE}; // V512 vregs read, in operand order
	u8 n_use{};
};

using IntentMap = std::unordered_map<Inst *, ChunkIntent>;

IntentMap CaptureIntent(Region *r)
{
	IntentMap m;
	for (auto &bb : r->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto op = ins.GetOpcode();
			if (op != Op::_vchunkload && op != Op::_vchunkadd && op != Op::_vchunkstore) {
				continue;
			}
			ChunkIntent ci;
			auto out = ins.outputs();
			for (u8 i = 0; i < out.size(); ++i) {
				if (out[i].GetType() == VType::V512) {
					CHECK(out[i].IsVVPR());
					ci.def = (i32)out[i].GetVVPR();
				}
			}
			auto in = ins.inputs();
			for (u8 i = 0; i < in.size(); ++i) {
				if (in[i].GetType() != VType::V512) {
					continue;
				}
				CHECK(in[i].IsVVPR());
				CHECK(ci.n_use < 2);
				ci.use[ci.n_use++] = (i32)in[i].GetVVPR();
			}
			m[&ins] = ci;
		}
	}
	return m;
}

struct SimResult {
	unsigned n_typed{};
	unsigned n_copy{}, n_spill{}, n_fill{};
	unsigned n_wrong_value{}, n_undefined_read{};
	// Typed operands whose value reached the register through a frame slot, i.e. the reload path
	// was not merely emitted but actually feeds a consumer.  Counted, never assumed.
	unsigned n_use_via_slot{}, n_add_input_via_slot{};
	std::vector<u16> slots;	    // local slot offsets written
	std::vector<u8> chunk_regs; // every ZMM that appeared as a typed chunk operand
};

// key a spill slot by (file, offset): a state offset and a frame offset are unrelated addresses
u32 SlotKey(VOperand o)
{
	return ((u32)o.IsGSlot() << 16) | o.GetSlotOffs();
}

SimResult SimulateV512(Region *r, IntentMap const &intent)
{
	SimResult res;
	i32 zmm[ArchTraits::VPR_NUM];
	bool via_slot[ArchTraits::VPR_NUM] = {};
	std::fill(std::begin(zmm), std::end(zmm), VAL_NONE);
	std::unordered_map<u32, i32> slot;

	auto read_reg = [&](VOperand o, i32 want, char const *what, u32 id, bool is_add_input) {
		CHECK(o.IsPVPR());
		if (!o.IsPVPR()) {
			return;
		}
		res.chunk_regs.push_back(o.GetPVPR());
		if (via_slot[o.GetPVPR()]) {
			++res.n_use_via_slot;
			if (is_add_input) {
				++res.n_add_input_via_slot;
			}
		}
		i32 have = zmm[o.GetPVPR()];
		if (have == VAL_NONE) {
			++res.n_undefined_read;
			fprintf(stderr, "  #%u %s reads zmm%u which holds nothing\n", id, what,
				o.GetPVPR());
			return;
		}
		if (have != want) {
			++res.n_wrong_value;
			fprintf(stderr, "  #%u %s reads zmm%u holding %%v%d, expected %%v%d\n", id, what,
				o.GetPVPR(), have, want);
		}
	};

	for (auto &bb : r->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			u32 id = ins.GetId();
			switch (ins.GetOpcode()) {
			case Op::_mov: {
				auto *u = static_cast<InstUnop *>(&ins);
				auto d = u->o(0), s = u->i(0);
				if (d.GetType() != VType::V512 && s.GetType() != VType::V512) {
					break; // scalar traffic: address fills, etc.
				}
				if (d.IsPVPR() && s.IsPVPR()) {
					++res.n_copy;
					zmm[d.GetPVPR()] = zmm[s.GetPVPR()];
					via_slot[d.GetPVPR()] = via_slot[s.GetPVPR()];
				} else if (d.IsPVPR() && s.IsSlot()) {
					++res.n_fill;
					via_slot[d.GetPVPR()] = true;
					auto it = slot.find(SlotKey(s));
					if (it == slot.end()) {
						++res.n_undefined_read;
						fprintf(stderr,
							"  #%u reloads slot %s:%u that was never written\n",
							id, s.IsGSlot() ? "g" : "l", s.GetSlotOffs());
						zmm[d.GetPVPR()] = VAL_NONE;
					} else {
						zmm[d.GetPVPR()] = it->second;
					}
				} else if (d.IsSlot() && s.IsPVPR()) {
					++res.n_spill;
					slot[SlotKey(d)] = zmm[s.GetPVPR()];
					if (d.IsLSlot()) {
						res.slots.push_back(d.GetSlotOffs());
					}
				} else {
					CHECK(false); // no other V512 mov shape is legal
				}
				break;
			}
			case Op::_vchunkload: {
				++res.n_typed;
				auto *v = static_cast<InstVChunkLoad *>(&ins);
				auto const &ci = intent.at(&ins);
				CHECK(!v->i(0).IsVPR()); // the address is a scalar, always
				CHECK(v->o(0).IsPVPR());
				res.chunk_regs.push_back(v->o(0).GetPVPR());
				zmm[v->o(0).GetPVPR()] = ci.def;
				via_slot[v->o(0).GetPVPR()] = false;
				break;
			}
			case Op::_vchunkadd: {
				++res.n_typed;
				auto *v = static_cast<InstVChunkAdd *>(&ins);
				auto const &ci = intent.at(&ins);
				CHECK_EQ(ci.n_use, 2);
				read_reg(v->i(0), ci.use[0], "vchunkadd.s1", id, true);
				read_reg(v->i(1), ci.use[1], "vchunkadd.s2", id, true);
				CHECK(v->o(0).IsPVPR());
				res.chunk_regs.push_back(v->o(0).GetPVPR());
				// The destination is written after both sources are read, so it may not
				// collide with either: AllocOpOutputV allocates it out of avoid_vpr, which
				// AllocOpInputV has already had both source registers set in.
				CHECK(v->o(0).GetPVPR() != v->i(0).GetPVPR());
				CHECK(v->o(0).GetPVPR() != v->i(1).GetPVPR());
				zmm[v->o(0).GetPVPR()] = ci.def;
				via_slot[v->o(0).GetPVPR()] = false;
				break;
			}
			case Op::_vchunkstore: {
				++res.n_typed;
				auto *v = static_cast<InstVChunkStore *>(&ins);
				auto const &ci = intent.at(&ins);
				CHECK_EQ(ci.n_use, 1);
				CHECK(!v->i(0).IsVPR());
				read_reg(v->i(1), ci.use[0], "vchunkstore.data", id, false);
				break;
			}
			default:
				break;
			}
		}
	}
	return res;
}

// Every register a typed chunk operand ever named must be an allocatable one.  zmm0/zmm1 are
// ArchTraits::VPR_FIXED because Emit_vmload4 and the diagnostic arm use them as unmodelled
// scratch; a typed value landing there would be silently clobbered.
void CheckChunkRegsAllocatable(SimResult const &res)
{
	CHECK(!res.chunk_regs.empty());
	for (auto p : res.chunk_regs) {
		CHECK(p < ArchTraits::VPR_NUM);
		CHECK(ArchTraits::VPR_POOL.Test(p));
		CHECK(!ArchTraits::VPR_FIXED.Test(p));
	}
}

// Frame slots are 64 bytes, 64-byte-strided inside a 1024-byte frame, and must not overlap.
void CheckSlots(SimResult const &res, size_t *n_distinct)
{
	std::vector<u16> uniq = res.slots;
	std::sort(uniq.begin(), uniq.end());
	uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());
	for (auto off : uniq) {
		CHECK_EQ(off % 64, 0);
		CHECK(off + 64 <= ArchTraits::spillframe_size);
	}
	CHECK(uniq.size() <= ArchTraits::spillframe_size / 64u);
	*n_distinct = uniq.size();
}

void RunPipeline(Region *r, MachineRegionInfo *info)
{
	ArchTraits::init();
	QSelPass::run(r, info);
	QRegAllocPass::run(r);
}

// ---------------------------------------------------------------------------------------------

// load A, load B, add, store: the minimal shape the milestone is about.
void BuildBasic(TestRegion &t, VOperand addr_a, VOperand addr_b, VOperand addr_out, u8 sew = 4)
{
	auto a = t.NewV();
	auto b = t.NewV();
	auto sum = t.NewV();
	t.qb.Create_vchunkload(a, addr_a);
	t.qb.Create_vchunkload(b, addr_b);
	t.qb.Create_vchunkadd(sum, a, b, sew);
	t.qb.Create_vchunkstore(addr_out, sum);
}

void D1_dataflow()
{
	printf("D1 typed V512 def-use through QSel and QRegAlloc\n");

	TestRegion t;
	// One address in a GPR (a guest global) and one immediate, so the mixed GPR+VPR operand path
	// and the immediate path are both selected in the same region.
	BuildBasic(t, GlobAddr(G_ADDR0), Addr(GA_B), Addr(GA_OUT));
	auto intent = CaptureIntent(t.region);
	CHECK_EQ(intent.size(), 4u);

	MachineRegionInfo info;
	RunPipeline(t.region, &info);
	Dump("D1", t.region);
	CHECK(!info.has_calls); // no helper, no fallback: this path IS the code

	// Selection must not have rewritten the chunk ops: no table has an alias, and the two guest
	// addresses fit the U32/ANY immediate constraints, so nothing should have been materialized.
	unsigned n_typed = 0, n_vec_mov = 0;
	for (auto &bb : t.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto op = ins.GetOpcode();
			if (op == Op::_vchunkload || op == Op::_vchunkadd || op == Op::_vchunkstore) {
				++n_typed;
			}
			if (op == Op::_mov) {
				auto *u = static_cast<InstUnop *>(&ins);
				if (u->o(0).GetType() == VType::V512) {
					++n_vec_mov;
				}
			}
		}
	}
	CHECK_EQ(n_typed, 4u);
	CHECK_EQ(n_vec_mov, 0u); // three values, thirty registers: nothing to spill or copy

	auto res = SimulateV512(t.region, intent);
	CHECK_EQ(res.n_typed, 4u);
	CHECK_EQ(res.n_wrong_value, 0u);
	CHECK_EQ(res.n_undefined_read, 0u);
	CheckChunkRegsAllocatable(res);

	// Two independent inputs: the two loads did not collapse onto one register.
	std::vector<u8> load_dsts;
	for (auto &bb : t.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_vchunkload) {
				load_dsts.push_back(static_cast<InstVChunkLoad *>(&ins)->o(0).GetPVPR());
			}
		}
	}
	CHECK_EQ(load_dsts.size(), 2u);
	CHECK(load_dsts[0] != load_dsts[1]);

	// The address operand really was allocated a GPR of its own, in the same instruction that got
	// a ZMM -- and the two numbering spaces did not leak into each other.
	unsigned n_gpr_addr = 0;
	for (auto &bb : t.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() != Op::_vchunkload) {
				continue;
			}
			auto a = static_cast<InstVChunkLoad *>(&ins)->i(0);
			CHECK(a.IsPGPR() || a.IsConst());
			if (a.IsPGPR()) {
				++n_gpr_addr;
				CHECK(ArchTraits::GPR_POOL.Test(a.GetPGPR()));
			}
		}
	}
	CHECK_EQ(n_gpr_addr, 1u);
	printf("  typed ops=%u vector movs=%u loads -> zmm%u/zmm%u GPR-held addresses=%u\n", n_typed,
	       n_vec_mov, load_dsts[0], load_dsts[1], n_gpr_addr);
}

// Register pressure.
//
// The construction follows a rule read off the allocator and confirmed in the post-RA trace, not a
// guess: AllocPRegV (qra.cpp:148) returns the LOWEST-numbered register of the target mask, taking
// it by force when nothing is free.  Under sustained pressure that makes exactly ONE register a
// revolving door while every other one keeps whatever it was first given.  Defining both inputs up
// front and then piling on filler loads therefore evicts only the FIRST of them -- the initial
// version of this test did that, asserted two refills, and correctly failed with one.
//
// So the second input is defined in the MIDDLE of the filler run, which puts it into the revolving
// register too.  The assertion is still not a count of spills: it is that each input the add
// consumes arrived through a frame slot, which SimulateV512 tracks per value.
void D2_pressure()
{
	printf("D2 typed values evicted to the frame and reloaded under pressure\n");

	unsigned const n_pool = ArchTraits::VPR_POOL.count();
	TestRegion t;
	auto a = t.NewV();
	t.qb.Create_vchunkload(a, Addr(GA_A));
	// enough to fill the pool and then evict `a` out of the revolving register
	for (unsigned i = 0; i < n_pool; ++i) {
		t.qb.Create_vchunkload(t.NewV(), Addr(GA_FILLER + i * 64));
	}
	auto b = t.NewV();
	t.qb.Create_vchunkload(b, Addr(GA_B)); // lands in the revolving register
	t.qb.Create_vchunkload(t.NewV(), Addr(GA_FILLER + n_pool * 64)); // ... and evicts it
	auto sum = t.NewV();
	t.qb.Create_vchunkadd(sum, a, b, 4);
	t.qb.Create_vchunkstore(Addr(GA_OUT), sum);

	auto intent = CaptureIntent(t.region);
	MachineRegionInfo info;
	RunPipeline(t.region, &info);
	Dump("D2", t.region);

	auto res = SimulateV512(t.region, intent);
	CHECK_EQ(res.n_wrong_value, 0u);
	CHECK_EQ(res.n_undefined_read, 0u);
	CheckChunkRegsAllocatable(res);

	// The load-bearing invariant: the values the add consumes are values that went to memory and
	// came back, so the dataflow above is not passing on a region that never left the register
	// file.  Both are forced by the construction; requiring at least one keeps the test meaningful
	// if the victim rule changes, and the measured number is printed either way.
	CHECK(res.n_add_input_via_slot >= 1);
	CHECK_EQ(res.n_add_input_via_slot, 2u);
	CHECK(res.n_fill >= res.n_add_input_via_slot);

	size_t n_slots = 0;
	CheckSlots(res, &n_slots);
	printf("  loads=%u spills=%u fills=%u distinct slots=%zu add inputs via frame=%u/2\n",
	       n_pool + 3, res.n_spill, res.n_fill, n_slots, res.n_add_input_via_slot);
}

void D3_call_boundary()
{
	printf("D3 typed values survive a call boundary\n");

	TestRegion t;
	auto a = t.NewV();
	auto b = t.NewV();
	t.qb.Create_vchunkload(a, Addr(GA_A));
	t.qb.Create_vchunkload(b, Addr(GA_B));
	// SysV AMD64 has no callee-saved vector register -- ArchTraits::VPR_CALL_CLOBBER is VPR_ALL --
	// so QRegAlloc::CallOp must send BOTH live values to the frame here.  Unlike D2 this is forced
	// by a rule and not by an amount of pressure, so "both inputs came back from a slot" is an
	// exact expectation rather than a tuned one.
	auto *call = t.qb.Create_hcall(RuntimeStubId::id_raise, VOperand::MakeConst(VType::I32, 0));
	auto sum = t.NewV();
	t.qb.Create_vchunkadd(sum, a, b, 4);
	t.qb.Create_vchunkstore(Addr(GA_OUT), sum);

	auto intent = CaptureIntent(t.region);
	MachineRegionInfo info;
	RunPipeline(t.region, &info);
	Dump("D3", t.region);
	CHECK(info.has_calls);

	auto res = SimulateV512(t.region, intent);
	CHECK_EQ(res.n_wrong_value, 0u);
	CHECK_EQ(res.n_undefined_read, 0u);
	CheckChunkRegsAllocatable(res);
	CHECK_EQ(res.n_add_input_via_slot, 2u);

	// Independent of the value tracking: after the call no ZMM may be READ unless something wrote
	// it after the call.  A read of a register last written before the call is a value that
	// crossed a call in a caller-saved register, which is a miscompile even if the abstract
	// machine above happens to agree with it.
	bool written_after[ArchTraits::VPR_NUM] = {};
	unsigned n_stale = 0;
	bool seen_call = false;
	for (auto &bb : t.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (&ins == call) {
				seen_call = true;
				continue;
			}
			auto in = ins.inputs();
			for (u8 i = 0; i < in.size(); ++i) {
				if (seen_call && in[i].IsPVPR() && !written_after[in[i].GetPVPR()]) {
					++n_stale;
					fprintf(stderr, "  #%u reads zmm%u last written before the call\n",
						ins.GetId(), in[i].GetPVPR());
				}
			}
			auto out = ins.outputs();
			for (u8 i = 0; i < out.size(); ++i) {
				if (seen_call && out[i].IsPVPR()) {
					written_after[out[i].GetPVPR()] = true;
				}
			}
		}
	}
	CHECK(seen_call);
	CHECK_EQ(n_stale, 0u);
	size_t n_slots = 0;
	CheckSlots(res, &n_slots);
	printf("  spills=%u fills=%u slots=%zu add inputs via frame=%u/2 stale post-call reads=%u\n",
	       res.n_spill, res.n_fill, n_slots, res.n_add_input_via_slot, n_stale);
}

// ---------------------------------------------------------------------------------------------
// Code emission
// ---------------------------------------------------------------------------------------------

struct TestCompilerRuntime final : CompilerRuntime {
	explicit TestCompilerRuntime(bool executable_ = false) : executable(executable_) {}
	~TestCompilerRuntime()
	{
		if (map_ptr) {
			munmap(map_ptr, map_sz);
		}
	}

	void *AllocateCode(size_t sz, uint align) override
	{
		// Slack for the `ret` appended by the native tests: a hand-built region has no gbr, so
		// nothing terminates it (see RunNative).
		if (!executable) {
			buf.resize(sz + 16);
			return buf.data();
		}
		map_sz = (sz + 16 + 4095) & ~size_t(4095);
		map_ptr = mmap(nullptr, map_sz, PROT_READ | PROT_WRITE | PROT_EXEC,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (map_ptr == MAP_FAILED) {
			map_ptr = nullptr;
			Panic("mmap RWX failed");
		}
		return map_ptr;
	}
	bool AllowsRelocation() const override
	{
		return false; // jit_mode
	}
	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override
	{
		return nullptr;
	}

	bool executable{};
	std::vector<u8> buf;
	void *map_ptr{};
	size_t map_sz{};
};

template <typename F>
std::vector<u8> Assemble(F &&f)
{
	asmjit::CodeHolder code;
	if (code.init(asmjit::Environment::host())) {
		Panic("codeholder init");
	}
	asmjit::x86::Assembler a;
	code.attach(a._emitter());
	f(a);
	code.flatten();
	code.resolveUnresolvedLinks();
	std::vector<u8> out(code.codeSize());
	code.copyFlattenedData(out.data(), out.size());
	return out;
}

std::string Hex(std::vector<u8> const &v, size_t from = 0, size_t to = SIZE_MAX)
{
	std::string s;
	char tmp[4];
	for (size_t i = from; i < v.size() && i < to; ++i) {
		snprintf(tmp, sizeof(tmp), "%02x", v[i]);
		if (!s.empty()) {
			s += ' ';
		}
		s += tmp;
	}
	return s;
}

// The addressing-mode contract, restated from make_vmem (qemit.cpp:957).
//
// It has to be restated rather than assumed, because it is configuration-dependent: with
// DBT_ZERO_MMU_BASE (this build) a guest address is a host address and MEMBASE does not appear in
// the addressing at all -- the emitted form is [reg32] or an absolute [disp32].  The first version
// of this oracle modelled the other branch and every load/store comparison failed, which is what
// surfaced the difference.  CheckAddressBytes below then re-derives the same fact straight out of
// the emitted bytes, so agreement here is not the only evidence.
asmjit::x86::Mem GuestMem(VOperand addr)
{
	asmjit::x86::Mem m;
	if constexpr (config::zero_membase) {
		m = addr.IsPGPR() ? asmjit::x86::ptr(asmjit::x86::gpd(addr.GetPGPR()))
				  : asmjit::x86::ptr(addr.GetConst());
	} else {
		m = addr.IsPGPR()
			? asmjit::x86::ptr(QEmit::R_MEMBASE, asmjit::x86::gpd(addr.GetPGPR()))
			: asmjit::x86::ptr(QEmit::R_MEMBASE, addr.GetConst());
	}
	m.setSize(64);
	return m;
}

// Decode-level facts about the emitted instruction, checked without reference to how it was built.
// An immediate guest address must appear literally as a little-endian u32 inside the instruction;
// a register-held one must not, and the instruction must carry the 0x67 address-size override that
// makes the 32-bit address register a full effective address.
void CheckAddressBytes(std::vector<u8> const &code, size_t at, size_t len, VOperand addr)
{
	if (addr.IsConst()) {
		u32 want = (u32)addr.GetConst();
		bool found = false;
		for (size_t i = at; i + 4 <= at + len; ++i) {
			u32 v;
			memcpy(&v, code.data() + i, 4);
			if (v == want) {
				found = true;
				break;
			}
		}
		CHECK(found);
		if (!found) {
			fprintf(stderr, "  guest address %08x not present in [%s]\n", want,
				Hex(code, at, at + len).c_str());
		}
	} else if constexpr (config::zero_membase) {
		CHECK_EQ(code[at], 0x67u); // 32-bit address size: the guest address is used as-is
	}
}

struct EmittedRegion {
	std::vector<u8> code;
	unsigned n_matched{};
	size_t first_typed_at{}; // where the first typed instruction begins
	size_t end{};		 // one past the last typed instruction
};

// Compile the region and check every typed instruction byte-for-byte against an independently
// assembled encoding of its ALLOCATED operands.  The match is positional, not a loose search: after
// the first typed instruction each one must begin exactly where the previous ended, and the last
// must end at the end of the region.  A missing, extra, reordered or padded instruction fails.
EmittedRegion EmitAndMatch(Region *r, TestCompilerRuntime &cruntime, u8 sew, unsigned n_expected)
{
	EmittedRegion out;
	auto code_span = qcg::GenerateCode(&cruntime, nullptr, r, 0);
	out.code.assign(code_span.begin(), code_span.end());
	CHECK(!out.code.empty());

	size_t cursor = 0;
	bool first = true;
	for (auto &bb : r->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			std::vector<u8> want;
			VOperand addr;
			bool has_addr = false;
			switch (ins.GetOpcode()) {
			case Op::_vchunkload: {
				auto *v = static_cast<InstVChunkLoad *>(&ins);
				auto d = asmjit::x86::Zmm(v->o(0).GetPVPR());
				addr = v->i(0);
				has_addr = true;
				auto m = GuestMem(addr);
				want = Assemble([&](asmjit::x86::Assembler &a) { a.vmovdqu64(d, m); });
				break;
			}
			case Op::_vchunkadd: {
				auto *v = static_cast<InstVChunkAdd *>(&ins);
				auto d = asmjit::x86::Zmm(v->o(0).GetPVPR());
				auto s1 = asmjit::x86::Zmm(v->i(0).GetPVPR());
				auto s2 = asmjit::x86::Zmm(v->i(1).GetPVPR());
				want = Assemble([&](asmjit::x86::Assembler &a) {
					switch (sew) {
					case 1:
						a.vpaddb(d, s1, s2);
						break;
					case 2:
						a.vpaddw(d, s1, s2);
						break;
					case 4:
						a.vpaddd(d, s1, s2);
						break;
					default:
						a.vpaddq(d, s1, s2);
						break;
					}
				});
				break;
			}
			case Op::_vchunkstore: {
				auto *v = static_cast<InstVChunkStore *>(&ins);
				addr = v->i(0);
				has_addr = true;
				auto m = GuestMem(addr);
				auto s = asmjit::x86::Zmm(v->i(1).GetPVPR());
				want = Assemble([&](asmjit::x86::Assembler &a) { a.vmovdqu64(m, s); });
				break;
			}
			default:
				continue;
			}

			size_t at;
			if (first) {
				// The only thing that may precede the first typed instruction is the
				// scalar prologue QRegAlloc emitted for the address globals, so search
				// for it -- but pin everything after it.
				at = SIZE_MAX;
				for (size_t i = 0; i + want.size() <= out.code.size(); ++i) {
					if (memcmp(out.code.data() + i, want.data(), want.size()) == 0) {
						at = i;
						break;
					}
				}
				out.first_typed_at = at;
				first = false;
			} else {
				at = cursor;
			}
			bool ok = at != SIZE_MAX && at + want.size() <= out.code.size() &&
				  memcmp(out.code.data() + at, want.data(), want.size()) == 0;
			CHECK(ok);
			if (!ok) {
				fprintf(stderr, "  sew=%u op=%u at=%zd\n    want: %s\n    code: %s\n", sew,
					to_underlying(ins.GetOpcode()), (ssize_t)at, Hex(want).c_str(),
					Hex(out.code).c_str());
				continue;
			}
			if (has_addr) {
				CheckAddressBytes(out.code, at, want.size(), addr);
			}
			cursor = at + want.size();
			++out.n_matched;
		}
	}
	out.end = cursor;
	CHECK_EQ(out.n_matched, n_expected);
	// Nothing follows the last typed instruction: a hand-built region has no terminator.
	CHECK_EQ(out.end, out.code.size());
	return out;
}

void D4_encoding()
{
	printf("D4 emitted bytes match the allocated operands positionally, SEW selects the opcode\n");

	struct SewCase {
		u8 sew;
		char const *name;
	};
	SewCase const cases[] = {{1, "vpaddb"}, {2, "vpaddw"}, {4, "vpaddd"}, {8, "vpaddq"}};

	std::vector<std::vector<u8>> per_sew_code;
	for (auto const &c : cases) {
		TestRegion t;
		BuildBasic(t, GlobAddr(G_ADDR0), Addr(GA_B), Addr(GA_OUT), c.sew);
		ArchTraits::init();
		TestCompilerRuntime cruntime;
		auto em = EmitAndMatch(t.region, cruntime, c.sew, 4);
		Dump("D4", t.region);
		per_sew_code.push_back(em.code);
		printf("  sew=%u -> %s: %u/4 instructions byte-identical, region %zu bytes, typed run "
		       "[%zu,%zu)\n",
		       c.sew, c.name, em.n_matched, em.code.size(), em.first_typed_at, em.end);
	}

	// Cross-check: the four regions are structurally identical and differ only in the add, so any
	// two must have the same length and differ somewhere.  Equal bytes would mean the SEW field
	// never reached the encoder.
	for (size_t i = 0; i < per_sew_code.size(); ++i) {
		for (size_t k = i + 1; k < per_sew_code.size(); ++k) {
			CHECK_EQ(per_sew_code[i].size(), per_sew_code[k].size());
			CHECK(per_sew_code[i] != per_sew_code[k]);
		}
	}
}

// C2.1b2 extension.  One region, two fully independent chains (BuildBasic, doubled): six fresh
// V512 locals, two vchunkadds that share no operand.  This is the op-level dataflow analogue of
// the two-chunk vadd.vv route's own shape (dbt/guest/rv32_qir.cpp's TRANSLATOR(vadd_vv), C2.1a
// design doc sections 17-18) -- QIR independence, distinct post-QRA allocation, and existing simulation
// correctness for BOTH chains -- with no rvvtypedchunkbegin/end frame and no claim about whether
// the two chains are scheduled together on the host CPU.
void D5_two_independent_adds()
{
	printf("D5 two independent typed adds in one region: six fresh V512 locals, no shared operand\n");

	TestRegion t;
	// Chain 0 and chain 1 use disjoint guest addresses (both immediates, matching D1's other
	// address form) so nothing about addressing ties them together either.
	BuildBasic(t, Addr(GA_A), Addr(GA_B), Addr(GA_OUT), 4);
	BuildBasic(t, Addr(GA_A2), Addr(GA_B2), Addr(GA_OUT2), 4);

	auto intent = CaptureIntent(t.region);
	CHECK_EQ(intent.size(), 8u); // 4 typed ops per chain x 2 chains

	MachineRegionInfo info;
	RunPipeline(t.region, &info);
	Dump("D5", t.region);
	// Neither vchunkadd nor vchunkload/store ever sets HAS_CALLS -- only rvvtypedchunkbegin does,
	// and this file never constructs that frame (see the coverage gap the C2.1a design doc's Part
	// IV records; the frame itself is checked by vaddvv_typedchunk_route_test.cpp instead).
	CHECK(!info.has_calls);

	auto res = SimulateV512(t.region, intent);
	CHECK_EQ(res.n_typed, 8u);
	CHECK_EQ(res.n_wrong_value, 0u);
	CHECK_EQ(res.n_undefined_read, 0u);
	CheckChunkRegsAllocatable(res);

	// The two adds' six operands (two inputs + one output, per add) never alias pairwise --
	// extends D1's "the two loads did not collapse onto one register" check from 2 to 6 values.
	// Each add's own destination-differs-from-its-own-sources property is already individually
	// checked by SimulateV512's Op::_vchunkadd case for every add it processes, so it needs no
	// separate check here.
	std::vector<u8> add_operand_regs;
	for (auto &bb : t.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() != Op::_vchunkadd) {
				continue;
			}
			auto *v = static_cast<InstVChunkAdd *>(&ins);
			add_operand_regs.push_back(v->i(0).GetPVPR());
			add_operand_regs.push_back(v->i(1).GetPVPR());
			add_operand_regs.push_back(v->o(0).GetPVPR());
		}
	}
	CHECK_EQ(add_operand_regs.size(), 6u);
	std::vector<u8> uniq = add_operand_regs;
	std::sort(uniq.begin(), uniq.end());
	uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());
	CHECK_EQ(uniq.size(), 6u); // none of the two adds' six operand registers ever aliases another

	printf("  two chains, six pairwise-distinct ZMMs: zmm%u zmm%u zmm%u / zmm%u zmm%u zmm%u, "
	       "has_calls=%d\n",
	       add_operand_regs[0], add_operand_regs[1], add_operand_regs[2], add_operand_regs[3],
	       add_operand_regs[4], add_operand_regs[5], (int)info.has_calls);
}

// ---------------------------------------------------------------------------------------------
// E1/E2: native execution
// ---------------------------------------------------------------------------------------------

// Enter emitted code with the register and stack contract jitabi.cpp's trampoline_to_jit
// establishes: r13 = STATE, rbp = MEMBASE, and spillframe_size bytes of scratch immediately above
// the return address, so a local slot at [rsp + 8 + offs] lands inside it.  Written out here rather
// than reused because the real trampoline ends in `int3` -- it expects the region to leave through
// qcgstub_escape_*, which a hand-built region with no gbr cannot do.
//
// The stack arithmetic is copied exactly, not approximated: six pushes then `sub 1032` leaves the
// frame 16-byte but NOT 64-byte aligned, which is precisely why the spill/fill path must use
// vmovdqu64.  Making this "more aligned" would silently retire the reason that code is unaligned.
#define TEST_ASM extern "C" __attribute__((noinline, used, naked))

TEST_ASM void vchunk_enter(void *state, void *membase, void *code);
TEST_ASM void vchunk_enter(void *state, void *membase, void *code)
{
	asm("pushq	%rbp\n\t"
	    "pushq	%rbx\n\t"
	    "pushq	%r12\n\t"
	    "pushq	%r13\n\t"
	    "pushq	%r14\n\t"
	    "pushq	%r15\n\t"
	    "movq	%rdi, %r13\n\t"	  // STATE
	    "movq	%rsi, %rbp\n\t"); // MEMBASE
	asm("sub	$%c0, %%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("callq	*%rdx\n\t");
	asm("add	$%c0, %%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("popq	%r15\n\t"
	    "popq	%r14\n\t"
	    "popq	%r13\n\t"
	    "popq	%r12\n\t"
	    "popq	%rbx\n\t"
	    "popq	%rbp\n\t"
	    "retq	\n\t");
}

constexpr size_t STATE_SZ = 4096;

// Guest memory has to live at the guest address itself (DBT_ZERO_MMU_BASE), so it is mapped
// MAP_FIXED_NOREPLACE at GUEST_BASE.  Failing to get that exact address is an environment failure,
// not a reason to skip: the static tests already used those addresses as immediates.
struct NativeEnv {
	NativeEnv()
	{
		guest = (u8 *)mmap((void *)(uptr)GUEST_BASE, GUEST_SZ, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
		ok = guest != MAP_FAILED && (uptr)guest == (uptr)GUEST_BASE;
		CHECK(ok);
		if (!ok) {
			fprintf(stderr, "  could not map guest memory at %08x (got %p)\n", GUEST_BASE,
				guest);
			guest = nullptr;
			return;
		}
		memset(guest, 0, GUEST_SZ);
		state = (u8 *)aligned_alloc(4096, STATE_SZ);
		memset(state, 0, STATE_SZ);
	}
	~NativeEnv()
	{
		if (guest) {
			munmap(guest, GUEST_SZ);
		}
		free(state);
	}
	u32 *Block(u32 guest_addr)
	{
		return (u32 *)(uptr)guest_addr;
	}
	void SetGlobal(u16 state_offs, u32 v)
	{
		memcpy(state + state_offs, &v, 4);
	}
	bool ok{};
	u8 *guest{};
	u8 *state{};
};

// Compile the region with the real QCG entry point, terminate it with a `ret` (a hand-built region
// has no gbr, so nothing else would), and run it.
void RunNative(Region *r, NativeEnv &env, TestCompilerRuntime &cruntime)
{
	auto code = qcg::GenerateCode(&cruntime, nullptr, r, 0);
	CHECK(!code.empty());
	if (code.empty()) {
		return;
	}
	code.data()[code.size()] = 0xC3; // ret
	vchunk_enter(env.state, env.guest, code.data());
}

// Lane data designed so that the answer identifies the SEW.  Lane 0 is 0xFFFFFFFF + 0x00000002:
//   vpaddd -> 0x00000001 and a carry that vanishes
//   vpaddq -> 0x00000001 but the carry lands in lane 1
//   vpaddw -> 0xFFFF0001, vpaddb -> 0xFFFFFF01 (the carry never leaves its sub-lane)
// Lane 6 repeats the trick so a wrong 64-bit pairing is caught at a second position too.
void FillOperands(u32 *a, u32 *b)
{
	for (int i = 0; i < 16; ++i) {
		a[i] = 0x9E3779B9u * (u32)(i + 1) + 0x01234567u;
		b[i] = (0x7F4A7C15u * (u32)(i + 3)) ^ 0xA5A5A5A5u;
	}
	a[0] = 0xFFFFFFFFu;
	b[0] = 0x00000002u;
	a[6] = 0xFFFF0000u;
	b[6] = 0x00020000u;
}

void CheckLanes(char const *tag, u32 const *a, u32 const *b, u32 const *out)
{
	unsigned bad = 0;
	for (int i = 0; i < 16; ++i) {
		u32 want = a[i] + b[i]; // wraps at 32 bits, which is the whole point
		if (out[i] != want) {
			++bad;
			if (bad <= 4) {
				fprintf(stderr, "  %s lane %d: got %08x want %08x\n", tag, i, out[i],
					want);
			}
		}
	}
	CHECK_EQ(bad, 0u);
}

void E1_native_lane_data()
{
	printf("E1 native execution, 16 nontrivial i32 lanes\n");

	NativeEnv env;
	if (!env.ok) {
		return;
	}
	u32 *a = env.Block(GA_A), *b = env.Block(GA_B), *out = env.Block(GA_OUT);
	FillOperands(a, b);
	memset(out, 0xCC, 64);
	// One address arrives in a GPR filled from guest state, one as an immediate: both addressing
	// forms of make_vmem execute here.
	env.SetGlobal(STATE_OFF_ADDR0, GA_A);
	env.SetGlobal(STATE_OFF_ADDR1, GA_OUT);

	TestRegion t;
	BuildBasic(t, GlobAddr(G_ADDR0), Addr(GA_B), GlobAddr(G_ADDR1), 4);
	auto intent = CaptureIntent(t.region);
	ArchTraits::init();

	TestCompilerRuntime cruntime(true);
	RunNative(t.region, env, cruntime);
	Dump("E1", t.region);

	auto res = SimulateV512(t.region, intent);
	CHECK_EQ(res.n_wrong_value, 0u);
	CHECK_EQ(res.n_undefined_read, 0u);
	CheckChunkRegsAllocatable(res);

	CheckLanes("E1", a, b, out);
	printf("  lane0 %08x + %08x = %08x  lane1 %08x (no carry in from lane 0)\n", a[0], b[0], out[0],
	       out[1]);
}

void E2_native_under_pressure()
{
	printf("E2 native execution with both inputs spilled to the JIT frame and refilled\n");

	NativeEnv env;
	if (!env.ok) {
		return;
	}
	u32 *a = env.Block(GA_A), *b = env.Block(GA_B), *out = env.Block(GA_OUT);
	FillOperands(a, b);
	memset(out, 0xCC, 64);

	// Same shape as D2, for the same documented reason: one register revolves under pressure, so
	// the second input has to be defined in the middle of the filler run to be evicted too.
	unsigned const n_pool = ArchTraits::VPR_POOL.count();
	TestRegion t;
	auto va = t.NewV();
	t.qb.Create_vchunkload(va, Addr(GA_A));
	auto filler = [&](unsigned i) {
		u32 ga = GA_FILLER + i * 64;
		u32 *blk = env.Block(ga);
		// Distinct data in every filler block, so a reload that returned the wrong 64 bytes
		// cannot coincidentally produce the right sum.
		for (int k = 0; k < 16; ++k) {
			blk[k] = ((i + 1) << 24) | (u32)k;
		}
		t.qb.Create_vchunkload(t.NewV(), Addr(ga));
	};
	for (unsigned i = 0; i < n_pool; ++i) {
		filler(i);
	}
	auto vb = t.NewV();
	t.qb.Create_vchunkload(vb, Addr(GA_B));
	filler(n_pool);
	auto sum = t.NewV();
	t.qb.Create_vchunkadd(sum, va, vb, 4);
	t.qb.Create_vchunkstore(Addr(GA_OUT), sum);

	auto intent = CaptureIntent(t.region);
	ArchTraits::init();

	TestCompilerRuntime cruntime(true);
	RunNative(t.region, env, cruntime);
	Dump("E2", t.region);

	auto res = SimulateV512(t.region, intent);
	CHECK_EQ(res.n_wrong_value, 0u);
	CHECK_EQ(res.n_undefined_read, 0u);
	CheckChunkRegsAllocatable(res);
	// If this region compiled without a frame round trip, the test would be E1 with more loads.
	CHECK_EQ(res.n_add_input_via_slot, 2u);
	size_t n_slots = 0;
	CheckSlots(res, &n_slots);

	CheckLanes("E2", a, b, out);
	printf("  spills=%u fills=%u slots=%zu add inputs via frame=%u/2; result correct after the "
	       "round trip\n",
	       res.n_spill, res.n_fill, n_slots, res.n_add_input_via_slot);
}

// D4 proves the emitted bytes for each SEW match an independent assembler, and E1 proves sew=4
// computes the right answer on hardware.  Neither proves the OTHER three widths compute what their
// mnemonic says -- an encoding can be byte-identical to an independent assembler and still be the
// wrong instruction for the operation, because both sides would have to agree on which mnemonic to
// use.  This runs all four widths on real data and checks each against a reference that adds at
// that element width, so the SEW -> opcode mapping is settled by execution and not by agreement.
void E3_native_all_sew()
{
	printf("E3 native execution of every SEW against a width-specific reference\n");

	NativeEnv env;
	if (!env.ok) {
		return;
	}
	u32 *a = env.Block(GA_A), *b = env.Block(GA_B), *out = env.Block(GA_OUT);

	struct SewCase {
		u8 sew;
		char const *name;
	};
	SewCase const cases[] = {{1, "vpaddb"}, {2, "vpaddw"}, {4, "vpaddd"}, {8, "vpaddq"}};
	u32 results[4][16];

	for (int c = 0; c < 4; ++c) {
		FillOperands(a, b);
		memset(out, 0xCC, 64);

		TestRegion t;
		BuildBasic(t, Addr(GA_A), Addr(GA_B), Addr(GA_OUT), cases[c].sew);
		ArchTraits::init();
		TestCompilerRuntime cruntime(true);
		RunNative(t.region, env, cruntime);

		// Reference: add at this element width, with carries confined to the element.
		u8 ref[64];
		u8 ba[64], bb[64];
		memcpy(ba, a, 64);
		memcpy(bb, b, 64);
		for (int e = 0; e < 64 / cases[c].sew; ++e) {
			u64 x = 0, y = 0;
			memcpy(&x, ba + e * cases[c].sew, cases[c].sew);
			memcpy(&y, bb + e * cases[c].sew, cases[c].sew);
			u64 s = x + y; // wraps within the element: only sew bytes are stored back
			memcpy(ref + e * cases[c].sew, &s, cases[c].sew);
		}
		bool ok = memcmp(ref, out, 64) == 0;
		CHECK(ok);
		if (!ok) {
			fprintf(stderr, "  sew=%u (%s) lane0 got %08x want %08x\n", cases[c].sew,
				cases[c].name, out[0], *(u32 *)ref);
		}
		memcpy(results[c], out, 64);
		printf("  sew=%u %s: lane0 = %08x (a=%08x b=%08x), 64/64 bytes match the reference\n",
		       cases[c].sew, cases[c].name, out[0], a[0], b[0]);
	}

	// The four widths must actually disagree on this data, otherwise "matches the reference" would
	// be satisfiable by emitting one opcode for all four.  FillOperands puts 0xFFFFFFFF + 2 in
	// lane 0 precisely so that b/w/d differ there, and lane 1 so that q differs from d.
	unsigned n_pairs = 0;
	for (int i = 0; i < 4; ++i) {
		for (int k = i + 1; k < 4; ++k) {
			CHECK(memcmp(results[i], results[k], 64) != 0);
			++n_pairs;
		}
	}
	printf("  all %u width pairs produced different results on this data\n", n_pairs);
}

bool HostHasAvx512()
{
	__builtin_cpu_init();
	return __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512bw");
}

} // namespace

int main()
{
	printf("QCG typed V512 chunk dataflow tests\n");
	printf("  GPR pool=%u  VPR pool=%u  frame=%u bytes  zero_membase=%d\n",
	       ArchTraits::GPR_POOL.count(), ArchTraits::VPR_POOL.count(), ArchTraits::spillframe_size,
	       (int)config::zero_membase);

	D1_dataflow();
	D2_pressure();
	D3_call_boundary();
	D4_encoding();
	D5_two_independent_adds();

	if (HostHasAvx512()) {
		E1_native_lane_data();
		E2_native_under_pressure();
		E3_native_all_sew();
	} else {
		g_skipped = 3;
		printf("E1/E2/E3 SKIPPED: host has no AVX-512F+BW, cannot execute a ZMM instruction\n");
	}

	if (g_failures) {
		printf("FAILED: %d check(s), %d test(s) skipped\n", g_failures, g_skipped);
		return 1;
	}
	if (g_skipped) {
		printf("OK: static checks passed, %d executable test(s) SKIPPED (NOT run on this host)\n",
		       g_skipped);
		return 0;
	}
	printf("OK: all tests passed, 0 skipped\n");
	return 0;
}
