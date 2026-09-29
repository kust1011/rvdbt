// Mechanism tests for the QCG vector register class (qir::RegClass::VPR / AVX-512 ZMM).
//
// SCOPE.  These test the register class and nothing else.  No guest instruction is routed to a
// VPR anywhere in the tree; the regions below are hand-built QIR whose only vector op is `mov`,
// which is exactly the op QRegAlloc itself creates for a copy, a spill and a fill.  Nothing here
// says anything about RVV lowering, about vadd.vv, or about performance.
//
// The tests are deliberately structured as differential or structural checks rather than
// "the allocator picked zmm5" assertions, so they keep their meaning if allocation order changes:
//
//   T1  GPR assignment is bit-identical with and without vector traffic, and vice versa
//       -> the two physical files are tracked independently.
//   T2  vector pressure above the pool size spills, to distinct 64-byte-aligned frame slots,
//       and refills from the same slots.
//   T3  exhausting the 1024-byte spill frame with genuinely simultaneously-live values aborts
//       (fail-closed), verified in a forked child.
//   T4  a call boundary leaves no VPR live: every live vector value is spilled before the call
//       and refilled after it.
//   T5  the emitted encoding is the UNALIGNED vmovdqu64 form, byte-for-byte, and provably not
//       vmovdqa64 -- the spill frame is only 8/16-byte aligned, so the aligned form would #GP.
//   T6  a block-local vector value whose last use precedes a call is NOT spilled at that call,
//       while the same shape with a use after the call still is (C3.1f-fix11).
//   T7  a vector value used in a second block is not retired at its last use in the first one:
//       it is still spilled at an intervening call and refilled where it is used.
//   T8  a region with 256 or more QIR virtual registers reaches a call boundary, RETURNS from it,
//       and still writes back every dirty global -- including one at an index a `u8` counter
//       cannot address (M2B).
//   T9  a narrow vector value (V128/V256) spills into a slot of ITS OWN width, naturally aligned
//       and inside the fixed frame, and every access to that slot carries the same width (M2C).
//
// Runs on any host: nothing here executes the emitted bytes.
//
// C3.1f-fix11 NOTE on T3. The frame-exhaustion case used to build a `BuildVectorChain`, whose
// values are each read exactly once by the next `mov` and are therefore dead immediately: it
// exhausted the frame only because the allocator kept spilling values nothing could read. With
// block-local last-use retirement that chain correctly needs no frame at all, so T3 now builds
// genuinely simultaneously-live pressure (`BuildVectorPressure`: define n, then read all n). That
// is the shape the fail-closed guard is actually for, and it must still abort.

#include "dbt/arena.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qcg/qemit.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <signal.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
using namespace dbt::qcg;

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
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,   \
				#b, (long long)_a, (long long)_b);                                           \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

// Fake guest state.  Only the shape matters: two scalar globals and one vector global, the latter
// giving the tests a V512 value that is already live in memory and can therefore seed a chain of
// vector locals without inventing a vector immediate (there is no such thing).
enum GlobalId : RegN {
	G_S0 = 0,
	G_S1,
	G_V0,
	G_COUNT,
};

StateReg g_state_regs[] = {
    {0x10, VType::I32, "s0"},
    {0x14, VType::I32, "s1"},
    {0x80, VType::V512, "v0"},
};
StateInfo g_state_info{g_state_regs, G_COUNT};

VOperand GlobS(RegN id)
{
	return VOperand::MakeVGPR(VType::I32, id);
}

VOperand GlobV()
{
	return VOperand::MakeVVPR(VType::V512, G_V0);
}

// T8 needs a guest state with more than 256 globals, so the state description is a constructor
// parameter rather than the file-scope default. Every pre-existing test passes neither argument and
// is therefore built exactly as before.
struct TestRegion {
	explicit TestRegion(size_t arena_sz = 4u << 20, StateInfo const *state = &g_state_info)
	    : arena(arena_sz)
	{
		region = arena.New<Region>(&arena, state);
		bb = region->CreateBlock();
		qb = Builder(bb);
	}

	VOperand NewLocalS()
	{
		return VOperand::MakeVGPR(VType::I32, qb.CreateVGPR(VType::I32));
	}

	VOperand NewLocalV()
	{
		return VOperand::MakeVVPR(VType::V512, qb.CreateVGPR(VType::V512));
	}

	MemArena arena;
	Region *region{};
	Block *bb{};
	Builder qb{nullptr};
};

// ---------------------------------------------------------------------------------------------
// Post-RA inspection helpers.  After QRegAllocPass every register operand has been rewritten to a
// physical one, so the instruction list is a faithful record of what the allocator decided.
// ---------------------------------------------------------------------------------------------

struct MovRec {
	VOperand dst, src;
};

std::vector<MovRec> CollectMovs(Region *region, bool vector_only)
{
	std::vector<MovRec> out;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() != Op::_mov) {
				continue;
			}
			auto *u = static_cast<InstUnop *>(&ins);
			bool is_vec = u->o(0).GetType() == VType::V512 || u->i(0).GetType() == VType::V512;
			if (is_vec != vector_only) {
				continue;
			}
			out.push_back({u->o(0), u->i(0)});
		}
	}
	return out;
}

// A textual transcript of every SCALAR register decision, used by T1 to compare two runs.
std::string ScalarAssignment(Region *region)
{
	std::string s;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			bool any = false;
			std::string line = std::to_string(to_underlying(ins.GetOpcode()));
			auto add = [&](VOperand o) {
				if (o.GetType() == VType::V512) {
					return; // vector operands deliberately excluded
				}
				any = true;
				if (o.IsPGPR()) {
					line += " r" + std::to_string(o.GetPGPR());
				} else if (o.IsSlot()) {
					line += (o.IsGSlot() ? " g" : " l") + std::to_string(o.GetSlotOffs());
				} else if (o.IsConst()) {
					line += " $" + std::to_string(o.GetConst());
				} else {
					line += " ?";
				}
			};
			auto outs = ins.outputs();
			for (u8 i = 0; i < outs.size(); ++i) {
				add(outs[i]);
			}
			auto ins_in = ins.inputs();
			for (u8 i = 0; i < ins_in.size(); ++i) {
				add(ins_in[i]);
			}
			if (any) {
				s += line + "\n";
			}
		}
	}
	return s;
}

// The mirror of ScalarAssignment for the vector file.
std::string VectorAssignment(Region *region)
{
	std::string s;
	for (auto &m : CollectMovs(region, true)) {
		auto fmt = [](VOperand o) -> std::string {
			if (o.IsPVPR()) {
				return "zmm" + std::to_string(o.GetPVPR());
			}
			if (o.IsSlot()) {
				return (o.IsGSlot() ? "g" : "l") + std::to_string(o.GetSlotOffs());
			}
			return "?";
		};
		s += fmt(m.dst) + " <- " + fmt(m.src) + "\n";
	}
	return s;
}

void RunRA(Region *region)
{
	ArchTraits::init();
	QRegAllocPass::run(region);
}

// ---------------------------------------------------------------------------------------------

// T1a: a purely scalar region, optionally with vector traffic appended.  The scalar transcript
// must be identical either way.
void BuildScalar(TestRegion &t, unsigned n_locals)
{
	std::vector<VOperand> live;
	for (unsigned i = 0; i < n_locals; ++i) {
		auto l = t.NewLocalS();
		t.qb.Create_mov(l, GlobS(i % 2 == 0 ? G_S0 : G_S1));
		live.push_back(l);
	}
	// keep them all live to the end
	for (auto &l : live) {
		t.qb.Create_mov(GlobS(G_S0), l);
	}
}

void BuildVectorChain(TestRegion &t, unsigned n)
{
	auto cur = t.NewLocalV();
	t.qb.Create_mov(cur, GlobV());
	for (unsigned i = 1; i < n; ++i) {
		auto next = t.NewLocalV();
		t.qb.Create_mov(next, cur);
		cur = next;
	}
}

// Define `n` independent vector locals and then read every one of them back, in definition order.
//
// The second use is the whole point of this shape. QRegAlloc has no liveness (`TODO: liveness` in
// Release), so a value that is defined and never read again still holds a register and still gets
// spilled under pressure -- but nothing ever reloads it. A fill assertion over a define-only chain
// would therefore be satisfiable without the fill path working at all. Consuming every value makes
// a reload of each spilled one mandatory.
//
// Returns the LAST DEFINITION, which splits the post-RA listing into a pressure phase and a
// consumption phase: the allocator inserts an instruction's spills and fills immediately before
// that instruction, so everything the consumption phase needs lands strictly after this one.
qir::Inst *BuildVectorPressure(TestRegion &t, unsigned n)
{
	std::vector<VOperand> live;
	qir::Inst *last_def = nullptr;
	for (unsigned i = 0; i < n; ++i) {
		auto v = t.NewLocalV();
		last_def = t.qb.Create_mov(v, GlobV());
		live.push_back(v);
	}
	for (auto &v : live) {
		t.qb.Create_mov(GlobV(), v);
	}
	return last_def;
}

// T11: SEQUENTIAL groups of vector values, each group dead before the next begins.
//
// This is the minimal reproduction of the `vbor` VLEN-1024 abort. A guest vector run lowers to a
// sequence of typed groups; `rvvtypedchunkbegin` carries HAS_CALLS, so at every group boundary
// CallOp spills every VPR that is still live, and each spilled value takes a frame slot. The
// values of group g are all dead once group g's own last read has run -- AnalyzeVPRRetirement
// proves exactly that and Spill already declines to STORE a retired value. What it did not do was
// give the SLOT back: AllocFrameSlot was a pure bump pointer, so group g's slots stayed owned for
// the rest of the region and group g+1 had to take fresh ones. With a 1024-byte frame and 64-byte
// V512 slots that is 16 slots for the whole region, and a long enough run exhausts them however
// short each group's lifetime is.
//
// The distinction this test draws against T3 is the whole point of the fix:
//   T3  n values SIMULTANEOUSLY live  -> genuinely needs n slots -> must still abort.
//   T11 n values live in disjoint groups -> needs only one group's worth -> must NOT abort.
//
// The bound asserted here is a real invariant, not the observed number: the frame high-water mark
// must be at most one group's simultaneous demand, no matter how many groups the region contains.
void T11_sequential_groups_reuse_frame_slots()
{
	printf("T11 dead vector values return their frame slots\n");

	unsigned const per_group = 8;			      // 8 x 64 B = 512 B, half the frame
	unsigned const n_slots = ArchTraits::spillframe_size / 64;
	unsigned const groups = (n_slots / per_group) * 2 + 2; // demands > 2x the whole frame

	// The child does the work: before the fix this aborts inside QRegAllocPass, and a forked
	// child is the only way to observe that without taking the test binary down with it. On
	// success it reports the frame high-water mark back through a pipe.
	int fds[2];
	CHECK(pipe(fds) == 0);
	fflush(stdout);
	fflush(stderr);
	pid_t pid = fork();
	if (pid == 0) {
		close(fds[0]);
		TestRegion t;
		for (unsigned g = 0; g < groups; ++g) {
			std::vector<VOperand> live;
			for (unsigned i = 0; i < per_group; ++i) {
				auto v = t.NewLocalV();
				t.qb.Create_mov(v, GlobV());
				live.push_back(v);
			}
			// The group boundary. hcall is the same generic HAS_CALLS boundary T4 uses, so
			// every value in `live` must be spilled here -- which is what takes the slots.
			t.qb.Create_hcall(RuntimeStubId::id_raise, VOperand::MakeConst(VType::I32, 0));
			// Last use of every value in this group: after this they are unreachable.
			for (auto &v : live) {
				t.qb.Create_mov(GlobV(), v);
			}
		}
		RunRA(t.region);

		// High-water mark = the highest local slot byte the emitted code actually touches.
		u32 high = 0;
		for (auto &m : CollectMovs(t.region, true)) {
			for (auto o : {m.dst, m.src}) {
				if (o.IsSlot() && !o.IsGSlot()) {
					u32 end = (u32)o.GetSlotOffs() + VTypeToSize(o.GetType());
					high = std::max(high, end);
				}
			}
		}
		ssize_t w = write(fds[1], &high, sizeof(high));
		_exit(w == (ssize_t)sizeof(high) ? 0 : 2);
	}
	CHECK(pid > 0);
	close(fds[1]);
	u32 high = 0;
	ssize_t got = read(fds[0], &high, sizeof(high));
	close(fds[0]);
	int status = 0;
	CHECK(waitpid(pid, &status, 0) == pid);

	if (WIFSIGNALED(status)) {
		fprintf(stderr,
			"  FAIL %s:%d: %u disjoint groups of %u vector values aborted with signal %d "
			"(spill frame exhausted); dead values are not returning their slots\n",
			__FILE__, __LINE__, groups, per_group, WTERMSIG(status));
		++g_failures;
		return;
	}
	CHECK(WIFEXITED(status));
	CHECK_EQ(WEXITSTATUS(status), 0);
	CHECK(got == (ssize_t)sizeof(high));

	// The invariant: never more than one group's simultaneous demand, however many groups there
	// are. Stated as a bound rather than an equality so it survives a change of allocation order.
	if (got == (ssize_t)sizeof(high)) {
		printf("    %u groups x %u values: frame high-water %u B (bound %u B, frame %u B)\n",
		       groups, per_group, high, per_group * 64u, ArchTraits::spillframe_size);
		CHECK(high <= per_group * 64u);
		CHECK(high <= ArchTraits::spillframe_size);
	}
}

void T1_isolation()
{
	printf("T1 GPR/VPR tracking isolation\n");

	// Enough scalar locals to fill the GPR pool but not overflow it, so any interference from the
	// vector file would show up as a changed register or a new spill.
	unsigned const n_scalar = ArchTraits::GPR_POOL.count() - 2;

	std::string scalar_alone, scalar_with_vec;
	{
		TestRegion t;
		BuildScalar(t, n_scalar);
		RunRA(t.region);
		scalar_alone = ScalarAssignment(t.region);
	}
	{
		TestRegion t;
		BuildScalar(t, n_scalar);
		BuildVectorChain(t, 8);
		RunRA(t.region);
		scalar_with_vec = ScalarAssignment(t.region);
	}
	CHECK(scalar_alone == scalar_with_vec);
	if (scalar_alone != scalar_with_vec) {
		fprintf(stderr, "--- scalar alone ---\n%s--- with vectors ---\n%s", scalar_alone.c_str(),
			scalar_with_vec.c_str());
	}

	// And the converse: scalar pressure, including scalar spilling, must not perturb the vector
	// assignment.
	std::string vec_alone, vec_with_scalar;
	{
		TestRegion t;
		BuildVectorChain(t, 8);
		RunRA(t.region);
		vec_alone = VectorAssignment(t.region);
	}
	{
		TestRegion t;
		BuildScalar(t, ArchTraits::GPR_POOL.count() + 8); // forces scalar spills
		BuildVectorChain(t, 8);
		RunRA(t.region);
		vec_with_scalar = VectorAssignment(t.region);
	}
	CHECK(vec_alone == vec_with_scalar);
	if (vec_alone != vec_with_scalar) {
		fprintf(stderr, "--- vec alone ---\n%s--- with scalars ---\n%s", vec_alone.c_str(),
			vec_with_scalar.c_str());
	}

	// Every vector register the allocator handed out is a legal pool member, and no scalar
	// operand ever became a VPR.
	TestRegion t;
	BuildScalar(t, n_scalar);
	BuildVectorChain(t, 8);
	RunRA(t.region);
	unsigned n_vec_movs = 0;
	for (auto &m : CollectMovs(t.region, true)) {
		++n_vec_movs;
		for (auto o : {m.dst, m.src}) {
			if (!o.IsPVPR()) {
				continue;
			}
			CHECK(o.GetPVPR() < ArchTraits::VPR_NUM);
			CHECK(ArchTraits::VPR_POOL.Test(o.GetPVPR()));
			CHECK(!ArchTraits::VPR_FIXED.Test(o.GetPVPR()));
		}
	}
	CHECK(n_vec_movs >= 8);
	for (auto &m : CollectMovs(t.region, false)) {
		CHECK(!m.dst.IsVPR());
		CHECK(!m.src.IsVPR());
	}
}

void T2_spill_fill()
{
	printf("T2 vector spill/fill and frame slots\n");

	// More simultaneously-live vector values than the pool holds -> the allocator must spill; and
	// every one of them is read again afterwards -> each spilled one must come back.
	unsigned const n = ArchTraits::VPR_POOL.count() + 4;
	TestRegion t;
	auto *last_def = BuildVectorPressure(t, n);
	RunRA(t.region);

	unsigned n_local_spill = 0, n_local_fill = 0;
	std::vector<u16> spill_offsets;	       // every local slot written, in emission order
	std::vector<u16> pressure_spill_offs;  // ... those written while pressure was building
	std::vector<u16> consumption_fill_offs; // ... local slots read back while consuming
	bool after_defs = false;
	for (auto &bb : t.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (&ins == last_def) {
				after_defs = true;
				continue;
			}
			if (ins.GetOpcode() != Op::_mov) {
				continue;
			}
			auto *u = static_cast<InstUnop *>(&ins);
			auto d = u->o(0), s = u->i(0);
			if (d.IsLSlot() && s.IsPVPR()) {
				++n_local_spill;
				spill_offsets.push_back(d.GetSlotOffs());
				CHECK_EQ(VTypeToSize(d.GetType()), 64);
				if (!after_defs) {
					pressure_spill_offs.push_back(d.GetSlotOffs());
				}
			}
			if (d.IsPVPR() && s.IsLSlot()) {
				++n_local_fill;
				if (after_defs) {
					consumption_fill_offs.push_back(s.GetSlotOffs());
				}
			}
		}
	}
	CHECK(after_defs);
	CHECK(n_local_spill >= 4);
	CHECK(!pressure_spill_offs.empty());

	// Frame slots are 64 bytes and live inside the frame.
	for (auto off : spill_offsets) {
		CHECK_EQ(off % 64, 0);
		CHECK(off + 64 <= ArchTraits::spillframe_size);
	}
	// A track's slot is allocated once (the NO_SPILL guard in AllocFrameSlot) and a re-spill of an
	// already-synced value emits nothing (spill_synced in SyncSpill); no local in this region is
	// ever redefined. So within this region a repeated offset can only mean two different values
	// were handed the same 64 bytes.
	std::vector<u16> uniq = spill_offsets;
	std::sort(uniq.begin(), uniq.end());
	uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());
	CHECK_EQ(uniq.size(), spill_offsets.size());

	// The real fill assertion: every value evicted while pressure was building is read again in
	// the consumption phase, so every one of those slots must be reloaded from.
	for (auto off : pressure_spill_offs) {
		bool refilled = std::find(consumption_fill_offs.begin(), consumption_fill_offs.end(),
					  off) != consumption_fill_offs.end();
		CHECK(refilled);
		if (!refilled) {
			fprintf(stderr, "  slot l:%u spilled under pressure but never reloaded\n", off);
		}
	}
	// and no reload invents a slot that was never written
	for (auto off : consumption_fill_offs) {
		CHECK(std::find(spill_offsets.begin(), spill_offsets.end(), off) != spill_offsets.end());
	}
	printf("  spills=%u (pressure %zu) fills=%u (consumption %zu) distinct slots=%zu\n",
	       n_local_spill, pressure_spill_offs.size(), n_local_fill, consumption_fill_offs.size(),
	       uniq.size());
}

void T3_frame_overflow_fails_closed()
{
	printf("T3 spill-frame exhaustion fails closed\n");

	// The frame is a fixed 1024 bytes and a V512 slot eats 64, so 16 spilled vector values fill
	// it. Ask for far more than that. Panic() is noreturn (abort), so the attempt runs in a
	// forked child and the parent asserts on the death signal -- the point of the test is that
	// the allocator does NOT quietly reuse or overlap a slot.
	//
	// The pressure must be REAL: BuildVectorPressure defines n values and only then reads all n,
	// so every one of them is live across every other one's definition and none can be retired
	// early (C3.1f-fix11). A chain of singly-used values would legitimately need no frame at all
	// now, and would test nothing.
	unsigned const n_slots = ArchTraits::spillframe_size / 64;
	unsigned const n = ArchTraits::VPR_POOL.count() + n_slots * 2;

	fflush(stdout);
	fflush(stderr);
	pid_t pid = fork();
	if (pid == 0) {
		TestRegion t;
		BuildVectorPressure(t, n);
		RunRA(t.region);
		_exit(0); // reached only if the overflow went unnoticed
	}
	CHECK(pid > 0);
	int status = 0;
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFSIGNALED(status));
	if (WIFSIGNALED(status)) {
		CHECK_EQ(WTERMSIG(status), SIGABRT);
	} else {
		fprintf(stderr, "  child exited %d instead of aborting\n", WEXITSTATUS(status));
	}
}

void T4_call_boundary()
{
	printf("T4 no VPR live across a call\n");

	unsigned const n_live = 4;
	TestRegion t;
	std::vector<VOperand> live;
	auto cur = t.NewLocalV();
	t.qb.Create_mov(cur, GlobV());
	live.push_back(cur);
	for (unsigned i = 1; i < n_live; ++i) {
		auto next = t.NewLocalV();
		t.qb.Create_mov(next, cur);
		live.push_back(next);
		cur = next;
	}

	// hcall is the generic call boundary (Flags::HAS_CALLS -> QRegAlloc::CallOp). Its argument is
	// a constant so the scalar side of the region needs no allocation.
	auto *call = t.qb.Create_hcall(RuntimeStubId::id_raise, VOperand::MakeConst(VType::I32, 0));

	// use every value after the call, forcing refills if they were spilled
	for (auto &l : live) {
		t.qb.Create_mov(GlobV(), l);
	}

	RunRA(t.region);

	// A local slot offset and a state slot offset are unrelated addresses, so a slot is identified
	// by (file, offset).
	auto slot_key = [](VOperand o) { return ((u32)o.IsGSlot() << 16) | o.GetSlotOffs(); };

	// The load-bearing invariant: after the call, no ZMM may be read unless something wrote it
	// after the call. A read of a register last written before the call IS a value that survived
	// the call in a caller-saved ZMM, which SysV does not permit -- and it is observable here
	// without predicting which register the allocator picks. (Checking that a reloaded value lands
	// in a *different* ZMM than it had before would not be a real invariant: the register is free
	// again after the call, so reusing the same number is legal.)
	bool zmm_written_after[ArchTraits::VPR_NUM] = {};
	unsigned n_stale_reads = 0;
	std::vector<u32> spilled_before, filled_after;
	bool seen_call = false;

	for (auto &bb : t.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (&ins == call) {
				seen_call = true;
				continue;
			}
			auto in = ins.inputs();
			for (u8 i = 0; i < in.size(); ++i) {
				auto o = in[i];
				if (!seen_call) {
					continue;
				}
				if (o.IsPVPR() && !zmm_written_after[o.GetPVPR()]) {
					++n_stale_reads;
					fprintf(stderr,
						"  #%u reads zmm%u, last written before the call\n",
						ins.GetId(), o.GetPVPR());
				}
				if (o.IsSlot() && o.GetType() == VType::V512) {
					filled_after.push_back(slot_key(o));
				}
			}
			auto out = ins.outputs();
			for (u8 i = 0; i < out.size(); ++i) {
				auto o = out[i];
				if (seen_call && o.IsPVPR()) {
					zmm_written_after[o.GetPVPR()] = true;
				}
				if (!seen_call && o.IsSlot() && o.GetType() == VType::V512) {
					spilled_before.push_back(slot_key(o));
				}
			}
		}
	}
	CHECK(seen_call);
	CHECK_EQ(n_stale_reads, 0u);

	// Preservation, the other half: the values were not merely dropped. Each of the n_live values
	// is used after the call, so each must have been written to a slot before it and reloaded from
	// that same slot after it.
	CHECK(spilled_before.size() >= n_live);
	CHECK(filled_after.size() >= n_live);
	for (auto k : filled_after) {
		bool preserved = std::find(spilled_before.begin(), spilled_before.end(), k) !=
				 spilled_before.end();
		CHECK(preserved);
		if (!preserved) {
			fprintf(stderr, "  post-call reload from slot %s:%u never written pre-call\n",
				(k >> 16) ? "g" : "l", k & 0xffff);
		}
	}
	printf("  spilled before call=%zu reloaded after=%zu stale reads=%u\n", spilled_before.size(),
	       filled_after.size(), n_stale_reads);
}

// ---------------------------------------------------------------------------------------------
// T6/T7: block-local last-use retirement (C3.1f-fix11)
// ---------------------------------------------------------------------------------------------

// Every V512 `mov` that touches a LOCAL slot, i.e. the spill frame -- the only thing
// AllocFrameSlot hands out. A V512 mov touching a GLOBAL slot is a CPUState access for the vector
// global and is deliberately not counted: `hcall` legitimately syncs dirty globals to CPUState on
// both sides of these tests, and that traffic is not what the frame limit is about.
struct FrameTraffic {
	std::vector<u16> spills_before, spills_after; // local slot written (spill)
	std::vector<u16> fills_before, fills_after;   // local slot read (fill)
	unsigned stale_reads = 0;		      // ZMM read after the call, last written before it
	bool seen_call = false;
};

FrameTraffic FrameTrafficAround(Region *region, qir::Inst const *call)
{
	FrameTraffic ft;
	bool zmm_written_after[ArchTraits::VPR_NUM] = {};
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (&ins == call) {
				ft.seen_call = true;
				continue;
			}
			auto in = ins.inputs();
			for (u8 i = 0; i < in.size(); ++i) {
				auto o = in[i];
				if (ft.seen_call && o.IsPVPR() && !zmm_written_after[o.GetPVPR()]) {
					++ft.stale_reads;
					fprintf(stderr, "  #%u reads zmm%u, last written before the call\n",
						ins.GetId(), o.GetPVPR());
				}
				if (o.IsLSlot() && o.GetType() == VType::V512) {
					(ft.seen_call ? ft.fills_after : ft.fills_before)
					    .push_back(o.GetSlotOffs());
				}
			}
			auto out = ins.outputs();
			for (u8 i = 0; i < out.size(); ++i) {
				auto o = out[i];
				if (ft.seen_call && o.IsPVPR()) {
					zmm_written_after[o.GetPVPR()] = true;
				}
				if (o.IsLSlot() && o.GetType() == VType::V512) {
					(ft.seen_call ? ft.spills_after : ft.spills_before)
					    .push_back(o.GetSlotOffs());
				}
			}
		}
	}
	return ft;
}

// The differential the fix is about. Two regions of the SAME shape -- define a vector local, read
// it, cross a call boundary -- differing only in whether one more read follows the call.
//
// `hcall` is HAS_CALLS, and SysV has no callee-saved ZMM, so QRegAlloc::CallOp offers every
// resident VPR to Spill. Whether Spill stores it is exactly the question: a value whose last use
// is already behind it cannot be read again, so storing it would burn one of the sixteen 64-byte
// frame slots on bytes nothing loads. That leak, repeated per typed group, is what exhausted the
// frame on K1.
void T6_retire_before_call()
{
	printf("T6 block-local value dead before a call is not spilled\n");

	unsigned n_dead_spills = 0, n_live_spills = 0, n_live_fills = 0;
	{ // a single-definition value with no reads is dead immediately after its definition
		TestRegion t;
		for (unsigned i = 0; i < 20; ++i) {
			t.qb.Create_mov(t.NewLocalV(), GlobV());
		}
		auto *call = t.qb.Create_hcall(RuntimeStubId::id_raise, VOperand::MakeConst(VType::I32, 0));
		RunRA(t.region);
		auto ft = FrameTrafficAround(t.region, call);
		CHECK(ft.seen_call);
		CHECK_EQ(ft.spills_before.size() + ft.spills_after.size(), 0u);
	}

	{ // dead: last use precedes the call
		TestRegion t;
		auto v = t.NewLocalV();
		t.qb.Create_mov(v, GlobV());
		t.qb.Create_mov(GlobV(), v); // final consumer
		auto *call = t.qb.Create_hcall(RuntimeStubId::id_raise, VOperand::MakeConst(VType::I32, 0));
		RunRA(t.region);

		auto ft = FrameTrafficAround(t.region, call);
		CHECK(ft.seen_call);
		n_dead_spills = ft.spills_before.size() + ft.spills_after.size();
		// Nothing may reach the spill frame at all: no store, and therefore no slot.
		CHECK_EQ(n_dead_spills, 0u);
		CHECK_EQ(ft.fills_before.size() + ft.fills_after.size(), 0u);
	}

	{ // live control: identical up to the call, but read once more after it
		TestRegion t;
		auto v = t.NewLocalV();
		t.qb.Create_mov(v, GlobV());
		t.qb.Create_mov(GlobV(), v); // NOT the final consumer this time
		auto *call = t.qb.Create_hcall(RuntimeStubId::id_raise, VOperand::MakeConst(VType::I32, 0));
		t.qb.Create_mov(GlobV(), v); // final consumer, after the call
		RunRA(t.region);

		auto ft = FrameTrafficAround(t.region, call);
		CHECK(ft.seen_call);
		CHECK_EQ(ft.stale_reads, 0u); // it may not survive the call in a caller-saved ZMM
		n_live_spills = ft.spills_before.size();
		n_live_fills = ft.fills_after.size();
		// It is genuinely live across the call, so it must be stored before it and reloaded from
		// that same slot after it.
		CHECK_EQ(n_live_spills, 1u);
		CHECK_EQ(n_live_fills, 1u);
		if (n_live_spills == 1 && n_live_fills == 1) {
			CHECK_EQ(ft.spills_before[0], ft.fills_after[0]);
		}
	}

	printf("  dead-before-call frame spills=%u; live-across-call frame spills=%u fills=%u\n",
	       n_dead_spills, n_live_spills, n_live_fills);
}

// The conservative half: retirement is only allowed when the definition AND every use are in one
// block. Here the value is defined and used in block A and used AGAIN in block B, so its last use
// in block A is not its last use at all. Retiring it there would drop it at the call and leave
// block B reading a register somebody else may own -- so the allocator must keep treating it as
// live, spill it at the call, and refill it in block B.
//
// (If a regression retired it anyway, AllocOpInputV's "use of a retired VPR value" Panic aborts
// this executable, which is a loud failure rather than a silent one.)
void T7_cross_block_not_retired()
{
	printf("T7 cross-block value is not retired at its last use in the defining block\n");

	TestRegion t;
	auto v = t.NewLocalV();
	t.qb.Create_mov(v, GlobV());
	t.qb.Create_mov(GlobV(), v); // last use IN BLOCK A, but not in the region
	auto *call = t.qb.Create_hcall(RuntimeStubId::id_raise, VOperand::MakeConst(VType::I32, 0));

	Block *b_next = t.region->CreateBlock();
	t.qb.Create_br(0u);
	t.bb->AddSucc(b_next);

	Builder qb_next(b_next);
	qb_next.Create_mov(GlobV(), v); // the real final consumer, in another block

	RunRA(t.region);

	auto ft = FrameTrafficAround(t.region, call);
	CHECK(ft.seen_call);
	CHECK_EQ(ft.stale_reads, 0u);
	CHECK_EQ(ft.spills_before.size(), 1u);
	CHECK_EQ(ft.fills_after.size(), 1u);
	if (ft.spills_before.size() == 1 && ft.fills_after.size() == 1) {
		CHECK_EQ(ft.spills_before[0], ft.fills_after[0]);
	}

	// The refill must be in the block that uses it, not left behind in block A.
	bool fill_in_second_block = false;
	for (auto &ins : b_next->ilist) {
		if (ins.GetOpcode() != Op::_mov) {
			continue;
		}
		auto *u = static_cast<InstUnop *>(&ins);
		if (u->o(0).IsPVPR() && u->i(0).IsLSlot() && u->i(0).GetType() == VType::V512) {
			fill_in_second_block = true;
		}
	}
	CHECK(fill_in_second_block);
	printf("  spilled at the call=%zu refilled in the second block=%d\n", ft.spills_before.size(),
	       (int)fill_in_second_block);
}

// ---------------------------------------------------------------------------------------------
// T8: a region with 256 or more QIR virtual registers still reaches, and returns from, CallOp
// (M2B).
//
// WHAT BROKE.  QRegAlloc::CallOp's global-writeback scan used a `u8` induction variable against
// the `u16` n_vregs (qra.cpp). MAX_VREGS is 512, so at n_vregs >= 256 the counter wrapped
// 255 -> 0 and the loop never exited: translation did not finish, at all, ever. M2A measured the
// threshold end to end -- at VLEN 1024 a 36-vadd chain translated in 0.17 s and a 37-vadd chain
// did not terminate in 90 s -- and every gdb sample stopped inside CallOp.
//
// WHY THE EXISTING TESTS MISSED IT.  T1-T7 above are shape tests; their largest region is a few
// dozen vregs (T3's frame-exhaustion case is the biggest and is bounded by the 1024-byte frame,
// not by the vreg count). None of them can reach 256 tracks, so none of them could ever have
// executed the wrapping loop.
//
// THE TWO HALVES, deliberately split, because one assertion cannot cover both failure modes:
//
//   T8a  TERMINATION on the shape the real workload has. Nothing about a truncated scan is
//        observable here, and it is not claimed to be.
//   T8b  NO SILENTLY MISSED GLOBAL. The global this writes lives at index 259 in a register the
//        callee does not preserve responsibility for, so a "fix" that merely bounds the scan at
//        255 leaves it unsynced and fails, while the correct index type passes.
//
// Both run in a forked child under a hard alarm. That is what makes the OLD behaviour a reported
// FAILURE with a named cause instead of a test binary that hangs forever.
// ---------------------------------------------------------------------------------------------

// A second guest state, wide enough that a global can live at an index a `u8` cannot address.
constexpr RegN WIDE_GLOBALS = 260;
constexpr RegN WIDE_LOW = 0;
constexpr RegN WIDE_HIGH = WIDE_GLOBALS - 1; // 259: past any 8-bit truncation point

char g_wide_names[WIDE_GLOBALS][8];
StateReg g_wide_state_regs[WIDE_GLOBALS];
StateInfo g_wide_state_info{g_wide_state_regs, WIDE_GLOBALS};

u16 WideStateOffs(RegN i)
{
	return (u16)(0x100 + i * 4);
}

void InitWideStateInfo()
{
	for (RegN i = 0; i < WIDE_GLOBALS; ++i) {
		snprintf(g_wide_names[i], sizeof(g_wide_names[i]), "g%u", (unsigned)i);
		g_wide_state_regs[i] = {WideStateOffs(i), VType::I32, g_wide_names[i]};
	}
}

VOperand GlobW(RegN id)
{
	return VOperand::MakeVGPR(VType::I32, id);
}

// Every CPUState (global-slot) offset written by a register-to-slot `mov` strictly BEFORE `call`.
// That store is the only way a dirty guest global reaches memory in time for the callee to read
// it, so this list is exactly "the globals that were synced at the call boundary".
std::vector<u16> GlobalSyncsBefore(Region *region, qir::Inst const *call)
{
	std::vector<u16> out;
	bool seen_call = false;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (&ins == call) {
				seen_call = true;
				continue;
			}
			if (seen_call || ins.GetOpcode() != Op::_mov) {
				continue;
			}
			auto *u = static_cast<InstUnop *>(&ins);
			if (u->o(0).IsGSlot() && (u->i(0).IsPGPR() || u->i(0).IsPVPR())) {
				out.push_back(u->o(0).GetSlotOffs());
			}
		}
	}
	return out;
}

bool Synced(std::vector<u16> const &syncs, u16 offs)
{
	return std::find(syncs.begin(), syncs.end(), offs) != syncs.end();
}

// Run `fn` in a forked child under `timeout_s` of alarm. The child inherits stderr, uses the same
// CHECK macros, and exits nonzero if any of them tripped. A child that never returns is reaped as
// killed-by-SIGALRM and reported as a non-terminating allocator -- which is precisely the old
// behaviour, and is why this is a failing test rather than a hung one.
template <typename F>
void RunChildWithWatchdog(char const *tag, unsigned timeout_s, F &&fn)
{
	fflush(stdout);
	fflush(stderr);
	pid_t pid = fork();
	if (pid == 0) {
		alarm(timeout_s);
		fn();
		fflush(stdout);
		fflush(stderr);
		_exit(g_failures ? 1 : 0);
	}
	CHECK(pid > 0);
	int status = 0;
	CHECK(waitpid(pid, &status, 0) == pid);
	if (WIFSIGNALED(status)) {
		int const sig = WTERMSIG(status);
		fprintf(stderr, "  FAIL %s: allocator child killed by signal %d%s\n", tag, sig,
			sig == SIGALRM ? " (watchdog: QRegAlloc::CallOp did not terminate)" : "");
		++g_failures;
		return;
	}
	CHECK(WIFEXITED(status));
	if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
		fprintf(stderr, "  FAIL %s: child reported %d failed check(s)\n", tag,
			WEXITSTATUS(status));
		++g_failures;
	}
}

// T8a. The region the real workload produces: many SHORT-LIVED vector values and one call
// boundary. n_vregs is a whole-region count fixed before allocation starts, so what matters is the
// TOTAL number of virtual registers, not the peak pressure -- which is why this can exceed 256
// tracks without going anywhere near the 16-slot vector spill frame that T3 covers.
void T8a_large_region_terminates()
{
	printf("T8a a 256+ vreg region with a call boundary terminates\n");

	// 3 V512 locals per group, matching the per-chunk load/load/compute shape; 90 groups is 270
	// vector locals + 1 scalar local + 3 globals = 274 tracks, comfortably over 256 and well
	// under MAX_VREGS (512).
	unsigned const n_groups = 90;

	RunChildWithWatchdog("T8a", 30, [&] {
		TestRegion t;
		for (unsigned g = 0; g < n_groups; ++g) {
			auto a = t.NewLocalV();
			t.qb.Create_mov(a, GlobV());
			auto b = t.NewLocalV();
			t.qb.Create_mov(b, GlobV());
			auto c = t.NewLocalV();
			t.qb.Create_mov(c, a);
			// Consume both, so each value has a real last use and the block-local
			// retirement of C3.1f-fix11 can drop it: this is pressure in COUNT, not in
			// simultaneous liveness.
			t.qb.Create_mov(GlobV(), b);
			t.qb.Create_mov(GlobV(), c);
		}
		// Make both scalar globals dirty immediately before the boundary as well, so the call
		// has something to sync in each register file.
		auto s = t.NewLocalS();
		t.qb.Create_mov(s, GlobS(G_S0));
		t.qb.Create_mov(GlobS(G_S0), s);
		t.qb.Create_mov(GlobS(G_S1), s);

		auto *call = t.qb.Create_hcall(RuntimeStubId::id_raise, VOperand::MakeConst(VType::I32, 0));

		// The trigger condition itself is asserted, not assumed: if a future harness change
		// drops this region under 256 tracks the test says so instead of quietly passing.
		auto const n_all = t.region->GetVRegsInfo()->NumAll();
		CHECK(n_all >= 256);
		CHECK(n_all < 512); // MAX_VREGS: past this the allocator legitimately Panics

		RunRA(t.region); // the old u8 loop never returns from here

		auto const syncs = GlobalSyncsBefore(t.region, call);
		CHECK(Synced(syncs, g_state_regs[G_S0].state_offs));
		CHECK(Synced(syncs, g_state_regs[G_S1].state_offs));
		CHECK(Synced(syncs, g_state_regs[G_V0].state_offs));
		printf("  T8a: tracks=%u returned, globals synced at the call=%zu\n", (unsigned)n_all,
		       syncs.size());
	});
}

// T8b. The anti-truncation half.
//
// `mov g259 <- g0` is deliberately the whole region: with exactly two simultaneously live values
// the allocator's scan order is determined, the input takes the first pool register and the
// high-index global takes the second -- which is a CALL-SAVED one. CallOp's first loop only spills
// GPR_CALL_CLOBBER, so that global is reachable ONLY through the global-writeback scan. Bound that
// scan at 255 and g259 is never written back; the callee then reads a stale CPUState word.
//
// The call-saved placement is verified rather than assumed. If allocation order ever changes so
// that the high global lands in a call-clobbered register, this test FAILS with that reason
// instead of passing vacuously while testing nothing.
void T8b_high_index_global_is_synced()
{
	printf("T8b a global above index 255 is still synced at a call boundary\n");

	RunChildWithWatchdog("T8b", 30, [&] {
		InitWideStateInfo();
		TestRegion t(4u << 20, &g_wide_state_info);

		auto *def = t.qb.Create_mov(GlobW(WIDE_HIGH), GlobW(WIDE_LOW));
		auto *call = t.qb.Create_hcall(RuntimeStubId::id_raise, VOperand::MakeConst(VType::I32, 0));

		auto const n_all = t.region->GetVRegsInfo()->NumAll();
		CHECK(n_all >= 256);
		CHECK(n_all < 512);

		RunRA(t.region); // the old u8 loop never returns from here

		// Precondition, checked not assumed: g259 is dirty in a register the first CallOp loop
		// does not touch.
		auto dst = static_cast<InstUnop *>(def)->o(0);
		CHECK(dst.IsPGPR());
		if (dst.IsPGPR()) {
			bool const call_saved = ArchTraits::GPR_CALL_SAVED.Test(dst.GetPGPR());
			CHECK(call_saved);
			if (!call_saved) {
				fprintf(stderr,
					"  T8b setup no longer exercises the global scan: g%u landed in "
					"call-clobbered r%u\n",
					(unsigned)WIDE_HIGH, (unsigned)dst.GetPGPR());
			}
		}

		// The assertion the repair exists for.
		auto const syncs = GlobalSyncsBefore(t.region, call);
		bool const high_synced = Synced(syncs, WideStateOffs(WIDE_HIGH));
		CHECK(high_synced);
		if (!high_synced) {
			fprintf(stderr,
				"  g%u (CPUState+0x%x) was NOT written back before the call: a truncated "
				"scan hands the callee a stale global\n",
				(unsigned)WIDE_HIGH, (unsigned)WideStateOffs(WIDE_HIGH));
		}
		printf("  T8b: tracks=%u g%u in r%u (call-saved) synced=%d\n", (unsigned)n_all,
		       (unsigned)WIDE_HIGH, dst.IsPGPR() ? (unsigned)dst.GetPGPR() : 99u,
		       (int)high_synced);
	});
}

// ---------------------------------------------------------------------------------------------
// T9 (M2C): the allocator handles a NARROW vector value at its own width.
//
// A V128 is the same physical register file as a V512, so nothing about allocation changes -- but
// the SLOT does. QRegAlloc::AllocFrameSlot sizes and aligns a spill slot with VTypeToSize, and
// QEmit::make_slot sizes the `Mem` operand with the same function, so a V128 must spill 16 bytes
// into a 16-byte slot. If the two ever disagreed, a spill would write past its slot and corrupt the
// neighbouring one; if the slot were sized 64 regardless, the fixed 1024-byte frame would hold four
// times fewer narrow values than it can.
//
// The frame is 1024 bytes, so V128 pressure is checked with far more values than a V512 frame could
// hold -- which is itself the observation: 40 spilled V128 values fit, 40 V512 ones would not.
// ---------------------------------------------------------------------------------------------

// A T9-private guest state carrying one global of each vector width, so a narrow local can be
// seeded from a same-width value already live in memory. Private rather than added to
// g_state_info: every other test's global set -- and therefore its spill transcript -- stays
// exactly what it was.
StateReg g_t9_state_regs[] = {
    {0x10, VType::I32, "s0"},
    {0x80, VType::V128, "w128"},
    {0x100, VType::V256, "w256"},
    {0x180, VType::V512, "w512"},
};
StateInfo g_t9_state_info{g_t9_state_regs, 4};

RegN T9GlobalFor(VType type)
{
	return type == VType::V128 ? 1 : type == VType::V256 ? 2 : 3;
}

void T9_narrow_vector_frame_slots(VType type, u16 want_bytes, char const *name)
{
	printf("T9 %s spill slots are %u bytes\n", name, (unsigned)want_bytes);
	CHECK_EQ(VTypeToSize(type), (u8)want_bytes);
	CHECK(VTypeToRegClass(type) == RegClass::VPR);

	// The same shape BuildVectorPressure uses and for the same reason: define n values, then read
	// every one of them, so none can be retired early and the pressure is real. n is the pool plus
	// a small overflow -- enough to force spills, few enough that the fixed frame is not the thing
	// under test (T3 owns that).
	unsigned const n = ArchTraits::VPR_POOL.count() + 5;
	auto glob = VOperand::MakeVVPR(type, T9GlobalFor(type));

	TestRegion t(4u << 20, &g_t9_state_info);
	std::vector<VOperand> live;
	for (unsigned i = 0; i < n; ++i) {
		auto v = VOperand::MakeVVPR(type, t.qb.CreateVGPR(type));
		t.qb.Create_mov(v, glob);
		live.push_back(v);
	}
	for (auto &v : live) {
		t.qb.Create_mov(glob, v);
	}
	RunRA(t.region);

	// Every LOCAL slot access (the spill frame; a global slot is CPUState and is not what
	// AllocFrameSlot hands out) and the width each access carried.
	std::vector<u16> offs;
	unsigned n_access = 0, n_wrong_width = 0;
	for (auto &bb : t.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() != Op::_mov) {
				continue;
			}
			auto *u = static_cast<InstUnop *>(&ins);
			for (auto o : {u->o(0), u->i(0)}) {
				if (!o.IsLSlot() || !qir::IsVectorVType(o.GetType())) {
					continue;
				}
				++n_access;
				if (o.GetType() != type) {
					++n_wrong_width;
				}
				offs.push_back(o.GetSlotOffs());
			}
		}
	}
	CHECK(n_access > 0);
	CHECK_EQ(n_wrong_width, 0u);

	std::sort(offs.begin(), offs.end());
	offs.erase(std::unique(offs.begin(), offs.end()), offs.end());
	CHECK(!offs.empty());
	for (auto o : offs) {
		// Naturally aligned to its own width, and the WHOLE value inside the frame -- the two
		// properties AllocFrameSlot is responsible for, and both are functions of VTypeToSize.
		CHECK_EQ((u32)o % want_bytes, 0u);
		CHECK((u32)o + want_bytes <= ArchTraits::spillframe_size);
	}
	// Distinct values never overlap: consecutive distinct slots are at least one width apart. At
	// 64 bytes this is the pre-existing T2 invariant; at 16 and 32 it is what proves the slot is
	// sized by the VALUE and not by a constant.
	unsigned min_stride = ArchTraits::spillframe_size;
	for (size_t i = 1; i < offs.size(); ++i) {
		unsigned const d = (unsigned)(offs[i] - offs[i - 1]);
		CHECK(d >= want_bytes);
		min_stride = std::min(min_stride, d);
	}
	printf("  %s: %u slot accesses, %zu distinct slots, min stride %u, all inside %u bytes\n",
	       name, n_access, offs.size(), offs.size() > 1 ? min_stride : (unsigned)want_bytes,
	       (unsigned)ArchTraits::spillframe_size);
}

// ---------------------------------------------------------------------------------------------
// T5: encoding
// ---------------------------------------------------------------------------------------------

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override
	{
		return false; // jit_mode
	}
	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override
	{
		return nullptr;
	}
	std::vector<u8> buf;
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

bool Contains(std::vector<u8> const &hay, std::vector<u8> const &needle, size_t from, size_t *at)
{
	if (needle.empty() || needle.size() > hay.size()) {
		return false;
	}
	for (size_t i = from; i + needle.size() <= hay.size(); ++i) {
		if (memcmp(hay.data() + i, needle.data(), needle.size()) == 0) {
			*at = i;
			return true;
		}
	}
	return false;
}

void T5_encoding()
{
	printf("T5 emitted encoding is the unaligned EVEX form\n");

	// A region with all three legal V512 mov shapes: a fill, a copy, and a spill (to a local slot,
	// forced by pressure). The pressure shape rather than a chain, for the same reason T3 uses it:
	// a chain's values are each dead after their single use and, since C3.1f-fix11, are retired
	// instead of spilled -- so a chain would silently stop covering the spill encoding.
	unsigned const n = ArchTraits::VPR_POOL.count() + 2;
	TestRegion t;
	BuildVectorPressure(t, n);
	RunRA(t.region);

	// is_leaf: the region has no call, matching what GenerateCode would pass.
	bool const is_leaf = true;
	u32 const sp_offs = sizeof(uptr) * (is_leaf ? 1 : 2);

	TestCompilerRuntime cruntime;
	QEmit ce(t.region, &cruntime, nullptr, is_leaf);
	ce.Prologue(0);
	for (auto &bb : t.region->GetBlocks()) {
		ce.SetBlock(&bb);
		for (auto &ins : bb.ilist) {
			CHECK_EQ(to_underlying(ins.GetOpcode()), to_underlying(Op::_mov));
			ce.Emit_mov(static_cast<InstUnop *>(&ins));
		}
	}
	auto code_span = ce.EmitCode();
	std::vector<u8> code(code_span.begin(), code_span.end());
	CHECK(!code.empty());

	auto mem_of = [&](VOperand o) {
		auto base = o.IsLSlot() ? QEmit::R_SP : QEmit::R_STATE;
		u32 off = o.GetSlotOffs() + (o.IsLSlot() ? sp_offs : 0);
		return asmjit::x86::Mem(base, off, 64);
	};

	unsigned n_copy = 0, n_spill = 0, n_fill = 0;
	size_t cursor = 0;
	for (auto &m : CollectMovs(t.region, true)) {
		std::vector<u8> want, aligned_variant;
		if (m.dst.IsPVPR() && m.src.IsPVPR()) {
			++n_copy;
			auto d = asmjit::x86::Zmm(m.dst.GetPVPR()), s = asmjit::x86::Zmm(m.src.GetPVPR());
			want = Assemble([&](asmjit::x86::Assembler &a) { a.vmovdqu64(d, s); });
			aligned_variant = Assemble([&](asmjit::x86::Assembler &a) { a.vmovdqa64(d, s); });
		} else if (m.dst.IsPVPR() && m.src.IsSlot()) {
			++n_fill;
			auto d = asmjit::x86::Zmm(m.dst.GetPVPR());
			auto s = mem_of(m.src);
			want = Assemble([&](asmjit::x86::Assembler &a) { a.vmovdqu64(d, s); });
			aligned_variant = Assemble([&](asmjit::x86::Assembler &a) { a.vmovdqa64(d, s); });
		} else if (m.dst.IsSlot() && m.src.IsPVPR()) {
			++n_spill;
			auto d = mem_of(m.dst);
			auto s = asmjit::x86::Zmm(m.src.GetPVPR());
			want = Assemble([&](asmjit::x86::Assembler &a) { a.vmovdqu64(d, s); });
			aligned_variant = Assemble([&](asmjit::x86::Assembler &a) { a.vmovdqa64(d, s); });
		} else {
			CHECK(false); // no other shape may exist
			continue;
		}

		size_t at = 0;
		bool found = Contains(code, want, cursor, &at);
		CHECK(found);
		if (found) {
			cursor = at + want.size();
		}

		// The aligned form must be absent everywhere, not merely unused here: the spill frame is
		// only 8/16-byte aligned, so vmovdqa64 on a 64-byte slot would #GP at run time.
		size_t unused = 0;
		CHECK(!Contains(code, aligned_variant, 0, &unused));
	}

	// EVEX prefix, i.e. a genuinely 512-bit encoding rather than a widened SSE/VEX one.
	CHECK(std::find(code.begin(), code.end(), 0x62) != code.end());
	CHECK(n_fill >= 1);
	CHECK(n_copy + n_spill >= 1);
	printf("  code=%zu bytes copies=%u spills=%u fills=%u\n", code.size(), n_copy, n_spill, n_fill);
}

// ---------------------------------------------------------------------------------------------
// T10.  CAN A THREE-OPERAND V512 INSTRUCTION'S DESTINATION TAKE THE ZMM OF A SOURCE THAT IS READ
// FOR THE LAST TIME BY THAT SAME INSTRUCTION?
//
// This is the question a residency model has to answer before it can count registers: at a
// definition step, is the demand `|live-in| + 1` (the new value coexists with every source it is
// computed from -- "model A"), or `max(|live-in|, |live-out|)` (a dying source's register is
// recycled into the destination on the spot -- "model B")?  The two differ by one register at
// every definition whose sources die there, which is most of them in a rotate/add/xor kernel.
//
// The allocator's answer is structural and does not depend on retirement: AllocOp allocates every
// input first and `avoid_vpr.Set(p)` each one, then AllocOpOutputV calls AllocPRegV(cr,
// avoid_vpr), whose `target = desire & ~avoid` excludes all three of AllocPRegV's loops -- the
// free-register loop, the retired-parking loop and the spill loop.  Retirement only makes it
// doubly impossible: RetireAt runs after the whole instruction has been allocated.
//
// The test is a differential, not an "it picked zmm5" assertion:
//
//   T10a  live-in exactly fills the pool and TWO of those live values are sources dying at the
//         instruction -> if the destination could take one of them, no spill would be needed.
//         A spill is emitted, and the destination is neither source register.  (Model B is
//         falsified here; under model B this case has 0 spills.)
//   T10b  the same shape with one fewer live value -> no spill at all, and the frame ends up
//         using exactly `live-in + 1` distinct ZMMs.  This is what makes T10a's spill mean
//         "one register more than live-in" rather than "this shape always spills".
//   T10c  a SECOND definition immediately after T10a's -> it reclaims one of the two registers
//         the first instruction's dying sources held, and emits no further spill.  So the
//         registers are free from the next instruction onward and only the defining instruction
//         itself cannot have them: the boundary is exactly one instruction wide.
//
// vchunkadd is used because it is the routed non-destructive three-operand chunk op (CT(r_r_r),
// no ALIAS) whose emitter is a single EVEX instruction.  Nothing here executes the code.
// ---------------------------------------------------------------------------------------------

struct ThreeOpResult {
	// Every slot access in the region, of either kind.  Counting slot TRAFFIC rather than local
	// spill stores is deliberate: the allocator's victim may be a clean value (a filled-but-
	// unwritten global is exactly that), and evicting one of those emits no store at all -- only
	// the reload that brings it back is observable.  A metric that counted stores would report
	// "no eviction" for precisely the case this test is about.
	unsigned fills{0};  // mov pzmm <- slot, anywhere in the region
	unsigned spills{0}; // mov slot <- pzmm, anywhere in the region
	unsigned spills_after{0};	 // ... of those, after the first vchunkadd
	int dst{-1}, src0{-1}, src1{-1}; // physical ZMM numbers after RA
	int dst2{-1};			 // T10c's second definition
	unsigned distinct_zmm{0};
	// The registers the values that are LIVE ACROSS the instruction occupy, read back from their
	// post-instruction consumers.  Meaningful only when nothing was evicted (fills/spills tell
	// you that), in which case each one is also the register the value held AT the instruction.
	unsigned live_pregs{0};	     // how many distinct registers those values occupy
	bool dst_hits_live{false};   // did the destination land on one of them?
};

// n_live: how many vector locals are kept live ACROSS the vchunkadd, in addition to the two
// sources that die at it and the vector global that is live from the first fill onward.
ThreeOpResult RunThreeOperandShape(unsigned n_live, bool second_def)
{
	TestRegion t;
	std::vector<VOperand> live;
	for (unsigned i = 0; i < n_live; ++i) {
		auto v = t.NewLocalV();
		t.qb.Create_mov(v, GlobV());
		live.push_back(v);
	}
	// The two sources.  Their ONLY reads are the vchunkadd below, so each is at its last use
	// there -- the model-B opportunity.
	auto a = t.NewLocalV();
	auto b = t.NewLocalV();
	t.qb.Create_mov(a, GlobV());
	t.qb.Create_mov(b, GlobV());

	auto d = t.NewLocalV();
	auto *add = t.qb.Create_vchunkadd(d, a, b, (u8)4);

	qir::Inst *add2 = nullptr;
	if (second_def) {
		// Two of the values that are live across `add`, so this instruction needs a register
		// that neither it nor `add` is reading.
		auto e = t.NewLocalV();
		add2 = t.qb.Create_vchunkadd(e, live[0], live[1], (u8)4);
		t.qb.Create_mov(GlobV(), e);
	}
	// A READ of the vector global, placed immediately after the definition and BEFORE anything
	// writes the global.  It is what makes an eviction observable: the global is clean, so
	// evicting it stores nothing, and if the next reference to it were a write (`mov GlobV(), d`
	// below) the allocator would simply give it a fresh register and the eviction would leave no
	// trace at all.  With this read in the way, a global that lost its register must be reloaded.
	auto w = t.NewLocalV();
	t.qb.Create_mov(w, GlobV());
	t.qb.Create_mov(GlobV(), d);
	std::vector<qir::Inst *> consumers;
	for (auto &v : live) {
		// keeps every one of them live across `add`; the pointer is kept so the register each
		// one occupies can be read back after allocation
		consumers.push_back(t.qb.Create_mov(GlobV(), v));
	}
	t.qb.Create_mov(GlobV(), w);
	RunRA(t.region);

	ThreeOpResult r;
	bool past_add = false;
	for (auto &bb : t.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (&ins == add) {
				past_add = true;
				continue;
			}
			if (ins.GetOpcode() != Op::_mov) {
				continue;
			}
			auto *u = static_cast<InstUnop *>(&ins);
			auto dv = u->o(0), sv = u->i(0);
			if (dv.IsPVPR() && sv.IsSlot()) {
				++r.fills;
			}
			if (dv.IsSlot() && sv.IsPVPR()) {
				++r.spills;
				if (past_add) {
					++r.spills_after;
				}
			}
		}
	}

	auto *ai = static_cast<InstVChunkAdd *>(add);
	CHECK(ai->o(0).IsPVPR() && ai->i(0).IsPVPR() && ai->i(1).IsPVPR());
	r.dst = ai->o(0).GetPVPR();
	r.src0 = ai->i(0).GetPVPR();
	r.src1 = ai->i(1).GetPVPR();
	if (add2) {
		auto *a2 = static_cast<InstVChunkAdd *>(add2);
		CHECK(a2->o(0).IsPVPR());
		r.dst2 = a2->o(0).GetPVPR();
	}

	std::vector<int> lp;
	for (auto *c : consumers) {
		auto *u = static_cast<InstUnop *>(c);
		CHECK(u->i(0).IsPVPR());
		lp.push_back(u->i(0).GetPVPR());
	}
	std::sort(lp.begin(), lp.end());
	lp.erase(std::unique(lp.begin(), lp.end()), lp.end());
	r.live_pregs = lp.size();
	r.dst_hits_live = std::find(lp.begin(), lp.end(), r.dst) != lp.end();

	std::vector<int> seen;
	for (auto &bb : t.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto note = [&](VOperand o) {
				if (o.IsPVPR()) {
					seen.push_back(o.GetPVPR());
				}
			};
			auto outs = ins.outputs();
			for (u8 i = 0; i < outs.size(); ++i) {
				note(outs[i]);
			}
			auto in = ins.inputs();
			for (u8 i = 0; i < in.size(); ++i) {
				note(in[i]);
			}
		}
	}
	std::sort(seen.begin(), seen.end());
	seen.erase(std::unique(seen.begin(), seen.end()), seen.end());
	r.distinct_zmm = seen.size();
	return r;
}

void T10_three_operand_dst_cannot_take_a_dying_source()
{
	printf("T10 three-operand V512: destination vs a source dying at the same instruction\n");

	unsigned const pool = ArchTraits::VPR_POOL.count();
	// The vector global occupies one pool register from its first fill on and is never retired
	// (globals are excluded from AnalyzeVPRRetirement), so `pool - 3` locals + the two dying
	// sources + the global is exactly `pool` values live entering the vchunkadd.
	unsigned const n_saturating = pool - 3;

	auto sat = RunThreeOperandShape(n_saturating, false);
	// One fewer value live across the instruction: `live-in + 1 == pool`, so the definition
	// still costs a register of its own but there is one left to give it.
	auto fit = RunThreeOperandShape(n_saturating - 1, false);

	printf("  T10a live-in=%u (=pool) dst=zmm%d src=(zmm%d,zmm%d) slot fills=%u spills=%u\n",
	       pool, sat.dst, sat.src0, sat.src1, sat.fills, sat.spills);
	printf("  T10b live-in=%u dst=zmm%d src=(zmm%d,zmm%d) slot fills=%u spills=%u "
	       "distinct zmm used=%u\n",
	       pool - 1, fit.dst, fit.src0, fit.src1, fit.fills, fit.spills, fit.distinct_zmm);

	// THE PRESSURE DIFFERENTIAL.  The two shapes differ by ONE value live across the
	// instruction, and in both of them two sources die at it.  Under model A the demand at the
	// definition is `live-in + 1`, so T10a overflows the pool and T10b does not, and the extra
	// slot traffic is the visible consequence.  Under model B the demand is
	// `max(live-in, live-out)` = `pool` in BOTH shapes, nothing would be evicted in either, and
	// the two totals would be EQUAL -- which is the outcome this assertion excludes.  The exact
	// size of the excess is not asserted: once one value has been displaced the shape's tail
	// redistributes registers, and that redistribution is not what is under test.
	CHECK(sat.fills + sat.spills > fit.fills + fit.spills);
	CHECK(sat.dst != sat.src0);
	CHECK(sat.dst != sat.src1);
	CHECK(fit.dst != fit.src0);
	CHECK(fit.dst != fit.src1);
	// `pool - 1` live in, one destination, and no eviction -> exactly `pool` registers were
	// needed.  Under model B this would be `pool - 1`.
	CHECK_EQ(fit.distinct_zmm, pool);
	CHECK_EQ(sat.distinct_zmm, pool);

	// The same statement without any counting of slot traffic, in the shape where nothing was
	// evicted (so every value still holds at its consumer the register it held at the
	// instruction): the destination is disjoint from ALL of them AND from both dying sources, so
	// `n_live + 2 + 1` registers were needed simultaneously at a `n_live + 2`-input step.
	CHECK_EQ(fit.live_pregs, n_saturating - 1);
	CHECK(!fit.dst_hits_live);
	printf("  T10b values live across the instruction hold %u distinct zmm, the two dying "
	       "sources 2 more, and the destination is none of those %u\n",
	       fit.live_pregs, fit.live_pregs + 2);

	// The very next definition may have what the previous one could not.
	auto nxt = RunThreeOperandShape(n_saturating, true);
	printf("  T10c second definition dst2=zmm%d (first insn's dying sources were zmm%d,zmm%d) "
	       "slot spills after it=%u\n",
	       nxt.dst2, nxt.src0, nxt.src1, nxt.spills_after);
	CHECK(nxt.dst2 == nxt.src0 || nxt.dst2 == nxt.src1);
}

} // namespace

int main()
{
	printf("QCG VPR register-class mechanism tests\n");
	printf("  GPR pool=%u  VPR pool=%u  frame=%u bytes\n", ArchTraits::GPR_POOL.count(),
	       ArchTraits::VPR_POOL.count(), ArchTraits::spillframe_size);

	T1_isolation();
	T2_spill_fill();
	T3_frame_overflow_fails_closed();
	T4_call_boundary();
	T5_encoding();
	T6_retire_before_call();
	T7_cross_block_not_retired();
	T8a_large_region_terminates();
	T8b_high_index_global_is_synced();
	T9_narrow_vector_frame_slots(VType::V128, 16, "V128");
	T9_narrow_vector_frame_slots(VType::V256, 32, "V256");
	T9_narrow_vector_frame_slots(VType::V512, 64, "V512");
	T10_three_operand_dst_cannot_take_a_dying_source();
	T11_sequential_groups_reuse_frame_slots();

	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("OK\n");
	return 0;
}
