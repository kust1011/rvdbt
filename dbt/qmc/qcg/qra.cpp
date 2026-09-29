#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir_builder.h"
#include "dbt/config.h"

#include <cstdio>

namespace dbt::qcg
{

struct QRegAlloc {
	static constexpr auto N_PREGS = ArchTraits::GPR_NUM;
	static constexpr auto PREGS_POOL = ArchTraits::GPR_POOL;
	// The vector file is tracked by a second, independent set of maps and masks.  Nothing below
	// ever indexes one file's array with the other file's register number, and no RegMask mixes
	// the two: a `p` is only meaningful together with its RTrack's `cls`.
	static constexpr auto N_VPREGS = ArchTraits::VPR_NUM;
	static constexpr auto VPREGS_POOL = ArchTraits::VPR_POOL;
	static constexpr auto MAX_VREGS = 2048; // Long RVV blocks can exceed 512 tracks before temp reuse.

	struct RTrack {
		RTrack() {}
		NO_COPY(RTrack)
		NO_MOVE(RTrack)

		static constexpr auto NO_SPILL = static_cast<u16>(-1);

		qir::VType type{};
		// Which physical file `p` refers to.  Derived once from `type` (qir::VTypeToRegClass) at
		// track creation, never inferred later.
		qir::RegClass cls{qir::RegClass::GPR};
		bool is_global{};
		u16 spill_offs{NO_SPILL};

	private:
		friend QRegAlloc;

		enum class Location : u8 {
			DEAD,
			MEM,
			REG,
		};

		qir::RegN p{};
		Location loc{Location::DEAD};
		bool spill_synced{false}; // valid if loc is REG
		bool pinned{false}; // 2026-06-21 --qcg-pin: held in a reserved host reg for the whole region (loop-carried)
		// Block-local last-use retirement (see AnalyzeVPRRetirement).  Set once this value's final
		// consumer has been allocated, which is only ever done for a non-global VPR-class local whose
		// definition and every use were proven to lie in one block.  It is never set on a GPR track,
		// so every scalar decision in this file is bit-identical to before.
		bool retired{false};
	};

	QRegAlloc(qir::Region *region_);
	void Run();

	qir::RegN AllocPReg(RegMask desire, RegMask avoid);
	qir::RegN AllocPRegV(RegMask desire, RegMask avoid);
	void EmitSpill(RTrack *v);
	void EmitFill(RTrack *v);
	void EmitMov(qir::VOperand pdst, qir::VOperand psrc);
	void Spill(qir::RegN p);
	void SpillV(qir::RegN p);
	void Spill(RTrack *v);
	void SyncSpill(RTrack *v);
	template <bool kill>
	void Release(RTrack *v);
	void AllocFrameSlot(RTrack *v);
	void FreeFrameSlot(RTrack *v);
	void NoteChunkGroup(bool open) { chunk_group_open = open; }
	void RefuseInsideChunkGroup(char const *what);
	void Fill(RTrack *v, RegMask desire, RegMask avoid);

	RTrack *AddTrack();
	RTrack *AddTrackGlobal(qir::VType type, u16 state_offs);
	RTrack *AddTrackLocal(qir::VType type);

	void AnalyzeVPRRetirement();
	void RetireAt(qir::Inst const *ins);

	void Prologue();
	void PinSelect();
	void BlockBoundary();
	void RegionBoundary();

	void AllocOp(qir::Inst *ins);
	void AllocOpInputV(qir::VOperand *opr, RAOpCt const &ct, RegMask &avoid_vpr);
	void AllocOpOutputV(qir::VOperand *opr, RAOpCt const &ct, RegMask &avoid_vpr);
	void CallOp(bool use_globals = true);

	static constexpr u16 frame_size{ArchTraits::spillframe_size};

	qir::Region *region{};
	qir::VRegsInfo const *vregs_info{};
	qir::Builder qb{nullptr};

	RegMask fixed{ArchTraits::GPR_FIXED};
	RegMask fixed_vpr{ArchTraits::VPR_FIXED};
	u16 frame_cur{0};

	// True between an rvvtypedchunkbegin and its rvvtypedchunkend.  The group is emitted under a
	// guard whose fallback arm BRANCHES OVER the body, so any instruction the allocator inserts
	// inside it would be skipped on that arm (qemit.cpp Emit_mov).  QEmit already refuses such a
	// mov; this flag lets the allocator refuse it one layer earlier, where the live-value counts
	// that explain WHY it was needed are still in scope.
	bool chunk_group_open{false};

	// Spill-frame free list (AllocFrameSlot / FreeFrameSlot).  `frame_cur` remains the bump
	// pointer for never-before-used bytes; this recycles the slots of values that are provably
	// dead.  Bucketed by exact slot size so a recycled slot keeps the natural alignment the bump
	// path gave it, and so a wide value can never land in a narrow hole.  The frame is
	// `frame_size` bytes and the narrowest slot is 1 byte, so `frame_size` entries is an
	// unreachable upper bound on how many slots can exist at once -- no allocation, no growth.
	struct FrameFree {
		u16 n{0};
		std::array<u16, frame_size / 8> offs{};
	};
	static constexpr u8 kFrameBuckets = 8; // slot sizes 1,2,4,8,16,32,64 -> log2 index 0..6
	std::array<FrameFree, kFrameBuckets> frame_free{};

	u16 n_vregs{0};
	u16 n_globals{0};
	std::array<RTrack, MAX_VREGS> vregs{};
	std::array<RTrack *, N_PREGS> p2v{nullptr};
	std::array<RTrack *, N_VPREGS> p2v_vpr{nullptr};

	// Block-local last-use retirement state (AnalyzeVPRRetirement / RetireAt).  Sized like `vregs`
	// and kept in the same fixed arrays: a vreg is queued at most once, so `retire_seq` can never
	// need more entries than there are tracks, and the allocator still allocates no memory.
	struct VRetire {
		qir::Block const *blk{nullptr};	    // the one block referencing this vreg, if any
		qir::Inst const *last_use{nullptr}; // last instruction of `blk` that READS it
		u8 definitions{0};	    // saturated at 2; only a single definition can retire at its definition
		bool multi_block{false};	    // referenced from more than one block -> never retired
		bool queued{false};		    // already has an entry in retire_seq
	};
	struct VRetirePoint {
		qir::Inst const *ins{nullptr};
		qir::RegN vreg{};
	};
	std::array<VRetire, MAX_VREGS> vretire{};
	std::array<VRetirePoint, MAX_VREGS> retire_seq{};
	u16 n_retire{0};
	u16 retire_pos{0};

	// Physical-file accessor. The ONLY place a class maps to a map; every caller goes through it
	// so that no code path can index the wrong array.
	RTrack *&PhysSlot(RTrack const *v)
	{
		switch (v->cls) {
		case qir::RegClass::GPR:
			assert(v->p < N_PREGS);
			return p2v[v->p];
		case qir::RegClass::VPR:
			assert(v->p < N_VPREGS);
			return p2v_vpr[v->p];
		default:
			Panic("QRegAlloc: vreg has no host register file (unsupported VType)");
		}
	}
};

QRegAlloc::QRegAlloc(qir::Region *region_) : region(region_), vregs_info(region->GetVRegsInfo())
{
	n_globals = vregs_info->NumGlobals();
	auto n_all = vregs_info->NumAll();

	for (u16 i = 0; i < n_globals; ++i) {
		auto *gr = vregs_info->GetGlobalInfo(i);
		AddTrackGlobal(gr->type, gr->state_offs);
	}

	for (u16 i = n_globals; i < n_all; ++i) {
		auto type = vregs_info->GetLocalType(i);
		AddTrackLocal(type);
	}
}

qir::RegN QRegAlloc::AllocPReg(RegMask desire, RegMask avoid)
{
	RegMask target = desire & ~avoid;
	for (qir::RegN p = 0; p < N_PREGS; ++p) {
		if (!p2v[p] && target.Test(p)) {
			return p;
		}
	}

	for (qir::RegN p = 0; p < N_PREGS; ++p) {
		if (target.Test(p)) {
			Spill(p);
			return p;
		}
	}
	Panic("Cannot allocate preg");
}

// Vector twin of AllocPReg, over the independent ZMM file.  Deliberately a separate function
// rather than a parameterised one: the GPR path above must stay byte-for-byte what it was.
qir::RegN QRegAlloc::AllocPRegV(RegMask desire, RegMask avoid)
{
	RegMask target = desire & ~avoid;
	for (qir::RegN p = 0; p < N_VPREGS; ++p) {
		if (!p2v_vpr[p] && target.Test(p)) {
			return p;
		}
	}

	// A register still parked by a RETIRED value before one holding a live value: reclaiming the
	// former emits nothing and takes no frame slot (Spill drops it), while evicting a live value
	// below costs a 64-byte spill out of the fixed frame.  Only when no retired parking remains
	// does a genuinely live value get spilled -- which is what keeps real pressure fail-closed.
	for (qir::RegN p = 0; p < N_VPREGS; ++p) {
		if (target.Test(p) && p2v_vpr[p] && p2v_vpr[p]->retired) {
			SpillV(p);
			return p;
		}
	}

	for (qir::RegN p = 0; p < N_VPREGS; ++p) {
		if (target.Test(p)) {
			SpillV(p);
			return p;
		}
	}
	Panic("Cannot allocate vpreg");
}

// The physical operand naming `v`'s current register, in whichever file it lives.
static inline qir::VOperand MakePhysOperand(qir::RegClass cls, qir::VType type, qir::RegN p)
{
	switch (cls) {
	case qir::RegClass::GPR:
		return qir::VOperand::MakePGPR(type, p);
	case qir::RegClass::VPR:
		return qir::VOperand::MakePVPR(type, p);
	default:
		Panic("QRegAlloc: vreg has no host register file (unsupported VType)");
	}
}

void QRegAlloc::EmitSpill(RTrack *v)
{
	if (!v->is_global && (v->spill_offs == RTrack::NO_SPILL)) {
		AllocFrameSlot(v);
	}
	auto preg = MakePhysOperand(v->cls, v->type, v->p);
	qb.Create_mov(qir::VOperand::MakeSlot(v->is_global, v->type, v->spill_offs), preg);
	dbt::config::g_spill_emit++; dbt::config::g_spill_store++; if (v->is_global) dbt::config::g_spill_global++; else dbt::config::g_spill_local++; // diag-only
}

void QRegAlloc::EmitFill(RTrack *v)
{
	assert(v->spill_offs != RTrack::NO_SPILL);
	auto preg = MakePhysOperand(v->cls, v->type, v->p);
	qb.Create_mov(preg, qir::VOperand::MakeSlot(v->is_global, v->type, v->spill_offs));
	dbt::config::g_spill_emit++; dbt::config::g_spill_fill++; if (v->is_global) dbt::config::g_spill_global++; else dbt::config::g_spill_local++; // diag-only
}

void QRegAlloc::EmitMov(qir::VOperand dst, qir::VOperand src)
{
	qb.Create_mov(dst, src);
}

void QRegAlloc::Spill(qir::RegN p)
{
	RTrack *v = p2v[p];
	if (!v) {
		return;
	}
	Spill(v);
}

// `p` is a ZMM number here, not a GPR number.
void QRegAlloc::SpillV(qir::RegN p)
{
	RTrack *v = p2v_vpr[p];
	if (!v) {
		return;
	}
	Spill(v);
}

// Report the pressure that forced an insertion into a guarded group.  This is the same fail-closed
// outcome QEmit produces, moved one layer up so the message can say how many vector values were
// live -- which is what distinguishes "the allocator is misbehaving" from "this group asks for more
// simultaneously-live vector values than the host register file has".
void QRegAlloc::RefuseInsideChunkGroup(char const *what)
{
	unsigned live_vpr = 0, resident = 0;
	for (qir::RegN i = 0; i < n_vregs; ++i) {
		auto const &t = vregs[i];
		if (t.cls != qir::RegClass::VPR || t.retired) {
			continue;
		}
		if (t.loc == RTrack::Location::REG) {
			++resident;
			++live_vpr;
		} else if (t.loc == RTrack::Location::MEM) {
			++live_vpr;
		}
	}
	static char msg[224];
	snprintf(msg, sizeof(msg),
		 "QRegAlloc: %s inside a typed chunk group (VPR pool=%u, %u vector value(s) live, %u "
		 "resident); the group's guard branches over its body, so no spill may be inserted here",
		 what, (unsigned)ArchTraits::VPR_POOL.count(), live_vpr, resident);
	Panic(msg);
}

void QRegAlloc::Spill(RTrack *v)
{
	if (unlikely(chunk_group_open && v->cls == qir::RegClass::VPR && !v->retired &&
		     v->loc == RTrack::Location::REG && !v->spill_synced)) {
		RefuseInsideChunkGroup("vector spill");
	}
	// A retired value has no reachable consumer left in the region, so storing it would write
	// bytes nothing can load -- and, because AllocFrameSlot is a bump pointer with no free list,
	// that store would permanently own 64 of the 1024-byte frame.  Drop it instead: no `mov` is
	// emitted, no slot is taken, and Release below turns the track DEAD rather than MEM.
	if (!v->retired) {
		SyncSpill(v);
	}
	Release<false>(v);
}

void QRegAlloc::SyncSpill(RTrack *v)
{
	if (v->spill_synced) { // or fixed
		return;
	}
	switch (v->loc) {
	case RTrack::Location::MEM:
		return;
	case RTrack::Location::REG:
		EmitSpill(v);
		break;
	default:
		Panic();
	}
	v->spill_synced = true;
}

template <bool kill>
void QRegAlloc::Release(RTrack *v)
{
	bool release_reg = (v->loc == RTrack::Location::REG);
	if (v->is_global) { // return if fixed
		v->loc = RTrack::Location::MEM;
	} else {
		// `retired` is the (VPR-only, block-local) half of the liveness this TODO asks for: a
		// retired value is dead however it got released, so it must not come back as MEM and be
		// filled from a slot that was never written.  Never set on a GPR track -> scalar
		// behaviour, including the remaining TODO, is unchanged.
		v->loc = (kill || v->retired) ? RTrack::Location::DEAD : RTrack::Location::MEM; // TODO: liveness
	}
	if (release_reg) {
		PhysSlot(v) = nullptr;
	}
}

// Exact-size bucket index.  Slot sizes are the powers of two VTypeToSize can return (1,2,4,8,16,
// 32,64); anything else has no bucket and must not silently share one.
static u8 FrameBucket(u16 slot_sz)
{
	if (slot_sz == 0 || (slot_sz & (slot_sz - 1)) != 0 || slot_sz > 64) {
		Panic("QRegAlloc: spill slot size is not a supported power of two");
	}
	u8 i = 0;
	while ((1u << i) != slot_sz) {
		++i;
	}
	return i;
}

void QRegAlloc::AllocFrameSlot(RTrack *v)
{
	assert(v->spill_offs == RTrack::NO_SPILL);
	assert(!v->is_global);

	u16 slot_sz = qir::VTypeToSize(v->type); // 64 for V512

	// Recycle first.  A slot reaches the free list only via FreeFrameSlot, which runs when the
	// value that owned it has been proven unreachable, so handing the same bytes to another value
	// cannot be observed.  Same-size buckets keep the alignment invariant the bump path
	// establishes: a slot handed out as `roundup(cur, sz)` is `sz`-aligned, and it is only ever
	// handed out again for that same `sz`.
	auto &bucket = frame_free[FrameBucket(slot_sz)];
	if (bucket.n) {
		v->spill_offs = bucket.offs[--bucket.n];
		return;
	}

	u16 slot_offs = roundup(frame_cur, slot_sz);
	// FAIL CLOSED.  The spill frame is a fixed 1024 bytes reserved once by trampoline_to_jit, and
	// a V512 slot eats 64 of them, so a vector-heavy region can exhaust it 16x faster than a
	// scalar one.  There is no grow path and no way to signal "give up and use the helper" from
	// here, so running out must abort translation loudly -- silently reusing or overlapping a slot
	// would corrupt guest vector state.  Recycling above does not weaken this: it only ever reuses
	// bytes whose previous owner can no longer be read, so genuinely simultaneous pressure still
	// aborts exactly as before.
	if (slot_offs + slot_sz > frame_size) {
		// Say what ran out.  A bare "exhausted" cannot distinguish the two causes that reach
		// here -- slots leaked by values that are already dead, versus a genuine peak of
		// simultaneously-live values that no recycling can reduce -- and telling them apart is
		// the difference between a bug and a capacity limit.  `live` counts the slots currently
		// owned by a value; `recyclable` counts the ones sitting in the free list.
		unsigned live = 0, recyclable = 0;
		for (qir::RegN i = 0; i < n_vregs; ++i) {
			auto const &t = vregs[i];
			if (!t.is_global && t.spill_offs != RTrack::NO_SPILL) {
				++live;
			}
		}
		for (auto const &b : frame_free) {
			recyclable += b.n;
		}
		static char msg[192]; // Panic takes one string and is noreturn; no reuse concern
		snprintf(msg, sizeof(msg),
			 "QRegAlloc: spill frame exhausted (frame=%u B, need %u B for a %u B slot; "
			 "%u slot(s) still owned by a live value, %u recyclable)",
			 (unsigned)frame_size, (unsigned)(slot_offs + slot_sz), (unsigned)slot_sz,
			 live, recyclable);
		Panic(msg);
	}
	v->spill_offs = slot_offs;
	frame_cur = slot_offs + slot_sz;
}

// Return a dead value's slot to its size bucket.  The ONLY caller is RetireAt, i.e. the point at
// which AnalyzeVPRRetirement has already proven that every reference to this value -- definition
// and use alike -- lies in one block and that its last read has now been allocated.  From here on
// Spill declines to store it, Fill can never reach it (Release turns the track DEAD, and reading a
// retired value Panics), so the bytes are unreachable and safe to hand out again.
//
// Deliberately NOT called from Release<kill>.  `kill` marks a register free, which is not the same
// claim as "no consumer remains anywhere in the region"; only the retirement analysis makes that
// claim, and reusing a slot on a weaker claim would be a silent-corruption bug of exactly the kind
// the fail-closed Panic above exists to prevent.
void QRegAlloc::FreeFrameSlot(RTrack *v)
{
	if (v->is_global || v->spill_offs == RTrack::NO_SPILL) {
		return;
	}
	auto &bucket = frame_free[FrameBucket(qir::VTypeToSize(v->type))];
	assert(bucket.n < bucket.offs.size());
	bucket.offs[bucket.n++] = v->spill_offs;
	v->spill_offs = RTrack::NO_SPILL;
	v->spill_synced = false; // the bytes are no longer this value's; never fill from them again
}

void QRegAlloc::Fill(RTrack *v, RegMask desire, RegMask avoid)
{
	switch (v->loc) {
	case RTrack::Location::MEM:
		v->p = (v->cls == qir::RegClass::VPR) ? AllocPRegV(desire, avoid) : AllocPReg(desire, avoid);
		v->loc = RTrack::Location::REG;
		PhysSlot(v) = v;
		v->spill_synced = true;
		EmitFill(v);
		return;
	case RTrack::Location::REG:
		return;
	default:
		Panic();
	}
}

QRegAlloc::RTrack *QRegAlloc::AddTrack()
{
	if (n_vregs == vregs.size()) {
		Panic("QRegAlloc: virtual-register track capacity exceeded");
	}
	auto *v = &vregs[n_vregs++];
	return new (v) RTrack();
}

QRegAlloc::RTrack *QRegAlloc::AddTrackGlobal(qir::VType type, u16 state_offs)
{
	auto *v = AddTrack();
	v->is_global = true;
	v->type = type;
	v->cls = qir::VTypeToRegClass(type);
	v->spill_offs = state_offs;
	return v;
}

QRegAlloc::RTrack *QRegAlloc::AddTrackLocal(qir::VType type)
{
	auto *v = AddTrack();
	v->is_global = false;
	v->type = type;
	// Class is fixed here and never revisited.  An unsupported type yields RegClass::NONE, which
	// is inert until something actually tries to allocate it (PhysSlot/MakePhysOperand Panic).
	// Constructing the track must not fail: a region may merely contain such a local.
	v->cls = qir::VTypeToRegClass(type);
	v->spill_offs = RTrack::NO_SPILL;
	return v;
}

// ---------------------------------------------------------------------------------------------
// Block-local last-use retirement for VPR locals.
//
// WHY.  `rvvtypedchunkbegin` carries HAS_CALLS, so CallOp spills every VPR the allocator still
// believes is resident, and AllocFrameSlot is a pure bump pointer: every distinct value ever
// spilled permanently owns 64 of the fixed 1024-byte frame.  A block holding several typed groups
// therefore exhausted that frame after 16 spilled values -- even though a group's values are all
// dead the moment its own store has run, because this lowering keeps no vector residency across
// guest instructions and the next group reloads from CPUState.
//
// WHAT.  This pre-pass proves, per value, that (a) it is a non-global VPR-class local, (b) EVERY
// reference to it, definition and use alike, lies in one block, and (c) which instruction of that
// block reads it last.  RetireAt marks the track `retired` after that instruction has been
// allocated; from then on the value can no longer be observed, so Spill must never store it and
// AllocPRegV may take its register for free.  Anything not proven block-local -- every global,
// every value crossing a block edge, every GPR -- keeps its previous behaviour exactly, and a
// value that is never read is retired after its definition only when it has exactly one.
//
// WHAT IT DELIBERATELY DOES NOT DO.  Retirement does not unbind the register on the spot.  A
// retired value stays parked in its ZMM until somebody actually needs a register, so the registers
// handed out INSIDE one typed group are exactly the ones handed out before this change -- which is
// what keeps the two chunks of a VLEN=1024 vadd.vv in disjoint ZMM sets (the accepted C2.2a/C2.3a
// evidence and the "two chunks, different ZMM registers" requirement).  Unbinding eagerly would
// let chunk 1's add write chunk 0's source register and turn that disjointness into a WAR name
// dependency, for nothing: the frame pressure this fixes comes from the call boundary BETWEEN
// groups, and there every retired value is dropped at no cost.
void QRegAlloc::AnalyzeVPRRetirement()
{
	auto is_local_vpr = [this](qir::RegN id) {
		return id >= n_globals && id < n_vregs && vregs[id].cls == qir::RegClass::VPR;
	};

	// (b) one block.  Definitions are counted too: a value defined in another block is a second
	// lifetime that a single last-use index cannot describe.
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto note = [&](qir::VOperand opr) {
				if (!opr.IsVVPR() || !is_local_vpr(opr.GetVVPR())) {
					return;
				}
				auto &ri = vretire[opr.GetVVPR()];
				if (!ri.blk) {
					ri.blk = &bb;
				} else if (ri.blk != &bb) {
					ri.multi_block = true;
				}
			};
			auto outl = ins.outputs();
			for (u8 i = 0; i < outl.size(); ++i) {
				note(outl[i]);
				if (outl[i].IsVVPR() && is_local_vpr(outl[i].GetVVPR())) {
					auto &definitions = vretire[outl[i].GetVVPR()].definitions;
					if (definitions < 2) {
						++definitions;
					}
				}
			}
			auto inl = ins.inputs();
			for (u8 i = 0; i < inl.size(); ++i) {
				note(inl[i]);
			}
		}
	}

	// (c) last read, then the retirement points in the exact order Run() walks the region, so
	// consuming them costs one pointer comparison per instruction.  `queued` bounds the sequence
	// by the number of tracks and makes a value used twice by one instruction retire once.
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto inl = ins.inputs();
			for (u8 i = 0; i < inl.size(); ++i) {
				if (!inl[i].IsVVPR() || !is_local_vpr(inl[i].GetVVPR())) {
					continue;
				}
				auto &ri = vretire[inl[i].GetVVPR()];
				if (!ri.multi_block) {
					ri.last_use = &ins;
				}
			}
		}
	}
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto inl = ins.inputs();
			for (u8 i = 0; i < inl.size(); ++i) {
				if (!inl[i].IsVVPR() || !is_local_vpr(inl[i].GetVVPR())) {
					continue;
				}
				auto &ri = vretire[inl[i].GetVVPR()];
				if (ri.multi_block || ri.last_use != &ins || ri.queued) {
					continue;
				}
				ri.queued = true;
				retire_seq[n_retire++] = {&ins, inl[i].GetVVPR()};
			}
			auto outl = ins.outputs();
			for (u8 i = 0; i < outl.size(); ++i) {
				if (!outl[i].IsVVPR() || !is_local_vpr(outl[i].GetVVPR())) {
					continue;
				}
				auto &ri = vretire[outl[i].GetVVPR()];
				if (ri.multi_block || ri.definitions != 1 || ri.last_use || ri.queued) {
					continue;
				}
				ri.queued = true;
				retire_seq[n_retire++] = {&ins, outl[i].GetVVPR()};
			}
		}
	}
}

// Consume every retirement point attached to `ins`.  Called AFTER the instruction has been fully
// allocated -- inputs and outputs both -- so the final consumer still reads the value in a
// register, and so an output of the same instruction cannot be handed a register the instruction
// itself is still reading.
void QRegAlloc::RetireAt(qir::Inst const *ins)
{
	while (retire_pos < n_retire && retire_seq[retire_pos].ins == ins) {
		auto *v = &vregs[retire_seq[retire_pos].vreg];
		assert(!v->is_global && v->cls == qir::RegClass::VPR && !v->pinned);
		v->retired = true;
		FreeFrameSlot(v); // its bytes are unreachable from here on
		++retire_pos;
	}
}

void QRegAlloc::Prologue()
{
	for (qir::RegN i = 0; i < n_vregs; ++i) {
		auto *v = &vregs[i];

		if (v->is_global) {
			v->loc = RTrack::Location::MEM;
		} else {
			v->loc = RTrack::Location::DEAD;
		}
	}
}

// 2026-06-21 bounded region-RA attack: for a call-free multi-block region with a backedge (a loop), reserve K host regs
// for the K most-used guest registers and hold them resident for the whole region (loaded once at entry, never spilled
// at intra-region branches incl. the backedge, synced at SIDEEFF + region exit). A fixed per-region host-reg assignment
// makes loop headers / merges trivially consistent (same host reg on every path) -- the property the linear-edge
// residency lacked. No global reservation (scoped to this region) -> not the V114 whole-program pin.
void QRegAlloc::PinSelect()
{
	if (!dbt::config::qcg_pin || dbt::config::qcg_pin_k == 0)
		return;
	u32 nblk = 0;
	bool backedge = false, has_call = false;
	RegMask forced{0}; // host regs some op in this region hard-requires (single-reg constraint) -> never pin to them
	std::array<u32, MAX_VREGS> use{};
	std::array<bool, MAX_VREGS> unsafe{}; // a global whose value can be written into the reserved pinned preg on EVERY def
	for (auto &bb : region->GetBlocks()) {
		nblk++;
		for (auto *s : bb.GetSuccs())
			if (s->GetId() <= bb.GetId())
				backedge = true;
		for (auto &ins : bb.ilist) {
			if (ins.GetFlags() & qir::Inst::Flags::HAS_CALLS)
				has_call = true;
			auto inl = ins.inputs();
			for (u8 j = 0; j < inl.size(); ++j)
				if (inl[j].IsVGPR() && inl[j].GetVGPR() < n_globals)
					use[inl[j].GetVGPR()]++;
			auto &oi_info = GetOpInfo(ins.GetOpcode());
			// FORCED single-reg constraints (any operand) -> never pin to such a host reg (shift->RCX, gbrind->RSI,
			// mulhsu input->RBX, etc.), else the op's required reg copy cannot allocate it.
			if (oi_info.ra_ct) {
				unsigned nops = (unsigned)oi_info.n_out + oi_info.n_in;
				for (unsigned kk = 0; kk < nops; ++kk) {
					auto cr = oi_info.ra_ct[kk].cr;
					int cnt = 0;
					qir::RegN single = 0;
					for (qir::RegN r = 0; r < ArchTraits::GPR_NUM; ++r)
						if (ArchTraits::GPR_POOL.Test(r) && cr.Test(r)) { cnt++; single = r; }
					if (cnt == 1)
						forced.Set(single);
				}
			}
			auto outl = ins.outputs();
			for (u8 j = 0; j < outl.size(); ++j) {
				if (!outl[j].IsVGPR() || outl[j].GetVGPR() >= n_globals)
					continue;
				auto g = outl[j].GetVGPR();
				use[g]++;
				// can this op's output go to an arbitrary pool register (so the reserved pinned preg works)?
				if (oi_info.ra_ct && oi_info.ra_order) {
					auto cr = oi_info.ra_ct[oi_info.ra_order[j]].cr;
					for (qir::RegN p = 0; p < ArchTraits::GPR_NUM; ++p)
						if (ArchTraits::GPR_POOL.Test(p) && !cr.Test(p)) {
							unsafe[g] = true;
							break;
						}
				} else {
					unsafe[g] = true; // unknown output constraint -> never pin (correctness over benefit)
				}
			}
		}
	}
	// IP is written DIRECTLY to CPUState by the translator (PreSideeff, before side-effects), bypassing the register
	// allocator, so a pinned IP preg would diverge from memory -> never pin it.
	for (u16 i = 0; i < n_globals; ++i) {
		auto *gi = vregs_info->GetGlobalInfo(i);
		if (gi && gi->name && gi->name[0] == 'i' && gi->name[1] == 'p' && gi->name[2] == 0)
			unsafe[i] = true;
	}
	if (nblk < 2 || !backedge || has_call)
		return;
	// The pinned loads are emitted ONCE in the codegen PROLOGUE (runs per region entry; the loop backedge jumps to a
	// block label after it), so no preheader block is needed and the loads never re-execute on the backedge.
	// Pin only to pool regs that are (a) not hard-required by any op in this region (`forced`: RCX shift / RSI gbrind
	// target / RBX mulhsu / ...) and (b) not used as HARDCODED scratch by the gbr/gbrind cache-check codegen (which
	// clobbers RCX/RSI/RDI/R12/R14/R15 inline, before control actually leaves). That leaves the genuinely-free pool
	// regs {RBX (when no mulhsu), R8, R9, R10, R11}. Helper-clobbered caller-saved regs are still fine because region
	// exits sync the pin to CPUState before the brind helper runs.
	RegMask const codegen_scratch = RegMask(0)
					.Set(ArchTraits::RCX)
					.Set(ArchTraits::RSI)
					.Set(ArchTraits::RDI)
					.Set(ArchTraits::R12)
					.Set(ArchTraits::R14)
					.Set(ArchTraits::R15);
	RegMask const pinnable = ArchTraits::GPR_POOL & ~forced & ~codegen_scratch;
	for (unsigned k = 0; k < dbt::config::qcg_pin_k && region->n_pins < 8; ++k) {
		qir::RegN p = ArchTraits::GPR_NUM;
		for (qir::RegN c = 0; c < ArchTraits::GPR_NUM; ++c)
			if (pinnable.Test(c) && !fixed.Test(c) && !p2v[c]) {
				p = c;
				break;
			}
		if (p >= ArchTraits::GPR_NUM)
			break; // no free callee-saved pool reg -> stop pinning this region
		int best = -1;
		u32 bestc = 0;
		for (u16 i = 0; i < n_globals; ++i)
			if (!vregs[i].pinned && !unsafe[i] && use[i] > bestc) {
				bestc = use[i];
				best = i;
			}
		if (best < 0)
			break;
		auto *v = &vregs[best];
		v->p = p;
		v->loc = RTrack::Location::REG;
		v->pinned = true;
		v->spill_synced = true;
		p2v[p] = v;
		fixed = fixed.Set(p); // reserve: AllocPReg avoids it for the rest of the region
		// record for the prologue to load once on entry (CPUState[spill_offs] -> preg p)
		region->pins[region->n_pins++] = {(u8)p, (u16)v->spill_offs, v->type};
		dbt::config::g_pin_globals++;
	}
	if (region->n_pins)
		dbt::config::g_pin_regions++;
}

void QRegAlloc::BlockBoundary()
{
	for (qir::RegN i = 0; i < n_vregs; ++i) {
		if (vregs[i].is_global && !vregs[i].pinned) { // pinned guest regs stay resident (synced at SIDEEFF/region exit)
			if (dbt::config::qcg_resident) {
				// Cross-block residency: sync the dirty value to CPUState memory (so any merge path reads
				// consistent state) but KEEP the guest register in its host register. A single-predecessor
				// successor laid out next inherits it (see Run()); other successors re-load from the synced
				// memory. Net: multi-block hot loop bodies stop reloading guest regs at every block boundary.
				SyncSpill(&vregs[i]);
			} else {
				Spill(&vregs[i]); // skip if fixed
			}
		}
	}
}

void QRegAlloc::RegionBoundary()
{
	for (qir::RegN i = 0; i < n_vregs; ++i) {
		auto vreg = &vregs[i];
		if (vreg->is_global) {
			if (vreg->pinned)
				// UNCONDITIONAL store: the pinned preg always holds the live runtime value, but the qra's
				// spill_synced dirty-tracking is linear (list order) and can miss a write that happens on a
				// runtime path reaching this exit out of list order. Always write the preg back to CPUState so
				// the next region reads the correct value. (Keep the preg resident for other exits.)
				EmitSpill(vreg);
			else
				Spill(vreg);
		} else {
			Release<false>(vreg);
		}
	}
}

// A vector operand's allowable registers come from the VPR file.  They cannot come from the
// opcode's RAOpCt, because every constraint table in arch_traits.cpp is built out of GPR masks --
// a mask bit there means "GPR n", and reading it as "zmm n" would be nonsense.
//
// Substituting VPR_POOL wholesale is only sound for an op whose constraint is "any register of the
// operand's own class".  Verify that rather than assume it: today the only op that can carry a
// vector operand is `mov` (CT r_ri, cr == GPR_ALL), emitted by spill/fill/copy.  A future
// constrained vector op must gain a real per-class constraint table instead of silently
// inheriting this one, and until it does it fails loudly here.
static RegMask VPRConstraint(RAOpCt const &ct)
{
	if (ct.cr.GetData() != ArchTraits::GPR_ALL.GetData()) {
		Panic("QRegAlloc: vector operand on an op with a constrained register mask");
	}
	return ArchTraits::VPR_POOL;
}

// Vector twins of AllocOp's per-operand bodies.  Split out so the scalar bodies below stay
// literally unchanged, and so no VPR number can reach `avoid`/`p2v`, or GPR number `avoid_vpr`/
// `p2v_vpr`.
void QRegAlloc::AllocOpInputV(qir::VOperand *opr, RAOpCt const &ct, RegMask &avoid_vpr)
{
	auto cr = VPRConstraint(ct);
	auto *src = &vregs[opr->GetVVPR()];
	assert(src->cls == qir::RegClass::VPR);
	// Fail loudly rather than read a register that may since have been handed to somebody else:
	// AnalyzeVPRRetirement claims this value has no reference after its recorded last use, and a
	// read arriving here would falsify exactly that claim.
	if (src->retired) {
		Panic("QRegAlloc: use of a retired VPR value");
	}

	Fill(src, cr, avoid_vpr);
	auto p = src->p;
	if (!cr.Test(p)) {
		p = AllocPRegV(cr, avoid_vpr);
		qb.Create_mov(qir::VOperand::MakePVPR(src->type, p),
			      qir::VOperand::MakePVPR(src->type, src->p));
	}

	avoid_vpr.Set(p);
	*opr = qir::VOperand::MakePVPR(opr->GetType(), p);
}

void QRegAlloc::AllocOpOutputV(qir::VOperand *opr, RAOpCt const &ct, RegMask &avoid_vpr)
{
	auto cr = VPRConstraint(ct);
	auto *dst = &vregs[opr->GetVVPR()];
	assert(dst->cls == qir::RegClass::VPR);
	// --qcg-pin only ever pins globals, and every global is a scalar guest register, so a vector
	// track is never pinned. Asserted rather than handled: a pinned VPR would need the whole
	// PinSelect safety analysis redone for a second file.
	assert(!dst->pinned);

	if (ct.has_alias) {
		// QSel guarantees there will be the same VReg, so dst already matches ct
	} else {
		auto p = AllocPRegV(cr, avoid_vpr);
		if (dst->loc == RTrack::Location::REG) {
			p2v_vpr[dst->p] = nullptr;
		}
		dst->loc = RTrack::Location::REG;
		p2v_vpr[p] = dst;
		dst->p = p;
	}
	// A definition starts a new lifetime for this vreg, so an earlier retirement of it no longer
	// applies (a dead definition after the last read; the analysis retires at the last READ).
	dst->retired = false;
	dst->spill_synced = false;
	avoid_vpr.Set(dst->p);
	*opr = qir::VOperand::MakePVPR(opr->GetType(), dst->p);
}

void QRegAlloc::AllocOp(qir::Inst *ins)
{
	auto srcl = ins->inputs();
	auto dstl = ins->outputs();
	auto dst_n = dstl.size();

	auto &op_info = GetOpInfo(ins->GetOpcode());
	auto *op_ct = op_info.ra_ct;
	auto *op_order = op_info.ra_order;
	assert(op_ct);

	auto avoid = fixed;
	// Separate exclusion set for the vector file. Sharing one mask would make GPR n exclude zmm n.
	auto avoid_vpr = fixed_vpr;

	for (u8 i_ao = 0; i_ao < srcl.size(); ++i_ao) {
		u8 i = op_order[dst_n + i_ao];
		auto ct = op_ct[dst_n + i];

		auto opr = &srcl[i];
		if (opr->IsVVPR()) {
			AllocOpInputV(opr, ct, avoid_vpr);
			continue;
		}
		if (!opr->IsVGPR()) {
			continue;
		}
		auto src = &vregs[opr->GetVGPR()];
		Fill(src, ct.cr, avoid);
		auto p = src->p;
		if (!ct.cr.Test(p)) {
			p = AllocPReg(ct.cr, avoid);
			qb.Create_mov(qir::VOperand::MakePGPR(src->type, p),
				      qir::VOperand::MakePGPR(src->type, src->p));
			if constexpr (false) { // TODO(tuning): different dep. distance, check perf
				p2v[src->p] = nullptr;
				p2v[p] = src;
				src->p = p;
			}
		}

		avoid.Set(p);
		*opr = qir::VOperand::MakePGPR(opr->GetType(), p);
	}

	if (ins->GetFlags() & qir::Inst::Flags::SIDEEFF) {
		for (int i = 0; i < n_vregs; ++i) {
			auto *v = &vregs[i];
			if (v->is_global) {
				if (v->pinned)
					// UNCONDITIONAL: the spill_synced flag is linear (list order) and can wrongly read
					// "clean" for a pinned reg written on a runtime path reaching this side-effect out of
					// list order; a fault here must see the live value -> always write the pinned preg back.
					EmitSpill(v);
				else
					SyncSpill(v);
			}
		}
	}

	for (u8 i_ao = 0; i_ao < dstl.size(); ++i_ao) {
		u8 i = op_order[i_ao];
		auto ct = op_ct[i];

		auto opr = &dstl[i];
		if (opr->IsVVPR()) {
			AllocOpOutputV(opr, ct, avoid_vpr);
			continue;
		}
		if (!opr->IsVGPR()) {
			continue;
		}
		auto dst = &vregs[opr->GetVGPR()];

		// A pinned guest register must stay in its reserved host reg (the fixed assignment is what makes merges
		// consistent). Write the result straight into the pinned preg when the op's output constraint allows it.
		if (dst->pinned) {
			if (ct.cr.Test(dst->p)) {
				dst->spill_synced = false; // dirty; value lives in the pinned preg
				avoid.Set(dst->p);
				*opr = qir::VOperand::MakePGPR(opr->GetType(), dst->p);
				continue;
			}
			// constrained output (e.g. mul -> AX) that cannot target the pinned preg: give up the pin for this
			// guest reg (revert to normal allocation below) -> correctness preserved, only the optimization lost.
			dst->pinned = false;
			fixed.Clear(dst->p); // un-reserve; normal allocation below frees dst->p (loc==REG) + assigns a new preg
		}

		// TODO(tuning): forcefull renaming, check perf
		if constexpr (true) {
			if (ct.has_alias) {
				// QSel guarantees there will be the same VReg, so dst already matches ct
			} else {
				auto p = AllocPReg(ct.cr, avoid);
				if (dst->loc == RTrack::Location::REG) {
					p2v[dst->p] = nullptr;
				}
				dst->loc = RTrack::Location::REG;
				p2v[p] = dst;
				dst->p = p;
			}
		} else {
			if (dst->loc != RTrack::Location::REG) {
				dst->p = AllocPReg(ct.cr, avoid);
				p2v[dst->p] = dst;
				dst->loc = RTrack::Location::REG;
			} else if (!ct.cr.Test(dst->p)) {
				auto p = AllocPReg(ct.cr, avoid);
				p2v[dst->p] = nullptr;
				p2v[p] = dst;
				dst->p = p;
			}
		}
		dst->spill_synced = false;
		avoid.Set(dst->p);
		*opr = qir::VOperand::MakePGPR(opr->GetType(), dst->p);
	}
}

// TODO: resurrect allocation for helpers
void QRegAlloc::CallOp(bool use_globals)
{
	for (u8 p = 0; p < N_PREGS; ++p) {
		if (ArchTraits::GPR_CALL_CLOBBER.Test(p)) {
			Spill(p);
		}
	}

	// SysV AMD64 has no callee-saved vector register (VPR_CALL_CLOBBER == VPR_ALL), so EVERY live
	// VPR must be spilled here -- there is no subset to preserve across the call. This loop is
	// unconditional on `use_globals` because that flag only selects whether guest *globals* are
	// written back to CPUState; a VPR is always a local, and a local surviving in a clobbered
	// register would be silently corrupted by the callee.
	for (u8 p = 0; p < N_VPREGS; ++p) {
		if (ArchTraits::VPR_CALL_CLOBBER.Test(p)) {
			SpillV(p);
		}
	}

	// M2B. The induction variable is `qir::RegN`, the type `n_vregs` itself has, and NOT `u8` --
	// which is what it was, and which made this loop non-terminating rather than merely wrong.
	// `MAX_VREGS` exceeds 255, so `n_vregs` legitimately reaches values a `u8` counter cannot hold: at
	// 256 or more, `i` wraps 255 -> 0 and `i < n_vregs` is never false, so translation spun here
	// forever instead of reaching the call. The two other full-vreg scans in this file,
	// BlockBoundary and RegionBoundary, already used `qir::RegN` for exactly this reason.
	//
	// A bound of 255 would NOT have been a fix. This loop is the only place a call boundary writes
	// dirty guest globals back to CPUState, and the callee reads CPUState: any global the loop
	// fails to visit is a stale value the helper then reads. Truncating the scan converts a hang
	// into a miscompile, so the index type -- not the trip count -- is the thing that must change.
	if (use_globals) {
		for (qir::RegN i = 0; i < n_vregs; ++i) {
			auto *v = &vregs[i];
			if (v->is_global) {
				Spill(v);
			}
		}
	}
}

struct QRegAllocVisitor : qir::InstVisitor<QRegAllocVisitor, void> {
	using Base = qir::InstVisitor<QRegAllocVisitor, void>;

public:
	QRegAllocVisitor(QRegAlloc *ra_) : ra(ra_) {}

	void visitInst(qir::Inst *ins)
	{
		unreachable("");
	}

	void visitInstUnop(qir::InstUnop *ins)
	{
		ra->AllocOp(ins);
	}

	void visitInstBinop(qir::InstBinop *ins)
	{
		ra->AllocOp(ins);
	}

	void visitInstSetcc(qir::InstSetcc *ins)
	{
		ra->AllocOp(ins);
	}

	void visitInstBr(qir::InstBr *ins)
	{
		// has no voperands
		ra->BlockBoundary();
	}

	void visitInstBrcc(qir::InstBrcc *ins)
	{
		ra->AllocOp(ins);
		ra->BlockBoundary();
	}

	void visitInstGBr(qir::InstGBr *ins)
	{
		// has no voperands
		ra->RegionBoundary();
	}

	void visitInstGBrind(qir::InstGBrind *ins)
	{
		ra->AllocOp(ins);
		ra->RegionBoundary();
	}

	void visitInstVMLoad(qir::InstVMLoad *ins)
	{
		ra->AllocOp(ins);
	}

	void visitInstVMStore(qir::InstVMStore *ins)
	{
		ra->AllocOp(ins);
	}
	
	void visitInstVMLoad2(qir::InstVMLoad2 *ins)
	{
		ra->AllocOp(ins);
	}

	void visitInstVMLoad4(qir::InstVMLoad4 *ins)
	{
		ra->AllocOp(ins);
	}

	void visitInstVMStore2(qir::InstVMStore2 *ins)
	{
		ra->AllocOp(ins);
	}

	void visitInstVMStore4(qir::InstVMStore4 *ins)
	{
		ra->AllocOp(ins);
	}

	void visitInstHcall(qir::InstHcall *ins)
	{
		ra->CallOp(true);
	}

	// CCRF chunks read and write CPUState directly with fixed scratch registers. They contain no
	// semantic-helper call, but their conservative HAS_CALLS classification deliberately forces
	// every resident guest global back to CPUState and clears call-clobbered allocation state before
	// the direct body. Keeping that contract explicit also makes debug builds fail closed on any
	// future CCRF node that is not handled here.
	void visitInstCCRFChunk(qir::InstCCRFChunk *ins)
	{
		ra->CallOp(true);
	}

	void visitInstCCRFComputeRegion(qir::InstCCRFComputeRegion *ins)
	{
		ra->CallOp(true);
	}

	// Same treatment as hcall: no QIR operands, but the emitted fallback path contains the
	// helper call, so call-clobbered registers must be spilled around it. The inline path
	// touches only xmm0/xmm1 (not modelled by the allocator, same as Emit_vmload4) and the
	// fixed state register.
	void visitInstRVVAddV(qir::InstRVVAddV *ins)
	{
		ra->CallOp(true);
	}

	// Diagnostic chunk control arm (see the block comment on InstRVVDiagChunkBegin in qir.h).
	// The call boundary belongs on `begin` and ONLY on `begin`.
	//
	// CallOp inserts the spill of call-clobbered registers immediately before the instruction's
	// emitted code. `begin` emits the guard, whose `jne` targets a fallback label that `end`
	// binds after the chunk ops. So a spill attached to `end` would be emitted after the guard
	// and before that label, and the guard-taken path -- the only path that actually calls the
	// helper -- would jump straight over it. Spilling at `begin` covers both paths, which is
	// exactly what the single-instruction InstRVVAddV above relies on.
	void visitInstRVVDiagChunkBegin(qir::InstRVVDiagChunkBegin *ins)
	{
		ra->CallOp(true);
	}

	// Nothing for the allocator to do, because there is nothing to allocate: these nodes have no
	// operands and no QIR value. Their ZMMs are hardcoded by the emitter, outside the allocator's
	// model entirely -- the same unmodelled-scratch convention as Emit_vmload4's xmm0/xmm1, and
	// the same reason this representation cannot be extended.
	void visitInstRVVDiagChunkAdd(qir::InstRVVDiagChunkAdd *ins) {}

	void visitInstRVVDiagChunkEnd(qir::InstRVVDiagChunkEnd *ins) {}

	// The typed group's frame. CallOp belongs on `begin` and ONLY on `begin`, for the reason
	// given on the diagnostic pair above -- the guard jumps past the body to a label `end`
	// binds, so a spill attached to `end` would sit on the far side of that jump -- and
	// additionally because syncing here is what leaves nothing dirty for the typed body's own
	// SIDEEFF syncs to emit inside the branched-over window (qir.h).
	void visitInstRVVTypedChunkBegin(qir::InstRVVTypedChunkBegin *ins)
	{
		ra->CallOp(true); // spills everything -- must happen BEFORE the group is marked open
		ra->NoteChunkGroup(true);
	}

	void visitInstRVVTypedChunkEnd(qir::InstRVVTypedChunkEnd *ins)
	{
		ra->NoteChunkGroup(false);
	}

	// Typed V512 chunk ops. Plain AllocOp -- the same entry point every scalar op uses. That is
	// the point: nothing about a vector value needs a special allocator path, only per-class
	// operand bodies (AllocOpInputV/AllocOpOutputV) that AllocOp already dispatches to on
	// IsVVPR(). vchunkload/vchunkstore mix an I32 address operand with a V512 data operand in one
	// instruction, which is the first thing in the tree to exercise that dispatch.
	void visitInstVChunkLoad(qir::InstVChunkLoad *ins)
	{
		ra->AllocOp(ins);
	}

	void visitInstVChunkAdd(qir::InstVChunkAdd *ins)
	{
		ra->AllocOp(ins);
	}

	// Identical treatment to the add above: same CT(r_r_r) table, same three independent VPR
	// operands, same absence of an ALIAS constraint. Nothing about the multiply changes what the
	// allocator has to do.
	void visitInstVChunkMul(qir::InstVChunkMul *ins)
	{
		ra->AllocOp(ins);
	}

	// Identical treatment again. AllocOp assigns a physical register per operand slot and never
	// reorders slots, so the subtract's minuend/subtrahend order survives allocation unchanged --
	// which is the property its route's emitted-code test re-derives from the decoded bytes.
	void visitInstVChunkSub(qir::InstVChunkSub *ins)
	{
		ra->AllocOp(ins);
	}

	// Identical treatment once more: same CT(r_r_r) table, three independent VPR operands, no
	// ALIAS constraint. The allocator never sees which host instruction the op becomes.
	void visitInstVChunkXor(qir::InstVChunkXor *ins)
	{
		ra->AllocOp(ins);
	}

	// Identical treatment again, for the second bitwise body op. The allocator is what makes the
	// two chunks of a VLEN=1024 frame land in disjoint ZMM sets, and it does that from the def-use
	// graph alone -- so nothing about `vpord` versus `vpxord` can change the allocation shape the
	// or route's emitted-code test gates.
	void visitInstVChunkOr(qir::InstVChunkOr *ins)
	{
		ra->AllocOp(ins);
	}

	// Identical treatment again, for the third bitwise body op. The allocator is what makes the
	// two chunks of a VLEN=1024 frame land in disjoint ZMM sets, and it does that from the def-use
	// graph alone -- so nothing about `vpandd` versus `vpord` or `vpxord` can change the allocation
	// shape the and route's emitted-code test gates.
	void visitInstVChunkAnd(qir::InstVChunkAnd *ins)
	{
		ra->AllocOp(ins);
	}
	// P7N-B. Identical treatment for the two shift-immediate body ops. The allocator is
	// UNCHANGED by this route: CT(r_r) is an existing table, one output and one input are fewer
	// operands than it already handles, and the shift amount is a node field it never sees.
	void visitInstVChunkSll(qir::InstVChunkSll *ins)
	{
		ra->AllocOp(ins);
	}
	void visitInstVChunkSrl(qir::InstVChunkSrl *ins)
	{
		ra->AllocOp(ins);
	}

	void visitInstVChunkStore(qir::InstVChunkStore *ins)
	{
		ra->AllocOp(ins);
	}

	// Also plain AllocOp. The op has no inputs, so the only work is AllocOpOutputV giving the
	// result a ZMM out of VPR_POOL -- and, because the opcode is SIDEEFF, AllocOp's global sync
	// runs first, which is what makes the CPUState bytes this reads the live ones (see qir.h).
	void visitInstVStateChunkLoad(qir::InstVStateChunkLoad *ins)
	{
		ra->AllocOp(ins);
	}

	// Also plain AllocOp. The op has no outputs, so the only work is AllocOpInputV filling the
	// value being stored into a ZMM out of VPR_POOL; the SIDEEFF global sync then runs after the
	// inputs are in place and before the store executes, which is the ordering the write needs
	// (see the note in qir.h -- syncing is all SIDEEFF does, it does not invalidate).
	void visitInstVStateChunkStore(qir::InstVStateChunkStore *ins)
	{
		ra->AllocOp(ins);
	}

	// Native-3. Also plain AllocOp, and for vstatechunkload's reason exactly: no inputs, so the
	// only work is AllocOpOutputV giving the splat result a ZMM out of VPR_POOL. The SIDEEFF
	// global sync running first is what makes the guest GPR word this reads the live one -- and
	// here that matters MORE than for vstatechunkload, because the 4 bytes read ARE a guest
	// global's state slot rather than a window proved disjoint from every one of them (qir.h).
	void visitInstVChunkBroadcast(qir::InstVChunkBroadcast *ins)
	{
		ra->AllocOp(ins);
	}
	void visitInstVChunkFBroadcast(qir::InstVChunkFBroadcast *ins) { ra->AllocOp(ins); }
	void visitInstVChunkFALU(qir::InstVChunkFALU *ins) { ra->AllocOp(ins); }
	void visitInstVChunkDep(qir::InstVChunkDep *ins) { ra->AllocOp(ins); }
	void visitInstVChunkMaskSet(qir::InstVChunkMaskSet *ins) {}
	// S1-1: no operands to allocate. It reads vec.vl straight out of CPUState and writes only
	// EFLAGS, which QRegAlloc does not track, so there is nothing for AllocOp to do.
	void visitInstVChunkActive(qir::InstVChunkActive *ins) {}
	void visitInstVChunkPartialAlu(qir::InstVChunkPartialAlu *ins) {}
	void visitInstVMaskLogic(qir::InstVMaskLogic *) {}
	void visitInstVMaskScalar(qir::InstVMaskScalar *) {}
	void visitInstVMaskIota(qir::InstVMaskIota *) {}
	void visitInstVScalarMove(qir::InstVScalarMove *) {}
	void visitInstVCompress(qir::InstVCompress *) {}
	void visitInstVReduce(qir::InstVReduce *) {}
	void visitInstVChunkIndex(qir::InstVChunkIndex *) {}
	void visitInstVChunkFClass(qir::InstVChunkFClass *) {}
	void visitInstVChunkIToF(qir::InstVChunkIToF *) {}
	void visitInstVChunkFToI(qir::InstVChunkFToI *) {}
	void visitInstVChunkFToF(qir::InstVChunkFToF *) {}
	void visitInstVGather(qir::InstVGather *) {}
	void visitInstVFEstimate(qir::InstVFEstimate *) {}
	void visitInstVMemory(qir::InstVMemory *) {}
	void visitInstVWholeMove(qir::InstVWholeMove *) {}
	void visitInstVFReduce(qir::InstVFReduce *) {}
	void visitInstVMaskPrefix(qir::InstVMaskPrefix *) {}
	void visitInstVChunkExtend(qir::InstVChunkExtend *) {}
	void visitInstVChunkWiden(qir::InstVChunkWiden *) {}
	void visitInstVChunkNarrowShift(qir::InstVChunkNarrowShift *) {}
	void visitInstRVVTypedChunkPartial(qir::InstRVVTypedChunkPartial *ins) {}
	void visitInstRVVRunScalar(qir::InstRVVRunScalar *) {}
	// P7I. Plain AllocOp, and NO allocator change of any kind. AllocOp's operand loops are
	// already generic in n_out + n_in, so a 1-out/3-in node needs nothing new; CT(vchunkfma,
	// r_r_r_r) is GPR_ALL on every operand, which is the only shape VPRConstraint accepts for a
	// vector operand. The entry is required rather than optional: the base visitInst is
	// unreachable(), so omitting it is undefined behaviour in a release build, not a diagnostic.
	void visitInstVChunkFMA(qir::InstVChunkFMA *ins) { ra->AllocOp(ins); }
	// P8. Plain AllocOp and no allocator change: AllocOp's operand loops are generic in
	// n_out + n_in, so a 1-out/1-in node needs nothing new, and CT(vchunkfsqrt, r_r) is GPR_ALL on
	// both operands, the only shape VPRConstraint accepts for a vector operand. Required, not
	// optional, for the reason the fused entry above gives.
	void visitInstVChunkFSqrt(qir::InstVChunkFSqrt *ins) { ra->AllocOp(ins); }
	// P9. Plain AllocOp: the operand loops are generic in n_out + n_in, and a 0-out/2-in node needs
	// nothing new. The opcode is SIDEEFF (it writes CPUState), which is what makes AllocOp sync
	// dirty guest globals before it runs, exactly as for vstatechunkstore.
	void visitInstVChunkFCmpState(qir::InstVChunkFCmpState *ins) { ra->AllocOp(ins); }
	// P10. Plain AllocOp. The operands' VALUE types differ in width, which the allocator already
	// handles for every V128/V256/V512 value; the constraint table is register-class only.
	void visitInstVChunkFWidenCvt(qir::InstVChunkFWidenCvt *ins) { ra->AllocOp(ins); }
	void visitInstRVVQCGFPBegin(qir::InstRVVQCGFPBegin *) {}
	void visitInstRVVQCGFPEnd(qir::InstRVVQCGFPEnd *) {}

	// S2.9. Plain AllocOp, the same entry point every scalar op uses, and NO allocator change of
	// any kind is made for it. The op is one GPR in and one GPR out under CT(rvvsetvl, r_r), so
	// AllocOp's ordinary scalar bodies handle both operands and the pin analysis needs nothing
	// either -- it reads output constraints generically and GPR(R) is the whole pool. Because the
	// opcode is SIDEEFF (and NOT HAS_CALLS), AllocOp's side-effect loop syncs dirty guest globals
	// here without the full call-clobber spill CallOp would impose; see qir_ops.h.
	void visitInstRVVSetVL(qir::InstRVVSetVL *ins)
	{
		ra->AllocOp(ins);
	}
	void visitInstRVVSetVLReg(qir::InstRVVSetVLReg *ins) { ra->AllocOp(ins); }

	// The typed RVV SSA instructions are emitted only by the LLVM-AOT translator.
	// Keep QCG fail-safe if one is ever routed here: treating it as a call boundary
	// prevents scalar guest registers from being assumed live across an unsupported op.
#define RVV_SSA_QRA_VISITOR(cls)                                                                            \
	void visit##cls(qir::cls *ins)                                                                         \
	{                                                                                                      \
		ra->CallOp(true);                                                                                 \
	}
	RVV_SSA_QRA_VISITOR(InstRVVRead)
	RVV_SSA_QRA_VISITOR(InstRVVWrite)
	RVV_SSA_QRA_VISITOR(InstRVVSplatF)
	RVV_SSA_QRA_VISITOR(InstRVVLoad)
	RVV_SSA_QRA_VISITOR(InstRVVStore)
	RVV_SSA_QRA_VISITOR(InstRVVFCmp)
	RVV_SSA_QRA_VISITOR(InstRVVMerge)
	RVV_SSA_QRA_VISITOR(InstRVVFALU)
	RVV_SSA_QRA_VISITOR(InstRVVFMA)
	RVV_SSA_QRA_VISITOR(InstRVVFPBegin)
	RVV_SSA_QRA_VISITOR(InstRVVFPEnd)
#undef RVV_SSA_QRA_VISITOR

	void visit_sll(qir::InstBinop *ins)
	{
		ra->AllocOp(ins);
	}

	void visit_srl(qir::InstBinop *ins)
	{
		ra->AllocOp(ins);
	}

	void visit_sra(qir::InstBinop *ins)
	{
		ra->AllocOp(ins);
	}

private:
	QRegAlloc *ra{};
};

void QRegAlloc::Run()
{
	Prologue();
	PinSelect();
	AnalyzeVPRRetirement();

	qir::Block *prev = nullptr;
	for (auto &bb : region->GetBlocks()) {
		if (dbt::config::qcg_resident) {
			// A block whose UNIQUE predecessor is the previously-emitted block inherits that block's resident
			// guest registers (the predecessor's BlockBoundary sync'd-but-kept them) -> no reload. Any other
			// block (region entry, a merge with >1 pred, or a pred not laid out immediately before) has an
			// ambiguous incoming register state at runtime, so reset all guest regs to memory at entry; they
			// were already sync'd by every predecessor's BlockBoundary, so this Spill emits no store, only
			// frees the host registers (loc=MEM). This is what makes merges/loop-headers correct.
			auto &preds = bb.GetPreds();
			bool inherit = prev && preds.size() == 1 && preds[0] == prev;
			if (inherit) dbt::config::g_resident_inherit++; else dbt::config::g_resident_reset++;
			if (!inherit) {
				qb = qir::Builder(&bb, bb.ilist.begin());
				for (qir::RegN i = 0; i < n_vregs; ++i)
					if (vregs[i].is_global)
						Spill(&vregs[i]);
			}
		}

		auto &ilist = bb.ilist;
		for (auto iit = ilist.begin(); iit != ilist.end(); ++iit) {
			qb = qir::Builder(&bb, iit);
			QRegAllocVisitor(this).visit(&*iit);
			// After the visit: the instruction's own operands are allocated, and the spills and
			// fills the allocator inserted went in BEFORE it, so nothing this retirement frees
			// can be needed again.  Retirement points were collected in this exact walk order
			// (AnalyzeVPRRetirement) and the allocator only ever inserts around an existing
			// instruction, never reorders or removes one, so the cursor stays in step.
			RetireAt(&*iit);
		}
		prev = &bb;
	}
	assert(retire_pos == n_retire);
}

void QRegAllocPass::run(qir::Region *region)
{
	QRegAlloc ra(region);
	ra.Run();
}

} // namespace dbt::qcg
