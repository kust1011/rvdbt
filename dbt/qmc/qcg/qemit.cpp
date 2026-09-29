#include "dbt/qmc/qcg/qemit.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_frame_semantics.h"
#include "dbt/execute.h"

// Z4B. The two gather-census counters, declared in rv32_cpu.h and defined here -- in the same
// translation unit as the emitter that bakes their address into generated code, so there is exactly
// one object and no reader can pick up a different copy. Zero unless the census switch armed the
// increments; see config::rvv_qcg_typed_chunk_vlse_gather_census.
extern "C" unsigned long long g_vlse_gather_fast = 0;
extern "C" unsigned long long g_vlse_gather_fallback = 0;

// P2a. The two active-chunk census counters, declared in rv32_cpu.h and defined here for exactly
// the reason the pair above is: the emitted code bakes in the address of one specific object, so
// there must be one object and no per-translation-unit copy a reader could miss. Zero unless
// config::rvv_qcg_active_chunk_census armed the adds.
extern "C" unsigned long long g_rvv_chunks_available = 0;
extern "C" unsigned long long g_rvv_chunks_executed = 0;

namespace dbt::qcg
{

QEmit::QEmit(qir::Region *region, CompilerRuntime *cruntime_, qir::CodeSegment *segment_, bool is_leaf_)
    : cruntime(cruntime_), segment(segment_), jit_mode(!cruntime->AllowsRelocation()), is_leaf(is_leaf_)
{
	spillframe_sp_offs = sizeof(uptr) * (is_leaf ? 1 : 2);

	// The JIT code is allocated by cruntime->AllocateCode (EmitCode), NOT by an asmjit JitRuntime; asmjit only
	// needs the target Environment. Using the static host Environment avoids constructing/destroying a
	// per-region JitRuntime (+ its JitAllocator) on every block translation. Output is identical (same env).
	if (jcode.init(asmjit::Environment::host())) {
		Panic();
	}
	jcode.attach(j._emitter());
	j.setErrorHandler(&jerr);
	jcode.setErrorHandler(&jerr);

	u32 n_labels = region->GetNumBlocks();
	labels.reserve(n_labels);
	for (u32 i = 0; i < n_labels; ++i) {
		labels.push_back(j.newLabel());
	}

	// T5d2a3: the pin assignment, taken here because QRegAllocPass has already run (qcg.cpp) and
	// `region->pins` is final. See EmitDeferredSideExits for what it is used for.
	n_pins = region->n_pins;
	for (u8 i = 0; i < n_pins; ++i) {
		pins[i] = region->pins[i];
	}
}

std::span<u8> QEmit::EmitCode()
{
	jcode.flatten();
	jcode.resolveUnresolvedLinks();

	size_t code_sz = jcode.codeSize();
	void *code_ptr = cruntime->AllocateCode(code_sz, 8);
	if (code_ptr == nullptr) {
		Panic();
	}

	jcode.relocateToBase((uptr)code_ptr);
	jcode.copyFlattenedData(code_ptr, code_sz);
	code_sz = jcode.codeSize();
	// A-line IC: resolve recorded blob/retaddr offsets to absolute addresses and register them
	// for the slowpath's patch lookup. jit_mode only (offsets are section-0-relative; QCG emits a
	// single text section).
	for (auto const &s : ic_sites) {
		tcache::ICRegister((uptr)code_ptr + s.ret_off, (u8 *)code_ptr + s.blob_off, _entry_ip);
		// PM round-10 P3 (--qcg-dispatch-ic-regret): populate this source's OWN blob address in its
		// regret-tracking slot, read back by the inline miss-path revert check qemit.cpp's blob
		// emission adds right after this same blob -- always populated here, synchronously, before
		// the compiled code this pointer is used FROM ever executes.
		if (unlikely(dbt::config::qcg_ic_regret))
			tcache::qcg_ic_regret_cache[tcache::gbrind_hitrate_hash(_entry_ip)].blob = (u8 *)code_ptr + s.blob_off;
	}
	return {(u8 *)code_ptr, code_sz};
}

void QEmit::DumpCode(std::span<u8> const &code)
{
	if (log_qcg.enabled()) {
		auto str = MakeHexStr(code.data(), code.size());
		log_qcg.write(str.c_str());
	}
}

static inline asmjit::x86::Gp make_gpr(qir::RegN pr, qir::VType type)
{
	switch (type) {
	case qir::VType::I8:
		return asmjit::x86::gpb(pr);
	case qir::VType::I16:
		return asmjit::x86::gpw(pr);
	case qir::VType::I32:
		return asmjit::x86::gpd(pr);
	default:
		unreachable("");
	}
}

static inline asmjit::x86::Gp make_gpr(qir::VOperand opr)
{
	return make_gpr(opr.GetPGPR(), opr.GetType());
}

// A VPR number names one physical register in the AVX-512 file; MASK64 would need the k-registers,
// which are not implemented (see qir::VTypeToRegClass).
//
// M2C. The host register FORM follows the value's TYPE: a V128 is xmm<n>, a V256 is ymm<n>, a V512
// is zmm<n> -- the same architectural register, named at the width the value actually occupies.
// This is the single place a QIR vector type becomes a host register operand, so no emitter can
// pick a width the type does not state, and adding a width later cannot be done by editing one
// emitter in isolation.
static inline asmjit::x86::Vec make_vpr(qir::RegN pr, qir::VType type)
{
	switch (type) {
	case qir::VType::V128:
		return asmjit::x86::Xmm(pr);
	case qir::VType::V256:
		return asmjit::x86::Ymm(pr);
	case qir::VType::V512:
		return asmjit::x86::Zmm(pr);
	default:
		Panic("qemit: VPR operand is not a vector value");
	}
}

static inline asmjit::x86::Vec make_vpr(qir::VOperand opr)
{
	return make_vpr(opr.GetPVPR(), opr.GetType());
}

// EVEX, always, for every vector move and lane operation this file emits.
//
// Without it AsmJit picks the shortest legal encoding, so `vpaddd xmm2, xmm3, xmm4` comes out
// VEX-encoded while the identical operation on zmm16+ comes out EVEX. Both are correct, but which
// one appears would then depend on which register the allocator happened to hand out -- the
// emitted bytes for one guest instruction would not be a function of the guest instruction. Pinning
// EVEX makes the encoding a property of the route, keeps all 32 registers addressable at every
// width, and is what the byte-level route tests can then assert against.
//
// It costs nothing at V512 (zmm has no VEX form), so no already-accepted golden byte sequence in
// the tree moves.
static inline void EvexOnly(asmjit::x86::Assembler &j)
{
	j.setInstOptions(asmjit::InstOptions::kX86_Evex);
}

// The State*/Loc* helpers below move a value between a host register and memory with a scalar
// `mov`. They are reached only from the --qcg-pin prologue, which pins guest globals and therefore
// only ever scalars. Fail closed rather than encoding a 64-byte value with a scalar mov.
static inline void assert_scalar_move(qir::VType type)
{
	if (qir::VTypeToRegClass(type) != qir::RegClass::GPR) {
		Panic("qemit: scalar state move on a non-GPR type");
	}
}

static inline asmjit::Imm make_imm(qir::VOperand opr)
{
	return asmjit::imm(opr.GetConst());
}

inline asmjit::x86::Mem QEmit::make_slot(qir::VOperand opr)
{
	auto size = VTypeToSize(opr.GetType());
	auto offs = opr.GetSlotOffs();
	asmjit::x86::Gp base;
	if (opr.IsLSlot()) {
		base = QEmit::R_SP;
		offs += spillframe_sp_offs;
	} else {
		base = QEmit::R_STATE;
	}
	return asmjit::x86::Mem(base, offs, size);
}

inline asmjit::Operand QEmit::make_operand(qir::VOperand opr)
{
	if (likely(opr.IsGPR())) {
		return make_gpr(opr);
	}
	if (opr.IsConst()) {
		return make_imm(opr);
	}
	if (opr.IsVPR()) {
		return make_vpr(opr);
	}
	return make_slot(opr);
}

inline asmjit::Operand QEmit::make_stubcall_target(RuntimeStubId stub)
{
	if (jit_mode) {
		return asmjit::imm(stub_tab[stub]);
	}
	return asmjit::x86::Mem(R_STATE, offsetof(CPUState, stub_tab) + RuntimeStubTab::offs(stub));
}

static inline asmjit::x86::CondCode make_cc(qir::CondCode cc)
{
	switch (cc) {
	case qir::CondCode::EQ:
		return asmjit::x86::CondCode::kEqual;
	case qir::CondCode::NE:
		return asmjit::x86::CondCode::kNotEqual;
	case qir::CondCode::LE:
		return asmjit::x86::CondCode::kSignedLE;
	case qir::CondCode::LT:
		return asmjit::x86::CondCode::kSignedLT;
	case qir::CondCode::GE:
		return asmjit::x86::CondCode::kSignedGE;
	case qir::CondCode::GT:
		return asmjit::x86::CondCode::kSignedGT;
	case qir::CondCode::LEU:
		return asmjit::x86::CondCode::kUnsignedLE;
	case qir::CondCode::LTU:
		return asmjit::x86::CondCode::kUnsignedLT;
	case qir::CondCode::GEU:
		return asmjit::x86::CondCode::kUnsignedGE;
	case qir::CondCode::GTU:
		return asmjit::x86::CondCode::kUnsignedGT;
	default:
		unreachable("");
	}
}

void QEmit::FrameSetup()
{
	if (!is_leaf) {
		// Push something to satisfy x86 frame alignment
		j.push(asmjit::x86::rcx);
	}
}

void QEmit::FrameDestroy()
{
	if (!is_leaf) {
		j.pop(asmjit::x86::rcx);
	}
}

void QEmit::Prologue(u32 ip)
{
	// j.int3();
	_entry_ip = ip;
	_entry_ip_hash = tcache::l1hash(ip) << 4;
	FrameSetup();
}

// A-line v3.1 (--qcg-freq-entry): one arrival counter per BLOCK label (see qemit.h). Replaces
// every source-side counting channel at stock's own granularity: inter-region arrivals enter via
// the region-entry block, intra-region br/brcc/fallthrough edges pass the successor's label.
// A block whose counter already saturated is emitted counter-free (compact retranslation).
void QEmit::EmitBlockArrivalCounter()
{
	u32 ip = bb->entry_ip;
	if (unlikely(dbt::config::qcg_freq_entry) && jit_mode && ip) {
		bool saturated = dbt::config::qcg_freq_retire &&
				 (tcache::SatCarrySaturated(ip, dbt::config::qcg_freq_sat_t) ||
				  tcache::SatTargetSaturated(ip, dbt::config::qcg_freq_sat_t));
		if (!saturated) {
			auto tmp2 = asmjit::x86::r12;
			auto *slot = tcache::EdgeSlotAlloc(ip);
			j.mov(tmp2.r64(), (uptr)slot);
			j.inc(asmjit::x86::qword_ptr(tmp2.r64()));
			if (dbt::config::qcg_freq_retire)
				tcache::SatSiteRegister(_entry_ip, ip, slot); // unit = region
		}
	}
	// shadow-equivalence probe: independent counter ALONGSIDE fully-stock counting
	if (unlikely(dbt::config::qcg_freq_shadow_out != nullptr) && jit_mode && ip &&
	    !dbt::config::qcg_freq_entry) {
		auto tmp2 = asmjit::x86::r12;
		j.mov(tmp2.r64(), (uptr)tcache::ShadowSlotAlloc(ip));
		j.inc(asmjit::x86::qword_ptr(tmp2.r64()));
	}
}

// Activation invariant (LINEB_GATE_IMPLEMENTATION_PLAN.md): region entry happens exactly once per
// dynamic execution of this QCG job's single basic block, so `n` (its static instruction count) IS the
// exact dynamic instruction count contributed by this entry -- not an approximation. Direct add-to-memory,
// no temp register needed. Default-off (--sr-activation-invariant); zero cost on the unmodified path.
void QEmit::EmitInstrSeenIncr(u32 n)
{
	if (!dbt::config::sr_activation_invariant || n == 0) {
		return;
	}
	j.add(asmjit::x86::qword_ptr(R_STATE, offsetof(CPUState, exec_instr_seen)), n);
}

void QEmit::StateFill(qir::RegN p, qir::VType type, u16 offs)
{
	assert_scalar_move(type);
	auto slot = asmjit::x86::ptr(R_STATE, offs);
	slot.setSize(VTypeToSize(type));
	j.mov(make_gpr(p, type), slot);
}

void QEmit::StateSpill(qir::RegN p, qir::VType type, u16 offs)
{
	assert_scalar_move(type);
	auto slot = asmjit::x86::ptr(R_STATE, offs);
	slot.setSize(VTypeToSize(type));
	j.mov(slot, make_gpr(p, type));
}

void QEmit::LocFill(qir::RegN p, qir::VType type, u16 offs)
{
	assert_scalar_move(type);
	auto slot = asmjit::x86::ptr(R_SP, offs);
	slot.setSize(VTypeToSize(type));
	j.mov(make_gpr(p, type), slot);
}

void QEmit::LocSpill(qir::RegN p, qir::VType type, u16 offs)
{
	assert_scalar_move(type);
	auto slot = asmjit::x86::ptr(R_SP, offs);
	slot.setSize(VTypeToSize(type));
	j.mov(slot, make_gpr(p, type));
}

void QEmit::Emit_hcall(qir::InstHcall *ins)
{
	assert(!is_leaf);
	j.mov(asmjit::x86::rdi, R_STATE);
	j.emit(asmjit::x86::Inst::kIdMov, asmjit::x86::rsi, make_operand(ins->i(0)));
	j.emit(asmjit::x86::Inst::kIdCall, make_stubcall_target(ins->stub));
}

// T5d2a2 LOOP-TIER NOTIFICATION (--loop-tier, default off), emitted INSIDE Emit_Cache and nowhere
// else. Requested by every direct BACKWARD edge -- `Emit_gbr` for a region-exit backedge, `Emit_br`
// and `Emit_brcc`'s taken arm for the intra-region ones, each on its own translator-computed
// retreating fact.
//
// WHY HERE AND NOT ANYWHERE ELSE. Wendell profiling already does, on this exact edge, the only
// expensive part of the question: it hashes the target ip into the L1 `cache_tb_exec_count` array,
// compares the tag, loads the target's `TBlock *` into r12, and increments
// `TBlock::flags.exec_count`. At the instruction after that `inc`, r12 already holds the TBlock and
// the counter already holds its new value. The notification is therefore a chain of compares on a
// pointer that is already in a register -- it performs NO second lookup, hashes nothing, and adds no
// counter of its own. A separate "is this loop hot yet" probe would have had to redo all of it.
//
// FOUR TESTS AND A CLAIM, in this order, all skipping to the same `skip_cache`:
//
//   (1) `exec_count >= bar`      -- the evidence: this target reached the compiler's admission bar.
//   (2) `loop_tier_state == ARMED` -- a notification could still be used.
//   (3) `loop_tier_event_ip == 0`  -- the one-slot mailbox is free.
//   (4) `*notify == 0`             -- this GUEST TARGET has not notified before; claim it.
//
// then the payload store and `lock or` of the service bit. See dbt/config.h's T5d2a2 block for what
// each test buys; the three properties that are specific to the GENERATED form are these:
//
// `>=`, NOT `==` (T5d2a1's form, and the defect that replaces it). `exec_count` is shared by every
// incoming path -- Execute()'s host loop increments it on each arrival that returns there, and a
// forward direct edge counts into the same word from its own Emit_Cache with no notification
// attached. An exact equality can therefore be CONSUMED by an arrival this edge never runs on, after
// which this edge sees `bar + 1` for ever and the loop is never reported at all. That is a silent
// miss, not a fail-safe one, and no argument about who writes `service_request` removes it. `>=`
// cannot be consumed; the one-shot equality gave for free is restored by (4).
//
// (4) IS ADDRESSED BY AN IMMEDIATE RESOLVED AT TRANSLATION TIME. `LoopTierNotifySlot(target_ip)`
// is called by this function, in the compiler, not by the emitted code -- so the run pays no lookup
// for it, and the byte it names is keyed by the GUEST IP and survives every retranslation of the
// block. A flag in the TBlock would be cleared by any revoke/retranslate and the same loop would
// notify once per translation.
//
// (2) IS WHY A SPENT TIER IS SILENT. Once `loop_tier_state` leaves ARMED there is no path back, so
// every later backward edge in the program stops at that compare: no payload store, no service bit,
// and therefore no further T5d0 safepoint escape. Under T5d2a1 the generated code did not test the
// state at all, and the committed run shows the consequence -- one consumed event but four escapes,
// and a summary naming a block that had nothing to do with the build.
//
// THE BAR IS BAKED, and that is exact rather than convenient: `sr_chunk_threshold` is set once from
// the command line before the guest boots and is the same number the child receives as
// `--threshold`. It is loaded into a register rather than used as an imm32 so that a bar above
// INT32_MAX -- which the below-bar control arm uses -- is compared correctly instead of truncated.
//
// COST. Below the bar the sequence is exactly what T5d2a1's was: load the bar, one compare, one
// not-taken branch. A target that HAS reached the bar pays the state compare as well (and, until it
// has notified, the mailbox and notify compares) on each later arrival. That is a real per-arrival
// cost on hot targets and it is not hidden here; it is the price of a notification that cannot be
// stolen by another writer of the counter, and this checkpoint makes no timing claim.
void QEmit::Emit_Cache(u32 target_ip, bool loop_tier_backedge, bool intra_region)
{
	// P1 (--p1-promote): DC-1 undo, flag-scoped. In an aot run QCG translations normally emit NO
	// counting, so an exiled (not-in-artifact) span can never earn admission evidence. With P1 the
	// run's own QCG code counts again; artifact code is untouched (compiled offline). See config.h.
	if ((dbt::config::use_aot && !dbt::config::p1_promote) || dbt::config::not_freq) {
		return;
	}
	if (unlikely(dbt::config::qcg_freq_entry)) {
		return; // v3: arrivals are counted once at the target TB's entry (Prologue)
	}
	if (unlikely(dbt::config::qcg_freq_scratch)) {
		// WITNESS ONLY: single absolute-address RMW, no hash chain (see config.h).
		auto tmp2 = asmjit::x86::r12;
		j.mov(tmp2.r64(), (uptr)&dbt::config::qcg_freq_scratch_slot);
		j.inc(asmjit::x86::qword_ptr(tmp2.r64()));
		return;
	}
	if (unlikely(dbt::config::qcg_freq_edge) && jit_mode) {
		// A-line EDGE: single inc to a per-edge slot in a SEPARATE data arena (never in the code
		// pool: writing next to executing code triggers x86 SMC machine-clears -- measured 2x
		// whole-run slowdown with code-embedded slots). No loads, no hash, no collision guard;
		// folded into per-TB counts at UpdateProfile.
		auto tmp2 = asmjit::x86::r12;
		j.mov(tmp2.r64(), (uptr)tcache::EdgeSlotAlloc(target_ip));
		j.inc(asmjit::x86::qword_ptr(tmp2.r64()));
		return;
	}
	auto skip_cache = j.newLabel();
	// auto tmp0 = asmjit::x86::rdi;
	auto tmp1 = asmjit::x86::rsi;
	auto tmp2 = asmjit::x86::r12;
	log_dbt("Emit_Cache from %08x to %08x", _entry_ip, target_ip);

	// (RETIRE now pairs with --qcg-freq-entry only: block-arrival counters are the retirement
	// unit; the earlier stock-chain retire form was falsified -- see PROFILE_REPRESENTATION_CYCLE)
	if (jit_mode) {
		j.mov(tmp2.r64(), (uptr)tcache::cache_tb_exec_count.data());
	} else {
		j.mov(tmp2.r64(), asmjit::x86::Mem(R_STATE, offsetof(CPUState, cache_tb_exec_count)));
	}
	j.mov(tmp1.r32(), target_ip); // move jump target to tmp0
	j.lea(tmp1.r32(), asmjit::x86::ptr(0, tmp1.r32(), 2)); // tmp1 = (f_id << 2)
	j.and_(tmp1.r32(), ((1ull << tcache::L1_CACHE_BITS) - 1) << 4); // tmp1 = (f_id & ((1 << L1_CACHE_BITS) - 1)) << 4
	j.cmp(asmjit::x86::ptr(tmp2.r64(), tmp1.r32(), 0, 0, sizeof(u32)), target_ip);
	// j.mov(tmp1.r32(), _entry_ip_hash);
	j.jne(skip_cache);
	j.mov(tmp2.r64(), asmjit::x86::ptr(tmp2.r64(), tmp1.r32(), 0, offsetof(tcache::CacheTbExecCountEntry, tb), sizeof(u64)));
	if (unlikely(dbt::config::qcg_freq_sat)) {
		// SAT: skip the RMW once the counter reached T (decision-sufficient, see config.h)
		j.cmp(asmjit::x86::qword_ptr(tmp2.r64(), offsetof(TBlock, flags) + 8),
		      (int32_t)dbt::config::qcg_freq_sat_t);
		j.jae(skip_cache);
	}
	j.inc(asmjit::x86::qword_ptr(tmp2.r64(), offsetof(TBlock, flags) + 8));
	if (unlikely(dbt::config::loop_tier) && loop_tier_backedge && jit_mode) {
		// THE COMPILER's own lookup, done once, here: the byte this target's one-shot lives in.
		// Nothing about it is computed by the emitted code.
		auto notify_slot = (uptr)dbt::config::LoopTierNotifySlot(target_ip);

		// T5d2a3/T5d2b0: this edge's out-of-line exit block, reserved ONCE and entered from two
		// places -- the notification path below (T5d2a3) and, when the completion poll is on, the
		// poll (T5d2b0). One block, one BranchSlot, one target guest PC: the two entries differ
		// only in WHY control is being handed back, never in where it resumes.
		bool const want_exit = unlikely(dbt::config::loop_tier_side_exit) && intra_region &&
				       likely(!dbt::config::trace) && !dbt::config::rvv_vector_ssa;
		asmjit::Label side_exit;
		if (want_exit) {
			side_exit = RequestSideExit(target_ip);
		}

		// (1) THE EVIDENCE. tmp2 still holds THIS target's TBlock -- the same pointer the `inc`
		// above just used -- and tmp1 is dead: its hashed index was consumed by the load two
		// instructions ago. So this test reloads nothing and hashes nothing; it compares the
		// counter that was just written. `jb`, so an arrival by any other path cannot step over
		// the value this edge is waiting for.
		j.mov(tmp1.r64(), (uptr)dbt::config::sr_chunk_threshold);
		j.cmp(asmjit::x86::qword_ptr(tmp2.r64(), offsetof(TBlock, flags) + 8), tmp1.r64());
		j.jb(skip_cache);
		// From here tmp2 is dead too: the TBlock has answered the only question asked of it.
		//
		// T5d2b0 THE CHILD-COMPLETION POLL (--loop-tier-completion-exit, default off), and it sits
		// HERE for a reason: after the evidence test, so a target below the bar pays exactly what
		// it paid before, and before the ARMED test, because the state this poll exists to serve is
		// BUILDING -- which is precisely the state T5d2a2's next compare stops at. Once the tier is
		// BUILDING its notification is spent by design (the one-shot is claimed and the state has
		// left ARMED), a second hotness event is deliberately impossible, and the guest can stay in
		// this one region for the rest of the run. So the only thing left that can hand control
		// back is the runtime asking for it, which is exactly the question T5d0's safepoint asks on
		// a gbr -- asked here on the one edge class T5d0 cannot reach.
		//
		// WHAT SETS THE WORD IS THE CHILD'S OWN TERMINATION. SIGCHLD raises `kSvcLoopTier` from a
		// handler that writes two lock-free atomics and nothing else; `Arm()` refuses every other
		// consumer of this word, so with the tier armed no other bit can be set and `cmp <word>, 0`
		// is exact. No timer, no cadence, no directory poll, no clock.
		//
		// COST: one load, one compare, one not-taken branch, on targets the run has already
		// admitted evidence for. The taken path counts itself and jumps to the SAME block the
		// notification path uses, so control resumes at this edge's own target either way.
		if (want_exit && unlikely(dbt::config::loop_tier_completion_exit)) {
			auto no_completion = j.newLabel();
			j.mov(tmp1.r64(), (uptr)dbt::config::ServiceRequestWordAddr());
			j.cmp(asmjit::x86::dword_ptr(tmp1.r64()), 0);
			j.je(no_completion);
			// AND A BUILD MUST ACTUALLY BE OUTSTANDING. SIGCHLD is process-wide: an unrelated host
			// child terminating raises the same word, and without this compare a PUBLISHED, FAILED,
			// ABSTAINED or ARMED tier would hand control back for a builder completion that cannot
			// exist. The state load is on the path where the word is already non-zero, so the
			// fall-through -- one load, one compare, one not-taken branch -- is unchanged.
			j.mov(tmp1.r64(), (uptr)&dbt::config::loop_tier_state);
			j.cmp(asmjit::x86::dword_ptr(tmp1.r64()), (int32_t)dbt::config::kLoopTierBuilding);
			j.jne(no_completion);
			// Counted at the ENTRY, not in the block, because the block has two entries and its
			// own counter cannot tell them apart. Cold path only.
			j.mov(tmp1.r64(), (uptr)&dbt::config::loop_tier_completion_exits);
			j.inc(asmjit::x86::qword_ptr(tmp1.r64()));
			j.jmp(side_exit);
			j.bind(no_completion);
			dbt::config::loop_tier_completion_exit_sites++;
		}
		// (2) CAN A NOTIFICATION STILL BE USED? Everything below is skipped once the tier leaves
		// ARMED, which is the whole of "a spent tier's generated code is silent".
		j.mov(tmp1.r64(), (uptr)&dbt::config::loop_tier_state);
		j.cmp(asmjit::x86::dword_ptr(tmp1.r64()), (int32_t)dbt::config::kLoopTierArmed);
		j.jne(skip_cache);
		// (3) IS THE MAILBOX FREE? If a notification is already pending, this target leaves its
		// own one-shot INTACT and retries at its next backward edge -- so nothing overwrites a
		// payload the consumer has not read, and no target's evidence is silently dropped.
		j.mov(tmp2.r64(), (uptr)&dbt::config::loop_tier_event_ip);
		j.cmp(asmjit::x86::dword_ptr(tmp2.r64()), 0);
		j.jne(skip_cache);
		// (4) HAS THIS GUEST TARGET NOTIFIED BEFORE? One byte, at an address the compiler
		// resolved above; claimed here, once and for the life of the process.
		j.mov(tmp1.r64(), notify_slot);
		j.cmp(asmjit::x86::byte_ptr(tmp1.r64()), 0);
		j.jne(skip_cache);
		j.mov(asmjit::x86::byte_ptr(tmp1.r64()), 1);
		// The payload, stored BEFORE the bit so a consumer that sees the request also sees the
		// target that raised it. x86 stores are ordered, and the consumer runs on this same
		// thread a few instructions later at this edge's own safepoint, so no fence is owed.
		j.mov(asmjit::x86::dword_ptr(tmp2.r64()), (int32_t)target_ip);
		j.mov(tmp1.r64(), (uptr)dbt::config::ServiceRequestWordAddr());
		j.lock().or_(asmjit::x86::dword_ptr(tmp1.r64()), (int32_t)dbt::config::kSvcLoopTier);
		dbt::config::loop_tier_event_sites++;
		// T5d2a3: THE ONE INSTRUCTION THIS CHECKPOINT ADDS TO THE GENERATED EDGE, and it is on the
		// path that has just claimed the target's one-shot -- so it is reached at most once per
		// guest target for the life of the process, and never at all below the bar. Everything
		// else lives in the out-of-line block this names. The no-event path still falls into
		// `skip_cache` and takes the region's own in-region branch.
		//
		// SCOPED TO INTRA-REGION EDGES. A `gbr` backedge already leaves through T5d0's safepoint
		// at its own slot, immediately, so it needs nothing here; only an edge whose successor
		// stays inside the region has no escape of its own. `--trace` and `--rvv-vector-ssa` are
		// refused for the frame and vector-state reasons config.h states, not skipped silently:
		// looptier::Arm refuses to arm alongside either.
		if (want_exit) {
			j.jmp(side_exit);
		}
	}
	j.bind(skip_cache);
	if (dbt::config::trace) {
		j.mov(asmjit::x86::r14, target_ip);
		j.mov(asmjit::x86::r15, _entry_ip);
		if (is_leaf) {
			j.push(asmjit::x86::rcx);
		}

		j.emit(asmjit::x86::Inst::kIdCall, make_stubcall_target(RuntimeStubId::id_trace_cache));

		if (is_leaf) {
			j.pop(asmjit::x86::rcx);
		} else {
			FrameDestroy();
		}
	}
}

void QEmit::Emit_br(qir::InstBr *ins)
{
	auto bb_s = bb->GetSuccs().at(0);
	auto bb_ff = &*++bb->getIter();

	// T5d2a1: an intra-region backward edge is a direct backward edge, and it is the one that
	// moves a tight loop header's counter. See InstBr::backedge.
	// T5d2a3: it is also the UNCONDITIONAL in-region form, so it passes `intra_region` -- this
	// edge has no branch slot and no safepoint of its own.
	Emit_Cache(ins->ip, ins->backedge, true);

	if (bb_s != bb_ff) {
		j.jmp(labels[bb_s->GetId()]);
	}
}

void QEmit::Emit_brcc(qir::InstBrcc *ins)
{
	auto bb_t = bb->GetSuccs().at(0);
	auto bb_f = bb->GetSuccs().at(1);
	auto bb_ff = &*++bb->getIter();

	auto &vs0 = ins->i(0);
	auto &vs1 = ins->i(1);

	// constfolded
	if (vs0.IsConst()) {
		std::swap(vs0, vs1);
		ins->cc = qir::SwapCC(ins->cc);
	}
	auto cc = ins->cc;

	j.emit(asmjit::x86::Inst::kIdCmp, make_operand(vs0), make_operand(vs1));
	auto jcc = asmjit::x86::Inst::jccFromCond(make_cc(cc));
	// j.emit(jcc, labels[bb_t->GetId()]);
	auto jump_bb_t= j.newLabel();
	auto end = j.newLabel();
	j.emit(jcc, jump_bb_t);

	// false path
	if (!ins->f_gbr) // not gbr, we must count here.
		Emit_Cache(ins->f_ip);
	if (bb_f != bb_ff) {
		j.jmp(labels[bb_f->GetId()]);
	}
	j.jmp(end);
	j.bind(jump_bb_t);
	// true path
	if (!ins->t_gbr) // not gbr, we must count here.
		// T5d2a1: the taken arm, when it stays in-region. T5d2a3: `!t_gbr` IS the in-region
		// fact, so the same test that decides to count here decides that this edge owns its exit.
		Emit_Cache(ins->t_ip, ins->t_backedge, true);
	j.jmp(labels[bb_t->GetId()]);

	j.bind(end);
}

// T5d-0 BACKEDGE SAFEPOINT (--qcg-backedge-safepoint, default off).
//
// Emitted between FrameDestroy() and the branch slot of a direct BACKWARD region exit:
//
//     mov  rax, &config::service_request     ; 10 B
//     cmp  dword ptr [rax], 0                ;  3 B
//     je   <slot>                            ;  2 B   -- the ONLY fall-through cost
//     mov  rax, &config::backedge_safepoint_escapes
//     inc  qword ptr [rax]
//     mov  dword ptr [r13 + CPUState::ip], <target>
//     lea  rax, [rip + <slot>]
//     mov  r12, <qcgstub_escape_link>
//     jmp  r12
//   <slot>:  <BranchSlot bytes, unchanged>
//
// WHY THIS IS A LEGAL PLACE TO LEAVE TRANSLATED CODE. Four properties hold here, and each of them
// is a property of the surrounding machinery rather than of this patch:
//
//  1. GUEST STATE IS COMMITTED. `gbr` carries qir::Inst::Flags::REXIT, so QRegAlloc's visitInstGBr
//     runs RegionBoundary(), which writes every guest global back to CPUState -- pinned registers
//     unconditionally, the rest through their spill slots. Nothing architectural is left in a host
//     register at this point. This is the same fact the existing lazy-link escape depends on.
//
//  2. THE HOST STACK IS AT THE REGION-ENTRY LEVEL. Emit_gbr calls FrameDestroy() before the slot,
//     which pops the alignment push FrameSetup() made, so rsp here equals the value it had when
//     the region was entered from `trampoline_to_jit`'s `call`. `qcgstub_escape_link` unwinds by
//     `add rsp, spillframe_size + 16` and six pops, which is exactly the reverse of what the
//     trampoline built. The stub is entered from the lazy-link path at this same rsp (the stub
//     pops the slot's return address before `jmp *%rdx`), so jumping to it directly from here
//     hands it the stack shape it was written for.
//
//  3. THE TARGET PC IS THE EDGE'S OWN. `ins->tpc` is a QIR-level constant, so the store into
//     CPUState::ip is a single immediate, not a computed value; Execute() resumes at exactly the
//     address the guest branch names, before any instruction of the target block runs.
//
//  4. THE VALUE Execute() RECEIVES IS THIS EDGE'S SLOT. `qcgstub_escape_link` forwards rax to the
//     trampoline's caller as the `BranchSlot *`. `lea rax, [rip + slot]` puts this edge's own slot
//     there, so Execute() takes its `if (branch_slot)` arm and does what the lazy-link path's
//     not-found case would have done -- Link(), RecordLink(), CacheBr() -- and its
//     `assert(branch_slot->gip == state->ip)` holds because the slot's gip IS `ins->tpc`. The
//     alternative, returning nullptr through escape_brind, would send a DIRECT edge through the
//     indirect-branch bookkeeping (CacheBrind) and pollute the L1 dispatch cache, so it is not
//     used here even though it is one instruction shorter.
//
// REGISTERS. Only rax is written on the fall-through path, and rax is dead at a gbr: an unlinked
// slot's own `mov rax, imm64; call rax` clobbers it on the first traversal of EVERY direct branch,
// so no region can be entered expecting a live rax. r12 is written only on the escape path, where
// the region is being abandoned and property 1 has already committed everything that matters.
//
// JIT MODE ONLY. Both immediates are addresses in THIS process (a config global and a runtime-stub
// entry). An AOT artifact is compiled by elfaot and executed by elfrun, so baking either address
// into relocatable output would be meaningless there. The offline AOT path is therefore
// byte-identical with the flag on or off, which is checked rather than asserted.
void QEmit::EmitBackedgeSafepoint(qir::InstGBr *ins, asmjit::Label const &slot_label)
{
	// THE FLAG-OFF PATH DOES NOTHING AT ALL, and the first statement is what makes that true.
	// An earlier version counted `gbr_total` before this test, so a run with the feature switched
	// off still moved a global -- inert in its generated bytes but not in its observable state.
	// Independent review rejected that: "default off" has to mean the process behaves as it did
	// before the feature existed, and a denominator is not a reason to make an off run different.
	// The denominator is now collected only by a run that asked for the feature, which is the only
	// run that has any use for it.
	if (likely(!dbt::config::qcg_backedge_safepoint) || !jit_mode) {
		return;
	}
	dbt::config::backedge_safepoint_gbr_total++;
	if (!ins->backedge) {
		return;
	}
	dbt::config::backedge_safepoint_sites++;

	auto tmp = asmjit::x86::rax;
	auto tmp2 = asmjit::x86::r12;

	j.mov(tmp, (uptr)dbt::config::ServiceRequestWordAddr());
	j.cmp(asmjit::x86::dword_ptr(tmp), 0);
	j.je(slot_label);

	j.mov(tmp, (uptr)&dbt::config::backedge_safepoint_escapes);
	j.inc(asmjit::x86::qword_ptr(tmp));
	j.mov(asmjit::x86::ptr(R_STATE, offsetof(CPUState, ip), sizeof(u32)), (int32_t)ins->tpc.GetConst());
	j.lea(tmp, asmjit::x86::ptr(slot_label));
	j.mov(tmp2, (uptr)stub_tab[RuntimeStubId::id_escape_link]);
	j.jmp(tmp2);
}

asmjit::Label QEmit::RequestSideExit(u32 target_ip)
{
	auto entry = j.newLabel();
	side_exits.push_back({entry, target_ip});
	dbt::config::loop_tier_side_exit_sites++;
	return entry;
}

// T5d2a3 IMMEDIATE SERVICE EXIT for an INTRA-REGION direct backedge (--loop-tier-side-exit).
//
// The problem this closes is stated in T5D0_BACKEDGE_SAFEPOINT.md §7.4 as a measured boundary: an
// intra-region `br` is not a REXIT, so QRegAlloc has not run RegionBoundary() there and the
// architectural state is not committed -- covering it "needs a state-commit at a non-exit edge,
// which is a different change". This IS that change, and it is confined to a block that is reached
// only after a notification has been claimed:
//
//   <exit>:  mov  dword ptr [r13 + <pin offs>], <pinned preg>   ; 0..8 of these, --qcg-pin only
//            pop  rcx                                           ; FrameDestroy, !is_leaf only
//            mov  dword ptr [r13 + CPUState::ip], <target>
//            mov  rax, &config::loop_tier_side_exits
//            inc  qword ptr [rax]
//            lea  rax, [rip + <slot>]
//            mov  r12, <qcgstub_escape_link>
//            jmp  r12
//   <slot>:  <BranchSlot, gip = target>
//
// WHY IT IS OUT OF LINE. Emitted by this function, after the last basic block, so not one byte of
// it lies on any path the loop executes while it is running. The hot edge's only change is the
// `jmp` at the end of the notification sequence, which is itself behind the four T5d2a2 guards.
//
// THE FOUR PROPERTIES, each re-established here rather than inherited (config.h has the argument in
// full):
//
//  1. STATE. `BlockBoundary` already wrote every non-pinned global to CPUState before the branch;
//     the loop below writes the pinned ones, which is the same store `RegionBoundary` makes at a
//     gbr, from the same `Region::pins` the prologue filled them from. This must come FIRST: `ip`
//     is a global, and a later pin spill could otherwise overwrite the target PC (`PinSelect`
//     refuses to pin `ip`, so today it cannot, but the ordering does not rest on that).
//  2. FRAME. `FrameDestroy` undoes `Prologue`'s single alignment push, so `rsp` is what
//     `trampoline_to_jit`'s `call` left -- exactly the shape `qcgstub_escape_link` unwinds.
//  3. TARGET PC. A translator-level constant, so one immediate store; Execute() resumes at the
//     address the guest branch names, BEFORE any instruction of the target block runs.
//  4. THE SLOT. `escape_link` forwards rax as the `BranchSlot *`, and this block ends with a real
//     one whose `gip` is this edge's target -- so Execute() takes its DIRECT-edge arm (Link,
//     RecordLink, CacheBr) and its `assert(branch_slot->gip == state->ip)` holds. `escape_brind`
//     would be one instruction shorter and is not used: it would run `CacheBrind`, marking the
//     target `is_brind_target` and inserting it into the L1 dispatch cache -- contaminating the
//     profile this tier's child is about to compile.
//
// REGISTERS. rax and rdx are in ArchTraits::GPR_FIXED, so the register allocator never places a
// guest value in either; rax is free scratch at any point in the region. r12 is written last, after
// property 1 has committed everything architectural, and is restored by the stub's own `pop r12`.
// The pinned pregs are read before anything else writes.
void QEmit::EmitDeferredSideExits()
{
	if (side_exits.empty()) {
		return; // an ordinary run emits nothing here and never even takes the branch above
	}
	for (auto const &se : side_exits) {
		j.bind(se.entry);
		// 1. commit what BlockBoundary deliberately left resident
		for (u8 i = 0; i < n_pins; ++i) {
			StateSpill(pins[i].preg, pins[i].type, pins[i].offs);
		}
		// 2. the host frame, back to the level trampoline_to_jit built
		FrameDestroy();
		// 3. the exact guest PC this edge names -- after the state, never before
		j.mov(asmjit::x86::ptr(R_STATE, offsetof(CPUState, ip), sizeof(u32)), (int32_t)se.target_ip);
		auto tmp = asmjit::x86::rax;
		auto tmp2 = asmjit::x86::r12;
		j.mov(tmp, (uptr)&dbt::config::loop_tier_side_exits);
		j.inc(asmjit::x86::qword_ptr(tmp));
		// 4. leave through the direct-edge escape contract, carrying THIS exit's own slot
		auto slot_label = j.newLabel();
		j.lea(tmp, asmjit::x86::ptr(slot_label));
		j.mov(tmp2, (uptr)stub_tab[RuntimeStubId::id_escape_link]);
		j.jmp(tmp2);
		j.bind(slot_label);
		static constexpr size_t patch_size = sizeof(jitabi::ppoint::BranchSlot);
		j.embedUInt8(0, patch_size);
		auto *slot = (jitabi::ppoint::BranchSlot *)(j.bufferPtr() - patch_size);
		slot->gip = se.target_ip;
		slot->flags.cross_segment = !segment->InSegment(slot->gip);
		// jit_mode is a precondition of the whole path (Emit_Cache gates on it), so the lazy form
		// is the JIT one. Nothing ever falls into these bytes: the only way to reach them is the
		// `jmp` Execute() writes over them when it links this slot.
		slot->LinkLazyJIT();
	}
	// Emitted once. Clearing here rather than relying on the single call site means a second call
	// binds no label twice, which is what makes the "emitted after the last block" property a
	// property of QCodegen::Run and not of this function's luck.
	side_exits.clear();
}

void QEmit::Emit_gbr(qir::InstGBr *ins)
{
	// Even LinkLazyJIT is called, and it looks like always TryLinkBranch.
	// But the call path is different after first found, so TryLinkBranch is not called again.
	// So we just emit cache to profile here.
	//
	// T5d2a1/T5d2a2: the REGION-EXIT backward edge asks for the loop-tier notification here. It is
	// not the only site that asks -- `Emit_br` and `Emit_brcc`'s taken arm ask for the intra-region
	// backward edges, which is where a tight loop's latch actually lives (see MakeGBr) -- but every
	// site asks from a translator-computed retreating fact. The region-boundary fall-through and
	// `Emit_brcc`'s false arm call this function without one, and `Emit_gbrind` never calls it at
	// all, so a forward or indirect edge cannot notify; that is checked on emitted bytes.
	//
	// T5d2a3 passes `intra_region = false` here, explicitly: this edge IS a region exit and gets
	// its immediate escape from EmitBackedgeSafepoint below, at its own slot, so it must not also
	// be given an out-of-line exit block. Written out rather than left to the default so that the
	// three call sites read as one decision.
	Emit_Cache(ins->tpc.GetConst(), ins->backedge, false);
	FrameDestroy();
	// Alias/wrapper multi-entry contract (--aot-link-alias-merge / --aot-link-multientry-merge),
	// root cause #2 (real-workload-only obstruction, DESIGN8_ALIAS_MULTIENTRY_OBSTRUCTION.md):
	// this branch/call site self-patches (jitabi.cpp::TryLinkBranch's hit path -- and the raw
	// Jump32Rel/Jump64Abs/CallTab bytes embedded below on every subsequent execution) straight to
	// the resolved code, WITHOUT ever touching state->ip -- correct for an ordinary callee, but
	// WRONG if the resolved address is a multi-entry PRIMARY function whose own entry block now
	// contains an injected `switch(state->ip)` (Round-41 multi-entry codegen, shared by both the
	// wrapper and alias variants -- QIRToLLVM::merge_entries): a stale state->ip left over from
	// some earlier, unrelated indirect dispatch (e.g. a DIFFERENT caller's earlier call into the
	// SAME shared body) can misroute this direct call/branch into the wrong internal block.
	// Confirmed live via gdb on expat (--aot-link-alias-merge): memset's shared duff's-device
	// table is entered both via a plain `jr` (tail computed-goto, no return) and via `jalr ra,...`
	// (a "call" whose return continuation IS a link-merge candidate) -- any ORDINARY, unrelated
	// `jal ra, memset` elsewhere in the program reaches memset's now-multi-entry-ified primary
	// entry through exactly this path. The wrapper variant's cost-model gate (only hot enough T
	// gets a switch case) makes this harder to trigger, not impossible -- same injected switch,
	// same self-patching QCG-tier call path, so it gets the same fix. Unlike Emit_gbrind's
	// dispatch (a genuinely runtime-computed target needing a per-dispatch store), this branch's
	// target is a QIR-level compile-time CONSTANT (tpc.GetConst()), so the fix is a single
	// unconditional immediate store per call site, not per dispatch.
	if (unlikely(dbt::config::aot_link_alias_merge || dbt::config::aot_link_multientry_merge)) {
		j.mov(asmjit::x86::ptr(R_STATE, offsetof(CPUState, ip), sizeof(u32)),
		      (int32_t)ins->tpc.GetConst());
	}
	auto slot_label = j.newLabel();
	EmitBackedgeSafepoint(ins, slot_label);
	j.bind(slot_label);
	static constexpr size_t patch_size = sizeof(jitabi::ppoint::BranchSlot);
	j.embedUInt8(0, patch_size);
	auto *slot = (jitabi::ppoint::BranchSlot *)(j.bufferPtr() - patch_size);
	slot->gip = ins->tpc.GetConst();
	slot->flags.cross_segment = !segment->InSegment(slot->gip);
	if (jit_mode) {
		slot->LinkLazyJIT();
	} else {
		slot->LinkLazyAOT(offsetof(CPUState, stub_tab));
	}
}

void QEmit::Emit_gbrind(qir::InstGBrind *ins)
{
	auto ptgt = make_gpr(ins->i(0));
	assert(ptgt.id() == asmjit::x86::Gp::kIdSi);
	if (unlikely(ins->ccrf_boundary)) {
		// RegionBoundary has already committed every allocated guest value. Preserve the real
		// jalr target, destroy this generated frame, and return to Execute without consulting or
		// populating the indirect cache; the certificate-driven coordinator owns this boundary.
		j.mov(asmjit::x86::ptr(R_STATE, offsetof(CPUState, ip), sizeof(u32)), ptgt.r32());
		FrameDestroy();
		auto tmp = asmjit::x86::r12;
		j.mov(tmp, (uptr)stub_tab[RuntimeStubId::id_escape_brind]);
		j.jmp(tmp);
		return;
	}

	// A-line (--shadow-edges), item-3 fast-path fix: the previous design called
	// ShadowEdgeCheckImpl (jitabi.cpp) UNCONDITIONALLY on every dispatch (measured 4.67x-14.89x
	// overhead). _entry_ip is this TB's static entry address -- a compile-time constant here,
	// since a jalr always terminates its TB -- so tcache::shadow_edge_hash(_entry_ip) and hence
	// &tcache::shadow_edge_cache[...] are ALSO compile-time constants: bake the slot's absolute
	// host address as an immediate and do the hit/miss compare inline, mirroring the
	// l1_brind_cache check just below (same function) but SOURCE-indexed instead of
	// TARGET-indexed. Both `src` and `tgt` are checked -- a hash collision (two distinct source
	// addresses mapping to the same slot) fails the `src` compare and falls to the slow path
	// exactly like a genuine miss, so a collision can only cause an extra re-log, never a missed
	// edge (ShadowEdgeCheckImpl re-validates and updates the slot unconditionally on entry).
	if (unlikely(dbt::config::shadow_edges) && ins->shadow_track && likely(!dbt::config::trace)) {
		if (unlikely(dbt::config::shadow_edges_k >= 2)) {
			// H2 (--shadow-edges-k=<N>, N>=2, SUPPORT_DISCOVERY_H1_VS_H2.md): per-source K-way
			// history SET, orthogonal to and mutually exclusive with the H1 inline path below
			// (shadow_edges_k defaults to 0, so this branch is dead code and H1's behavior is
			// byte-identical unless explicitly requested). Deliberate first-cut scoping decision:
			// UNCONDITIONAL call into ShadowEdgeKCheckImpl (jitabi.cpp) every dispatch, same as
			// H1's own pre-item-3 design (c2aa6c31) -- the K-way hit/miss compare is a short (K<=8)
			// linear scan done in C++, not inlined here as compile-time-constant compares the way
			// H1's single-slot check is. Reuses the SAME _entry_ip/shadow_edge_tgt spill
			// discipline H1 established (no new QIR-level plumbing).
			j.mov(asmjit::x86::ptr(R_STATE, offsetof(CPUState, ip), sizeof(u32)), (int32_t)_entry_ip);
			j.mov(asmjit::x86::ptr(R_STATE, offsetof(CPUState, shadow_edge_tgt), sizeof(u32)), ptgt.r32());
			j.mov(asmjit::x86::gpq(asmjit::x86::Gp::kIdDi), R_STATE);
			if (is_leaf) {
				j.push(asmjit::x86::rcx);
			}
			j.emit(asmjit::x86::Inst::kIdCall, make_stubcall_target(RuntimeStubId::id_shadow_edge_check_k));
			if (is_leaf) {
				j.pop(asmjit::x86::rcx);
			}
		} else {
			auto &slot = tcache::shadow_edge_cache[tcache::shadow_edge_hash(_entry_ip)];
			auto tmpS = asmjit::x86::r10;
			auto shadow_slow = j.newLabel();
			auto shadow_done = j.newLabel();

			j.mov(tmpS.r64(), (uptr)&tcache::shadow_edge_total_dispatches);
			j.inc(asmjit::x86::qword_ptr(tmpS.r64()));

			j.mov(tmpS.r64(), (uptr)&slot);
			j.cmp(asmjit::x86::ptr(tmpS.r64(), offsetof(tcache::ShadowEdgeSlot, src), sizeof(u32)),
			      (int32_t)_entry_ip);
			j.jne(shadow_slow);
			j.cmp(asmjit::x86::ptr(tmpS.r64(), offsetof(tcache::ShadowEdgeSlot, tgt), sizeof(u32)),
			      ptgt.r32());
			j.jne(shadow_slow);
			j.jmp(shadow_done);

			j.bind(shadow_slow);
			j.mov(asmjit::x86::ptr(R_STATE, offsetof(CPUState, ip), sizeof(u32)), (int32_t)_entry_ip);
			j.mov(asmjit::x86::ptr(R_STATE, offsetof(CPUState, shadow_edge_tgt), sizeof(u32)), ptgt.r32());
			j.mov(asmjit::x86::gpq(asmjit::x86::Gp::kIdDi), R_STATE);
			if (is_leaf) {
				j.push(asmjit::x86::rcx);
			}
			j.emit(asmjit::x86::Inst::kIdCall, make_stubcall_target(RuntimeStubId::id_shadow_edge_check));
			if (is_leaf) {
				j.pop(asmjit::x86::rcx);
			}
			j.bind(shadow_done);
		}
	}

	// A-line round 14 (--shadow-edges2, TRACK 2): fully-inline, fixed 2-slot-per-source multi-
	// target collector, orthogonal to shadow_edges/shadow_edges_k (independent opt-in, no shared
	// state). Same compile-time-constant-address technique as H1 (_entry_ip is known at JIT-
	// compile time for a jalr-terminated TB, so shadow_edge2_hash(_entry_ip) is baked in as an
	// immediate, zero runtime hash cost) but tracks up to 2 (target,count) pairs per source
	// straight-line, with NO out-of-line call -- see tcache.h's ShadowEdge2Slot comment for why
	// (H2's out-of-line call measured 41-145% overhead; this design targets shadow-majority's
	// already-measured 7-12% inline-only overhead instead).
	if (unlikely(dbt::config::shadow_edges2) &&
	    (ins->shadow_track || dbt::config::shadow_edges2_all_jalr) && likely(!dbt::config::trace)) {
		auto &slot = tcache::shadow_edge2_cache[tcache::shadow_edge2_hash(_entry_ip)];
		auto tmpS = asmjit::x86::r11;
		// A-line round 15 (TRACK 1): TRUE per-class dispatch counter, unconditional, resolved to a
		// single compile-time-known counter address (ins->jalr_class is static) -- no runtime
		// branch, exact denominator even for high-fanout RETURN sites the 2-slot cache undercounts.
		if (likely(dbt::config::shadow_edges2_all_jalr)) {
			u64 *counter_addr = ins->jalr_class == 2   ? &tcache::shadow_edge2_dispatches_return
						 : ins->jalr_class == 1 ? &tcache::shadow_edge2_dispatches_tailcall
									 : &tcache::shadow_edge2_dispatches_call;
			j.mov(tmpS.r64(), (uptr)counter_addr);
			j.inc(asmjit::x86::qword_ptr(tmpS.r64()));
		}
		auto se2_check_t1 = j.newLabel();
		auto se2_check_empty = j.newLabel();
		auto se2_claim_fresh = j.newLabel();
		auto se2_done = j.newLabel();

		j.mov(tmpS.r64(), (uptr)&slot);
		j.cmp(asmjit::x86::ptr(tmpS.r64(), offsetof(tcache::ShadowEdge2Slot, src), sizeof(u32)),
		      (int32_t)_entry_ip);
		j.jne(se2_claim_fresh);
		j.cmp(asmjit::x86::ptr(tmpS.r64(), offsetof(tcache::ShadowEdge2Slot, t0), sizeof(u32)),
		      ptgt.r32());
		j.jne(se2_check_t1);
		j.inc(asmjit::x86::dword_ptr(tmpS.r64(), offsetof(tcache::ShadowEdge2Slot, c0)));
		j.jmp(se2_done);
		j.bind(se2_check_t1);
		j.cmp(asmjit::x86::ptr(tmpS.r64(), offsetof(tcache::ShadowEdge2Slot, t1), sizeof(u32)),
		      ptgt.r32());
		j.jne(se2_check_empty);
		j.inc(asmjit::x86::dword_ptr(tmpS.r64(), offsetof(tcache::ShadowEdge2Slot, c1)));
		j.jmp(se2_done);
		j.bind(se2_check_empty);
		// both t0 and t1 are occupied by OTHER (non-matching) targets -- if c1==0, slot1 was
		// never claimed (this source has had <2 distinct targets so far); claim it as the 2nd.
		// If c1!=0, this is a genuine 3rd+ distinct target -- dropped (capacity bound, see
		// tcache.h comment: coverage/precision cost only, multiguard's own fallback covers it).
		j.cmp(asmjit::x86::dword_ptr(tmpS.r64(), offsetof(tcache::ShadowEdge2Slot, c1)), 0);
		j.jne(se2_done);
		j.mov(asmjit::x86::ptr(tmpS.r64(), offsetof(tcache::ShadowEdge2Slot, t1), sizeof(u32)),
		      ptgt.r32());
		j.mov(asmjit::x86::dword_ptr(tmpS.r64(), offsetof(tcache::ShadowEdge2Slot, c1)), 1);
		j.jmp(se2_done);
		j.bind(se2_claim_fresh);
		j.mov(asmjit::x86::ptr(tmpS.r64(), offsetof(tcache::ShadowEdge2Slot, src), sizeof(u32)),
		      (int32_t)_entry_ip);
		j.mov(asmjit::x86::ptr(tmpS.r64(), offsetof(tcache::ShadowEdge2Slot, t0), sizeof(u32)),
		      ptgt.r32());
		j.mov(asmjit::x86::dword_ptr(tmpS.r64(), offsetof(tcache::ShadowEdge2Slot, c0)), 1);
		j.mov(asmjit::x86::dword_ptr(tmpS.r64(), offsetof(tcache::ShadowEdge2Slot, t1)), 0);
		j.mov(asmjit::x86::dword_ptr(tmpS.r64(), offsetof(tcache::ShadowEdge2Slot, c1)), 0);
		j.bind(se2_done);
	}

	// A-line 2026-07-27 (--temporal-order-collect, Codex 7th audit P1): per-source order-1/order-2
	// lag-match update, unconditional on EVERY dispatch through this site (not gated on the L1
	// cache hit/miss outcome, unlike gbrind_hitrate_collect/shadow_majority below) -- same
	// positioning discipline as shadow_edge2 immediately above (before the L1 check), so this
	// covers the entire profiling run, not just cache hits, and never forces a slowpath. See
	// tcache.h's TemporalOrderSlot comment for field semantics.
	//
	// COST HISTORY (kept honest, not scrubbed): two decimation attempts were tried to bring the
	// measured overhead below this simple version's 8.5-15.6%, and both were REJECTED after
	// measurement -- see the "COST NOTE" comment below on the exact numbers and root cause (a
	// global-tick version was also a real correctness bug: variable, cross-site-diluted sample
	// gaps silently redefined "lag1/lag2" away from "1/2 real dispatches ago for this site",
	// confirmed via direct repro). This simple, always-compare, 100%-sampling version is what
	// ships: correct (verified against exact full-population ground truth) but above the 1-2%
	// target -- reported as a real, unresolved limitation, not glossed over.
	if (unlikely(dbt::config::temporal_order_collect) &&
	    (ins->shadow_track || dbt::config::temporal_order_all_jalr) && likely(!dbt::config::trace)) {
		auto &tslot = tcache::temporal_order_cache[tcache::shadow_edge2_hash(_entry_ip)];
		auto tmpT = asmjit::x86::r10;
		auto to_fresh = j.newLabel();
		auto to_check_lag2 = j.newLabel();
		auto to_shift = j.newLabel();
		auto to_end = j.newLabel();

		j.mov(tmpT.r64(), (uptr)&tslot);
		j.cmp(asmjit::x86::ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, src), sizeof(u32)),
		      (int32_t)_entry_ip);
		j.jne(to_fresh);

		// existing slot: total++, compare-and-increment against last1/last2, then shift.
		// COST NOTE (two decimation attempts tried and REJECTED, not silently dropped): a global-
		// tick decimation measured WORSE than this simple always-compare version (expat 16.7% vs
		// 8.5%); a per-site-tick (`total`'s own low bits) decimation measured 12.96%, still worse.
		// Both added a gate branch that cost more than the compares it decimated away. This simple
		// 100%-sampling version (real measured overhead: expat +8.5%, wasm3_indcall +12.2%,
		// pugixml +15.6%, n=5, see SECTION_D_REAL_WORLD_BRIDGE.md) is the best real result achieved
		// this cycle -- `compared` always equals `total` here (kept as a field, not removed, so the
		// dump format/offline analysis code does not need a second variant).
		j.inc(asmjit::x86::qword_ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, total)));
		j.inc(asmjit::x86::qword_ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, compared)));
		j.cmp(asmjit::x86::ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, last1), sizeof(u32)),
		      ptgt.r32());
		j.jne(to_check_lag2);
		j.inc(asmjit::x86::qword_ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, lag1_match)));
		j.bind(to_check_lag2);
		j.cmp(asmjit::x86::ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, last2), sizeof(u32)),
		      ptgt.r32());
		j.jne(to_shift);
		j.inc(asmjit::x86::qword_ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, lag2_match)));
		j.bind(to_shift);
		// shift: last2 <- last1, last1 <- current target (read last1 BEFORE overwriting it)
		{
			auto tmpV = asmjit::x86::r11;
			j.mov(tmpV.r32(), asmjit::x86::ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, last1), sizeof(u32)));
			j.mov(asmjit::x86::ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, last2), sizeof(u32)), tmpV.r32());
		}
		j.mov(asmjit::x86::ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, last1), sizeof(u32)), ptgt.r32());
		j.jmp(to_end);
		j.bind(to_fresh);
		// fresh claim (new source, or hash collision with a different source): reset state to a
		// single-observation baseline -- this dispatch itself is not yet a "match" of anything
		// (last1/last2 start at 0, a sentinel no real target equals in practice on this project's
		// text-segment address ranges).
		j.mov(asmjit::x86::ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, src), sizeof(u32)),
		      (int32_t)_entry_ip);
		j.mov(asmjit::x86::ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, last1), sizeof(u32)), ptgt.r32());
		j.mov(asmjit::x86::dword_ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, last2)), 0);
		j.mov(asmjit::x86::qword_ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, total)), 1);
		j.mov(asmjit::x86::qword_ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, compared)), 1);
		j.mov(asmjit::x86::qword_ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, lag1_match)), 0);
		j.mov(asmjit::x86::qword_ptr(tmpT.r64(), offsetof(tcache::TemporalOrderSlot, lag2_match)), 0);
		j.bind(to_end);
	}

	auto slowpath = j.newLabel();
	// A-line 2026-07-23 (--qcg-dispatch-ic): 31-byte self-patching site IC ahead of the shared
	// L1-hash path. Unpatched guard compares esi (guest target, always even) against 0xFFFFFFFF
	// (odd sentinel) -> never matches, falls straight through to the unchanged L1 path; the brind
	// slowpath patches {guard imm32, count addr imm64, jmp rel32} on the site's first natural miss.
	// Layout (offsets):
	//   +0  81 FE ff ff ff ff     cmp esi, imm32          (guard; imm at +2)
	//   +6  0F 85 13 00 00 00     jne +19 -> blob end     (to the L1 path)
	//   +12 59 / 90               pop rcx (frame) / nop   (leaf has no frame)
	//   +13 49 BE <imm64>         mov r14, imm64          (exec-count addr; at +15)
	//   +23 49 FF 06              inc qword [r14]         (freq attribution preserved)
	//   +26 E9 <rel32>            jmp rel32               (direct jump to target; at +27)
	if (jit_mode && dbt::config::qcg_dispatch_ic && likely(!dbt::config::trace) &&
	    !dbt::config::profile_brind_edges &&
	    (dbt::config::qcg_dispatch_ic_site == 0 || dbt::config::qcg_dispatch_ic_site == _entry_ip)) {
		u8 blob[31];
		blob[0] = 0x81; blob[1] = 0xFE;
		memset(blob + 2, 0xFF, 4);
		blob[6] = 0x0F; blob[7] = 0x85;
		i32 jne_rel = 19;
		memcpy(blob + 8, &jne_rel, 4);
		blob[12] = is_leaf ? 0x90 : 0x59;
		blob[13] = 0x49; blob[14] = 0xBE;
		u64 dummy = (u64)&dbt::config::qcg_ic_dummy_count;
		memcpy(blob + 15, &dummy, 8);
		blob[23] = 0x49; blob[24] = 0xFF; blob[25] = 0x06;
		blob[26] = 0xE9;
		i32 jmp_rel = 0;
		memcpy(blob + 27, &jmp_rel, 4);
		pending_ic_blob_off = (u32)j.offset();
		j.embed(blob, sizeof(blob));
		has_pending_ic = true;
		// PM round-10 P3 (--qcg-dispatch-ic-regret): a real per-source MISS counter, placed
		// immediately after the blob so the guard's OWN `jne` fallthrough (taken whenever the
		// guard doesn't match -- INCLUDING cases the L1 path right after this would still resolve
		// as a software cache HIT) reaches it unconditionally, before falling into the unchanged
		// L1 path. This is deliberately NOT part of the self-patching blob above (its own address
		// is a compile-time constant, never patched, so ordinary asmjit emission is used instead
		// of hand-crafted bytes) -- counts EVERY guard miss, not just the rarer subset that also
		// misses the L1 software cache (which --qcg-dispatch-ic-regret's earlier, insufficient cut
		// at the qcgstub_brind call site would under-count almost entirely, since the L1 cache
		// alone already resolves ~99.999% of dispatches on real workloads). r11 is dead here (same
		// scratch register gbrind_hitrate_collect's own per-source counter already uses at this
		// exact program point, for the same reason: unused by the blob above and unused by the L1
		// path code that follows).
		if (unlikely(dbt::config::qcg_ic_regret)) {
			auto &slot = tcache::qcg_ic_regret_cache[tcache::gbrind_hitrate_hash(_entry_ip)];
			auto tmpBlob = asmjit::x86::r11;
			auto tmpVal = asmjit::x86::r10;
			auto tmpAddr = asmjit::x86::r9;
			auto regret_skip = j.newLabel();
			// Gate EVERYTHING below on the guard being genuinely PATCHED right now (its own
			// immediate is not the never-matching sentinel) -- otherwise this fallthrough is the
			// site's pre-first-patch state, not a real "committed guess just failed" event, and
			// must not be counted as a miss (counting it would trip the break-even check on the
			// very first-ever dispatch, before the guess is even made, reverting a guard that was
			// never given a fair trial).
			j.mov(tmpBlob.r64(), (uptr)&slot.blob);
			j.mov(tmpBlob.r64(), asmjit::x86::qword_ptr(tmpBlob.r64())); // tmpBlob = slot.blob (or 0)
			j.test(tmpBlob.r64(), tmpBlob.r64());
			j.jz(regret_skip); // blob not yet registered (should not happen post-emission; safe no-op)
			j.cmp(asmjit::x86::dword_ptr(tmpBlob.r64(), 2), 0xFFFFFFFFu);
			j.je(regret_skip); // still unpatched -- not yet a real committed guess
			// Real miss against an already-committed guess. Structural, zero-tuned-parameter
			// break-even check: the guard can only be a net loss once cumulative wrong guesses
			// (miss) outnumber cumulative right ones (hit), since both pay approximately the
			// same one-extra-compare fixed cost whenever the guard's own presence is the only
			// difference from the unguarded baseline. If tripped, permanently revert THIS
			// source's own blob to the never-matching sentinel (the same safe fallback every
			// guard mechanism in this codebase already uses) -- entirely inline, no runtime
			// call, no separate profile pass, no oracle.
			j.mov(tmpAddr.r64(), (uptr)&slot.miss);
			j.inc(asmjit::x86::qword_ptr(tmpAddr.r64()));
			j.mov(tmpVal.r64(), asmjit::x86::qword_ptr(tmpAddr.r64())); // tmpVal = miss (post-inc)
			j.mov(tmpAddr.r64(), (uptr)&slot.hit);
			j.cmp(tmpVal.r64(), asmjit::x86::qword_ptr(tmpAddr.r64()));
			j.jbe(regret_skip); // miss <= hit: not yet a net loss, nothing to do
			j.mov(asmjit::x86::dword_ptr(tmpBlob.r64(), 2), 0xFFFFFFFFu); // revert: write sentinel
			j.bind(regret_skip);
		}
	}
	// A-line Round 60 (--qcg-gbrind-outline, jit_mode/QCG tier only -- see qcgstub_brind_checked's
	// comment in jitabi.cpp for the full rationale): replace the normally-inlined l1_brind_cache
	// hit-check (~5-6 x86 instructions PER indirect-terminated TB, unconditionally emitted) with a
	// single out-of-line call that performs the SAME check once, shared across every site. Mutually
	// exclusive with the other experimental inline-check variants below (shadow_edges/shadow_edges2/
	// qcg_dispatch_ic/gbrind_hitrate_collect/shadow_majority) -- this is a probe of the base
	// mechanism's own compile-cost/execute-cost tradeoff, not meant to compose with them.
	if (jit_mode && dbt::config::qcg_gbrind_outline && likely(!dbt::config::trace)) {
		j.mov(asmjit::x86::gpq(asmjit::x86::Gp::kIdDi), R_STATE);
		if (is_leaf) {
			j.push(asmjit::x86::rcx);
		}
		j.emit(asmjit::x86::Inst::kIdCall, make_stubcall_target(RuntimeStubId::id_brind_checked));
		if (is_leaf) {
			j.pop(asmjit::x86::rcx);
		} else {
			FrameDestroy();
		}
		j.jmp(asmjit::x86::rax);
		j.bind(slowpath); // never reached on this path; binds the label declared above so it is not left dangling
		return;
	}
	if (likely(!dbt::config::trace))
	{
		// commented the original
		// Inlined l1_brind_cache lookup
		auto tmp0 = asmjit::x86::rdi;
		auto tmp1 = asmjit::x86::r14; // Note not using the regs in X(*) like X(rdx)
		auto tmp2 = asmjit::x86::r12;

		if (jit_mode) {
			j.mov(tmp1.r64(), (uptr)tcache::l1_brind_cache.data());
		} else {
			j.mov(tmp1.r64(), asmjit::x86::Mem(R_STATE, offsetof(CPUState, l1_brind_cache)));
		}

		static_assert(sizeof(tcache::BrindCacheEntry) == 16); // the size has been changed to count number of executions.
		static_assert(offsetof(tcache::BrindCacheEntry, gip) == 0);

		j.lea(tmp0.r32(), asmjit::x86::ptr(0, ptgt.r64(), 2));
		j.and_(tmp0.r32(), ((1ull << tcache::L1_CACHE_BITS) - 1) << 4);
	
		j.cmp(asmjit::x86::ptr(tmp1.r64(), tmp0.r64(), 0, 0, sizeof(u32)), ptgt.r32());
		j.jne(slowpath);

		// A-line Round 48 (--gbrind-hitrate-collect): per-source HIT counter for the L1 gbrind-cache
		// check just above -- r11 is dead here (only used by the earlier, self-contained shadow_edges/
		// shadow_edges_k sections, if emitted at all) and not read again before this fastpath's own
		// tmp0/tmp1 reuse at the jmp below, so it is safe scratch. `_entry_ip` is a compile-time
		// constant (a jalr always terminates its TB), so the slot address is a baked immediate --
		// exactly the same technique shadow_edge2_cache already uses, 2 instructions, no new hash.
		if (unlikely(dbt::config::gbrind_hitrate_collect)) {
			auto &hr_slot = tcache::gbrind_hitrate_cache[tcache::gbrind_hitrate_hash(_entry_ip)];
			auto tmpH = asmjit::x86::r11;
			j.mov(tmpH.r64(), (uptr)&hr_slot.hit);
			j.inc(asmjit::x86::qword_ptr(tmpH.r64()));
		}

		FrameDestroy();
		if (jit_mode) {
			j.mov(tmp2.r64(), (uptr)tcache::cache_tb_exec_count.data());
		} else {
			j.mov(tmp2.r64(), asmjit::x86::Mem(R_STATE, offsetof(CPUState, cache_tb_exec_count)));
		}
		// j.mov(tmp2.r64(), asmjit::x86::ptr(tmp2.r64(), tmp0.r64(), 0, offsetof(tcache::BrindCaxwcheEntry, code)));
		// P1: same DC-1 undo on the gbrind-fastpath arrival counter (see Emit_Cache above).
		if ((!dbt::config::use_aot || dbt::config::p1_promote) && !dbt::config::not_freq &&
		    !dbt::config::qcg_freq_entry) {
			j.mov(tmp2.r64(), asmjit::x86::ptr(tmp2.r64(), tmp0.r64(), 0, offsetof(tcache::CacheTbExecCountEntry, tb), sizeof(u64)));
			// todo: this 8 is computed from the size of the flags to exec count, should be changed to another offsetof.
			if (unlikely(dbt::config::qcg_freq_sat)) {
				// SAT: same decision-sufficient cap on the indirect-dispatch fastpath
				auto skip_inc = j.newLabel();
				j.cmp(asmjit::x86::qword_ptr(tmp2.r64(), offsetof(TBlock, flags) + 8),
				      (int32_t)dbt::config::qcg_freq_sat_t);
				j.jae(skip_inc);
				j.inc(asmjit::x86::qword_ptr(tmp2.r64(), offsetof(TBlock, flags) + 8));
				j.bind(skip_inc);
			} else {
				j.inc(asmjit::x86::qword_ptr(tmp2.r64(), offsetof(TBlock, flags) + 8));
			}
		}

		if (unlikely(dbt::config::shadow_majority) && ins->shadow_track) {
			// A-line Design 3: per-TARGET Boyer-Moore majority vote, piggybacked on this ALREADY-
			// UNCONDITIONALLY-EXECUTED l1_brind_cache HIT path. Reuses `tmp0` (the hash*16 offset
			// already computed above for l1_brind_cache/cache_tb_exec_count -- no new hash). Only
			// one new base-address load (tmp3); everything else is plain memory ALU on that base,
			// no branches beyond the algorithm's own 3-way case, no function call.
			auto tmp3 = asmjit::x86::r15;
			static_assert(sizeof(tcache::MajorityVoteEntry) == 16);
			if (jit_mode) {
				j.mov(tmp3.r64(), (uptr)tcache::majority_cache.data());
			} else {
				j.mov(tmp3.r64(), asmjit::x86::Mem(R_STATE, offsetof(CPUState, majority_cache)));
			}
			// CORRECTNESS FIX (Codex audit, 2026-07-24): this slot is indexed by the SAME hash as
			// l1_brind_cache, whose OWN hit-check only proves l1_brind_cache's CURRENT tag matches
			// ptgt -- it says nothing about whether THIS table's slot was last written by a
			// DIFFERENT target that happens to hash to the same slot (a genuine l1hash collision,
			// e.g. any two indirect targets whose addresses agree mod 16MB, `L1_CACHE_BITS=22`).
			// The original version unconditionally overwrote target_gip and then applied the vote
			// update against whatever candidate_src/counter/candidate_hits happened to be sitting in
			// the slot -- silently mixing two logically distinct targets' vote streams whenever a
			// collision occurred. Fixed by checking target_gip FIRST: a mismatch (including the
			// initial all-zero state) means "this slot is not this target's own state," so the
			// dispatch is treated as a fresh first-touch (target_gip claimed, candidate/counter/hits
			// reset to this dispatch alone) before any vote arithmetic runs -- collisions can now only
			// ever cost an extra reset (never-wrong, matches the safety discipline already used
			// elsewhere in this cycle: capacity effects may cost accuracy/coverage, never correctness).
			// Verified via a deterministic collision witness (temporarily forced with a shrunk
			// L1_CACHE_BITS so witness_fdre.elf's Tdom/Tfiller1/Tfiller2/Tpoly_a/Tpoly_b addresses,
			// which are only 8-32 bytes apart, are guaranteed to alias) -- see
			// SINGLE_RUN_ECONOMICS.md's collision-witness section for the raw before/after slot dumps.
			auto mv_adopt = j.newLabel();
			auto mv_decrement = j.newLabel();
			auto mv_done = j.newLabel();
			auto mv_same_target = j.newLabel();
			j.cmp(asmjit::x86::dword_ptr(tmp3.r64(), tmp0.r64(), 0, offsetof(tcache::MajorityVoteEntry, target_gip)),
			      ptgt.r32());
			j.je(mv_same_target);
			// different target (or never-touched slot) now owns this hash bucket -- claim it fresh,
			// discarding whatever candidate/counter/hits belonged to the PREVIOUS occupant.
			j.mov(asmjit::x86::ptr(tmp3.r64(), tmp0.r64(), 0, offsetof(tcache::MajorityVoteEntry, target_gip), sizeof(u32)),
			      ptgt.r32());
			j.jmp(mv_adopt);
			j.bind(mv_same_target);
			// A-line Design 3b (Codex audit item 3) was ATTEMPTED here: skip the vote update once
			// candidate_hits*2 > target_exec_count already holds, deriving the stop condition from
			// the SAME safety certificate this cycle already uses (not a tuned sampling rate).
			// RETRACTED after honest measurement: the check itself (load candidate_hits, shift,
			// walk cache_tb_exec_count -> TBlock*, compare -- ~6 instructions incl. a SECOND
			// pointer chase not reused from anywhere else) costs as much as or more than the
			// ~4-5 instruction update it was meant to let some dispatches skip, so it added net
			// overhead on interpreter_bench (10.3s/6.7s baseline pre-attempt -> 10.95-10.99s
			// post-attempt, WORSE not better) instead of the hoped-for improvement -- a real,
			// measured negative result, not hidden. See SINGLE_RUN_ECONOMICS.md. A version that
			// reused an EXISTING pointer chase (e.g. tmp2's, when the cache_tb_exec_count-increment
			// block above actually ran) instead of doing its own might still be worth trying, but
			// was not achieved this cycle.
			j.cmp(asmjit::x86::dword_ptr(tmp3.r64(), tmp0.r64(), 0, offsetof(tcache::MajorityVoteEntry, counter)), 0);
			j.je(mv_adopt);
			j.cmp(asmjit::x86::dword_ptr(tmp3.r64(), tmp0.r64(), 0, offsetof(tcache::MajorityVoteEntry, candidate_src)),
			      (int32_t)_entry_ip);
			j.jne(mv_decrement);
			// hit: this dispatch's source IS the current candidate -- exact vote AND exact hits both grow.
			j.inc(asmjit::x86::dword_ptr(tmp3.r64(), tmp0.r64(), 0, offsetof(tcache::MajorityVoteEntry, counter)));
			j.inc(asmjit::x86::dword_ptr(tmp3.r64(), tmp0.r64(), 0, offsetof(tcache::MajorityVoteEntry, candidate_hits)));
			j.jmp(mv_done);
			j.bind(mv_decrement);
			// miss: cancel one vote (Boyer-Moore); candidate_hits UNCHANGED (candidate got no hit
			// this round) -- this is what keeps candidate_hits an exact, never-inflated lower bound.
			j.dec(asmjit::x86::dword_ptr(tmp3.r64(), tmp0.r64(), 0, offsetof(tcache::MajorityVoteEntry, counter)));
			j.jmp(mv_done);
			j.bind(mv_adopt);
			// counter reached 0 (on a PRIOR dispatch) -- this dispatch's source becomes the new
			// candidate, starting its own exact-hit count fresh at 1.
			j.mov(asmjit::x86::dword_ptr(tmp3.r64(), tmp0.r64(), 0, offsetof(tcache::MajorityVoteEntry, candidate_src)),
			      (int32_t)_entry_ip);
			j.mov(asmjit::x86::dword_ptr(tmp3.r64(), tmp0.r64(), 0, offsetof(tcache::MajorityVoteEntry, counter)), 1);
			j.mov(asmjit::x86::dword_ptr(tmp3.r64(), tmp0.r64(), 0, offsetof(tcache::MajorityVoteEntry, candidate_hits)), 1);
			j.bind(mv_done);
		}

		// Alias-entry multi-entry contract (--aot-link-alias-merge): this L1-cache fastpath jumps
		// directly to a resolved code pointer without ever touching state->ip -- correct for a
		// normal, single-entry target, but WRONG if the resolved code pointer is a
		// GlobalAlias-exposed secondary entry sharing an AOT worker's address, since that worker's
		// own entry switch reads state->ip to decide which internal block to route to. The AOT/LLVM
		// side already refreshes state->ip on every path that can reach a multi-entry function
		// (dbt/qmc/llvmgen/llvmgen.cpp); this QCG/JIT-tier emitter is a SEPARATE code generator
		// (asmjit, not LLVM) for the SAME dispatch operation and needed the identical fix. Gated on
		// the flag so the default (flag off) fastpath is completely unchanged -- one extra store,
		// only when the alias mechanism can possibly be in play.
		if (unlikely(dbt::config::aot_link_alias_merge)) {
			j.mov(asmjit::x86::ptr(R_STATE, offsetof(CPUState, ip), sizeof(u32)), ptgt.r32());
		}
		j.jmp(asmjit::x86::ptr(tmp1.r64(), tmp0.r64(), 0, offsetof(tcache::BrindCacheEntry, code),
				       sizeof(u64)));
	}

	j.bind(slowpath);

	// A-line Round 48 (--gbrind-hitrate-collect): per-source MISS counter, symmetric to the HIT
	// counter above. r11 is dead on arrival here (tmp0/tmp1's earlier values are irrelevant on this
	// path -- tmp0/rdi is about to be overwritten as the call argument on the very next line).
	if (unlikely(dbt::config::gbrind_hitrate_collect)) {
		auto &hr_slot = tcache::gbrind_hitrate_cache[tcache::gbrind_hitrate_hash(_entry_ip)];
		auto tmpH = asmjit::x86::r11;
		j.mov(tmpH.r64(), (uptr)&hr_slot.miss);
		j.inc(asmjit::x86::qword_ptr(tmpH.r64()));
	}

	j.mov(asmjit::x86::gpq(asmjit::x86::Gp::kIdDi), R_STATE);

	// Allow call in leaf procedure and setup frame in slowpath
	if (is_leaf) {
		j.push(asmjit::x86::rcx);
	}

	j.emit(asmjit::x86::Inst::kIdCall, make_stubcall_target(RuntimeStubId::id_brind));
	if (has_pending_ic) {
		// the call's return address (next byte after the call) keys the site's blob for the
		// slowpath's patch lookup
		ic_sites.push_back({pending_ic_blob_off, (u32)j.offset()});
		has_pending_ic = false;
	}

	if (is_leaf) {
		j.pop(asmjit::x86::rcx);
	} else {
		FrameDestroy();
	}
	j.jmp(asmjit::x86::rax);
}

// set size manually
static inline asmjit::x86::Mem make_vmem(qir::VOperand vbase)
{
	if constexpr (config::zero_membase) {
		if (likely(vbase.IsPGPR())) {
			return asmjit::x86::ptr(make_gpr(vbase));
		} else {
			return asmjit::x86::ptr(vbase.GetConst());
		}
	} else {
		if (likely(vbase.IsPGPR())) {
			return asmjit::x86::ptr(QEmit::R_MEMBASE, make_gpr(vbase));
		} else {
			return asmjit::x86::ptr(QEmit::R_MEMBASE, vbase.GetConst());
		}
	}
}

void QEmit::Emit_vmload(qir::InstVMLoad *ins)
{
	// j.emit(asmjit::x86::Inst::kIdCall, make_stubcall_target(RuntimeStubId::id_trace));
	auto &vrd = ins->o(0);
	auto &vbase = ins->i(0);
	auto sgn = ins->sgn;

	auto prd = make_gpr(vrd);
	auto mem = make_vmem(vbase);

	assert(vrd.GetType() == qir::VType::I32);
	switch (ins->sz) {
	case qir::VType::I8:
		mem.setSize(1);
		if (sgn == qir::VSign::U) {
			j.movzx(prd, mem);
		} else {
			j.movsx(prd, mem);
		}
		mem.addOffset(1);
		break;
	case qir::VType::I16:
		mem.setSize(2);
		if (sgn == qir::VSign::U) {
			j.movzx(prd, mem);
		} else {
			j.movsx(prd, mem);
		}
		mem.addOffset(2);
		break;
	case qir::VType::I32:
		mem.setSize(4);
		j.mov(prd, mem);
		mem.addOffset(4);
		break;
	default:
		unreachable("");
	};
}

void QEmit::Emit_vmstore(qir::InstVMStore *ins)
{
	// j.emit(asmjit::x86::Inst::kIdCall, make_stubcall_target(RuntimeStubId::id_trace));
	auto &vbase = ins->i(0);
	auto &vdata = ins->i(1);

	auto pdata = make_operand(vdata);
	auto mem = make_vmem(vbase);

	assert(ins->sgn == qir::VSign::U);
	mem.setSize(VTypeToSize(ins->sz));
	j.emit(asmjit::x86::Inst::kIdMov, mem, pdata);
	mem.addOffset(VTypeToSize(ins->sz));
}

void QEmit::Emit_vmload2(qir::InstVMLoad2 *ins)
{
	auto prd1 = make_gpr(ins->o(0));
	auto prd2 = make_gpr(ins->o(1));
	auto vbase = ins->i(0);

	auto mem = make_vmem(vbase);
	mem.setSize(8);
	j.movsd(asmjit::x86::xmm0, mem);
	j.movd(prd1, asmjit::x86::xmm0);
	j.pextrd(prd2, asmjit::x86::xmm0, 1);
}

void QEmit::Emit_vmload4(qir::InstVMLoad4 *ins)
{
	auto prd1 = make_gpr(ins->o(0));
	auto prd2 = make_gpr(ins->o(1));
	auto prd3 = make_gpr(ins->o(2));
	auto prd4 = make_gpr(ins->o(3));

	auto mem = make_vmem(ins->i(0));
	mem.setSize(16);
	j.movdqu(asmjit::x86::xmm0, mem);
	j.movd(prd1, asmjit::x86::xmm0);
	j.pextrd(prd2, asmjit::x86::xmm0, 1);
	j.pextrd(prd3, asmjit::x86::xmm0, 2);
	j.pextrd(prd4, asmjit::x86::xmm0, 3);
}

void QEmit::Emit_vmstore2(qir::InstVMStore2 *ins)
{
	auto &vbase = ins->i(0);
	auto &vdata1 = ins->i(1);
	auto &vdata2 = ins->i(2);

	auto pdata1 = make_gpr(vdata1);
	auto pdata2 = make_gpr(vdata2);
	auto mem = make_vmem(vbase);
	mem.setSize(8);
	j.movd(asmjit::x86::xmm0, pdata1);
	j.pinsrd(asmjit::x86::xmm0, pdata2, 1);
	j.movsd(mem, asmjit::x86::xmm0);
}

void QEmit::Emit_vmstore4(qir::InstVMStore4 *ins)
{
	auto &vbase = ins->i(0);
	auto &vdata1 = ins->i(1);
	auto &vdata2 = ins->i(2);
	auto &vdata3 = ins->i(3);
	auto &vdata4 = ins->i(4);

	auto pdata1 = make_gpr(vdata1);
	auto pdata2 = make_gpr(vdata2);
	auto pdata3 = make_gpr(vdata3);
	auto pdata4 = make_gpr(vdata4);
	auto mem = make_vmem(vbase);
	mem.setSize(16);
	j.movd(asmjit::x86::xmm0, pdata1);
	j.pinsrd(asmjit::x86::xmm0, pdata2, 1);
	j.pinsrd(asmjit::x86::xmm0, pdata3, 2);
	j.pinsrd(asmjit::x86::xmm0, pdata4, 3);
	j.movdqu(mem, asmjit::x86::xmm0);
}

// ---------------------------------------------------------------------------------------------
// RVV direct lowering: inline SSE2 for vadd.vv, with a runtime guard and a helper fallback.
//
// This is the ONE place in the RVV work where guest vector arithmetic becomes host SIMD inside
// JIT-EMITTED code rather than inside a C++ helper. It is deliberately narrow:
//
//   * The vtype is a translation-time constant (taken from a vsetvli in the same basic block),
//     so SEW, LMUL, EMUL, group legality and the chunk count are all decided at compile time
//     and no validation logic is duplicated into emitted assembly.
//   * The inline path handles ONLY vl == VLMAX with vstart == 0. Every other case -- a partial
//     tail, a different vtype at run time, a non-zero vstart -- branches to the helper, which
//     is the already-verified reference/chunked implementation. That is what keeps this small:
//     no emitted loop, no emitted tail handling, all offsets constant.
//   * Vector values never enter QIR's SSA world: they are read and written straight out of
//     CPUState::vec.vreg via the state register. Hence no QIR vector type and no register
//     allocator change. xmm0/xmm1 are fixed scratch, the same convention Emit_vmload4 uses.
//
// The guard is what makes it sound: even if this block were reached without executing the
// in-block vsetvli, the run-time vtype/vl would not match and the helper would run.
// R1A.3d. THE ONE PLACE THE RESEARCH HIT COUNTER IS EMITTED.
//
// `CPUState::rvv_direct_hits` is incremented by emitted code at the join of every typed frame --
// one `inc` per frame, on the TIMED fast path -- and until R1A.3d there was no way to build
// without it. R1A.3c therefore had to report that instrumentation as part of its measured delta.
//
// Routing all three fast-arm increments through one function is what makes "this build is
// counter-free" a property of a SINGLE decision. A per-site copy is a per-site chance to forget
// one, and forgetting one would leave a timing arm quietly carrying instrumentation.
//
// THE GUARD-MISS `rvv_direct_fallbacks` INCREMENTS ARE DELIBERATELY NOT ROUTED THROUGH HERE. They
// sit after the fallback label, so a guard-hit arm never executes them and they cost a timing arm
// nothing; keeping them unconditional is what lets a counter-free arm still assert
// `guard_fallbacks == 0` on every single invocation. Removing them would trade a real validity
// gate for no saving at all.
//
// Default TRUE (config.h), so every accepted pinned golden keeps its exact bytes.
void QEmit::EmitRvvHitCount()
{
	namespace x86 = asmjit::x86;
	if (!config::rvv_qcg_hit_counter)
		return;
	j.inc(x86::qword_ptr(R_STATE, (int32_t)offsetof(CPUState, rvv_direct_hits)));
}

// P7M-E. THE ONE PLACE THE PER-FRAME CENSUS INCREMENT IS EMITTED.
//
// PLACED AT THE FAST-ARM JOIN, immediately after `EmitRvvHitCount`, and that is the whole
// correctness argument: `rvv_typed_chunk_join` is reached only when the frame's guard PASSED, and
// the guard-miss arm binds `rvv_typed_chunk_fallback` and reaches `rvv_typed_chunk_done` without
// crossing this label. So `count` is executions of the frame's NATIVE body, never of its ordered
// helper arm -- which is exactly the population section 16 needs and the one `rvv_direct_fallbacks`
// already counts separately.
//
// WHY `rax` IS FREE HERE, rather than a saved/restored register. `begin` carries HAS_CALLS, so
// QRegAlloc placed a call boundary before the guard and no virtual register is assigned to a
// call-clobbered host register anywhere inside the frame (the comment on the fallback arm in
// `Emit_rvvtypedchunkend` states the same fact for the same reason). The guard emitted by
// `Emit_rvvtypedchunkbegin` already uses `eax` on its base-limit path on that basis, and the body
// emitters use `eax`/`edx` throughout. Nothing can be live in `rax` across this join, because the
// other arm reaching `rvv_typed_chunk_done` has just returned from helper calls.
//
// TWO INSTRUCTIONS, NOT ONE, and deliberately not folded into `R_STATE`: the slot lives in
// `rvvrun`'s translation-order arena, not in CPUState, so it has no R_STATE-relative displacement.
// Growing CPUState by a per-frame array instead would change a layout that is hashed
// (`rv32_cpu.h`'s `mix(offsetof(...))`) and is shared by every arm, armed or not. The cost is
// irrelevant because this is never enabled on a timed arm.
void QEmit::EmitRvvFrameCensusIncr()
{
	namespace x86 = asmjit::x86;
	if (!rvv_typed_chunk_census_slot)
		return;
	if (unlikely(!config::rvv_run_frame_census))
		Panic("qemit: frame-census slot present with the census switch off");
	j.mov(x86::rax, (uptr)rvv_typed_chunk_census_slot);
	j.inc(x86::qword_ptr(x86::rax));
}

// P2a. THE ONE PLACE EITHER ACTIVE-CHUNK CENSUS COUNTER IS ADVANCED.
//
// Two forms of the same two-instruction shape `EmitRvvFrameCensusIncr` and `EmitRvvGatherCensus`
// already use, and for the same stated reason: the counters live in .bss, not in CPUState, so they
// have no R_STATE-relative displacement and the address must be materialised. `add [rax], imm`
// rather than `inc` whenever the frame contributes more than one unit at once, because the join's
// contribution is a whole prefix and splitting it into N increments would put a per-unit cost on a
// path that has no per-unit structure.
//
// `n == 0` EMITS NOTHING, and that is load-bearing at the join: a FrameEpilogue-convention bounded
// frame has first_bounded_unit == 0, so every unit carries a bound and its always-executed prefix
// is empty. The available counter still gets its add; the executed counter is advanced entirely by
// the bounds themselves.
//
// WHY rax IS FREE AT BOTH CALL SITES, and not saved:
//
//   * At the join, for exactly the reason `EmitRvvFrameCensusIncr` states two functions above --
//     the frame's `begin` carries HAS_CALLS, so QRegAlloc released every global into its CPUState
//     slot before the guard and no virtual register is assigned to a call-clobbered host register
//     anywhere inside the frame. This call sits immediately after that function, which has just
//     written rax itself.
//   * After a bound, because a bound is inserted at a WORK-UNIT BOUNDARY (immediately before the
//     unit's own first node, which is its mask node when it has one and its anchor otherwise). No
//     frame-internal scratch is live across such a boundary: every body emitter that can open a
//     unit -- Emit_vchunkpartialalu, Emit_vchunknarrowshift, Emit_vchunkwiden, Emit_vchunkextend,
//     Emit_vchunkindex, Emit_vchunkfclass, Emit_vchunkftoi, Emit_vchunkitof, Emit_vchunkftof,
//     Emit_vchunkmaskset, Emit_vchunkfalu, Emit_vchunkfma -- WRITES rax/edx/rdi/rsi before reading
//     them (EmitRvvBodyMask and EmitRvvFpLaneMask are the first thing each does with a GPR), and
//     none reads rax on entry. The bound's own `cmp`/`jbe` already establishes that the flags are
//     dead across the same boundary, and `add`/`inc` writes nothing else.
void QEmit::EmitRvvActiveChunkCensusAdd(unsigned long long *counter, u32 n)
{
	namespace x86 = asmjit::x86;
	if (!config::rvv_qcg_active_chunk_census || n == 0)
		return;
	j.mov(x86::rax, (uint64_t)(uintptr_t)counter);
	if (n == 1)
		j.inc(x86::qword_ptr(x86::rax));
	else
		j.add(x86::qword_ptr(x86::rax), (int32_t)n);
}

void QEmit::Emit_rvvaddv(qir::InstRVVAddV *ins)
{
	if (ins->llvm_wide) {
		Panic("qcg: LLVM-wide vadd node reached the QCG backend");
	}
	namespace x86 = asmjit::x86;
	auto const vec_off = (int32_t)offsetof(CPUState, vec);
	auto const vreg_off = vec_off + (int32_t)offsetof(rv32::VectorState, vreg);
	auto const slot = (int32_t)rv32::VLEN_MAX_BYTES;

	auto fallback = j.newLabel();
	auto done = j.newLabel();

	// Guard: the architectural state must be exactly what translation assumed.
	j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vtype)),
	      (int32_t)ins->vtype);
	j.jne(fallback);
	j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vl)),
	      (int32_t)ins->vlmax);
	j.jne(fallback);
	j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vstart)), 0);
	j.jne(fallback);

	// Inline body: emul_regs * chunks_per_reg fully-unrolled 128-bit operations at constant
	// offsets. Chunk c of register r lives at vreg[base+r] + c*16.
	auto add_id = [&]() -> uint32_t {
		switch (ins->sew_bytes) {
		case 1:
			return x86::Inst::kIdPaddb;
		case 2:
			return x86::Inst::kIdPaddw;
		case 4:
			return x86::Inst::kIdPaddd;
		default:
			return x86::Inst::kIdPaddq;
		}
	}();
	for (unsigned r = 0; r < ins->emul_regs; ++r) {
		for (unsigned c = 0; c < ins->chunks_per_reg; ++c) {
			int32_t const co = (int32_t)(c * 16);
			j.movdqu(x86::xmm0, x86::ptr(R_STATE, vreg_off + (ins->vs2 + r) * slot + co, 16));
			j.movdqu(x86::xmm1, x86::ptr(R_STATE, vreg_off + (ins->vs1 + r) * slot + co, 16));
			j.emit(add_id, x86::xmm0, x86::xmm1);
			j.movdqu(x86::ptr(R_STATE, vreg_off + (ins->vd + r) * slot + co, 16), x86::xmm0);
		}
	}
	EmitRvvHitCount();
	j.jmp(done);

	// Fallback: the verified helper. Same sequence Emit_hcall produces.
	j.bind(fallback);
	j.inc(x86::qword_ptr(R_STATE, (int32_t)offsetof(CPUState, rvv_direct_fallbacks)));
	j.mov(x86::rdi, R_STATE);
	j.mov(x86::rsi, (uint64_t)ins->raw);
	j.emit(x86::Inst::kIdCall, make_stubcall_target(ins->stub));

	j.bind(done);
}

void QEmit::Emit_ccrfchunk(qir::InstCCRFChunk *ins)
{
	namespace x86 = asmjit::x86;
	using Kind = qir::InstCCRFChunk::Kind;
	if (ins->vlenb < 128 || ins->vlenb > rv32::VLEN_MAX_BYTES ||
	    (u32)ins->component * 64u + 64u > ins->vlenb)
		Panic("qemit: malformed CCRF component shape");
	auto const vec_off = (int32_t)offsetof(CPUState, vec);
	auto const vreg_off = vec_off + (int32_t)offsetof(rv32::VectorState, vreg);
	auto const slot = (int32_t)rv32::VLEN_MAX_BYTES;
	u32 const reg = (ins->raw >> 7) & 0x1fu;
	u32 const rs1 = (ins->raw >> 15) & 0x1fu;
	u32 const vs2 = (ins->raw >> 20) & 0x1fu;
	int32_t const component_off = (int32_t)ins->component * 64;
	bool const zmm = ins->host_width == qir::InstCCRFChunk::HostWidth::AVX512ZMM;

	if (ins->kind == Kind::WholeLoad || ins->kind == Kind::WholeStore) {
		u32 const nregs = ((ins->raw >> 29) & 7u) + 1u;
		// rax is allocator-fixed scratch. A prior cut used r10 and could overwrite a resident
		// duplicated scalar induction value, turning the component stream into a nonterminating loop.
		auto addr = x86::rax;
		j.mov(addr.r32(), x86::dword_ptr(R_STATE, (int32_t)offsetof(CPUState, gpr) + (int32_t)rs1 * 4));
		if (ins->kind == Kind::WholeLoad)
			j.add(addr, x86::qword_ptr(R_STATE, (int32_t)offsetof(CPUState, ccrf_read_base)));
		else
			j.add(addr, R_MEMBASE);
		for (u32 r = 0; r < nregs; ++r) {
			int32_t const mo = (int32_t)r * (int32_t)ins->vlenb + component_off;
			int32_t const so = vreg_off + (int32_t)(reg + r) * slot + component_off;
			if (zmm && ins->kind == Kind::WholeLoad) {
				j.vmovdqu64(x86::zmm0, x86::ptr(addr, mo, 64));
				j.vmovdqu64(x86::ptr(R_STATE, so, 64), x86::zmm0);
			} else if (zmm) {
				j.vmovdqu64(x86::zmm0, x86::ptr(R_STATE, so, 64));
				j.vmovdqu64(x86::ptr(addr, mo, 64), x86::zmm0);
			} else {
				// Explicitly functional only: this preserves T7m behavior on hosts without
				// AVX-512 and is never evidence for the host-width claim.
				for (u32 lane = 0; lane < 4; ++lane) {
					int32_t const lo = (int32_t)lane * 16;
					if (ins->kind == Kind::WholeLoad) {
						j.movdqu(x86::xmm0, x86::ptr(addr, mo + lo, 16));
						j.movdqu(x86::ptr(R_STATE, so + lo, 16), x86::xmm0);
					} else {
						j.movdqu(x86::xmm0, x86::ptr(R_STATE, so + lo, 16));
						j.movdqu(x86::ptr(addr, mo + lo, 16), x86::xmm0);
					}
				}
			}
		}
	} else if (ins->kind == Kind::MulVX || ins->kind == Kind::MaccVX) {
		int32_t const scalar = (int32_t)offsetof(CPUState, gpr) + (int32_t)rs1 * 4;
		if (zmm) {
			j.vpbroadcastd(x86::zmm1, x86::dword_ptr(R_STATE, scalar));
			j.vmovdqu64(x86::zmm0, x86::ptr(R_STATE, vreg_off + (int32_t)vs2 * slot + component_off, 64));
			j.vpmulld(x86::zmm0, x86::zmm0, x86::zmm1);
			if (ins->kind == Kind::MaccVX) {
				j.vmovdqu64(x86::zmm2, x86::ptr(R_STATE, vreg_off + (int32_t)reg * slot + component_off, 64));
				j.vpaddd(x86::zmm0, x86::zmm0, x86::zmm2);
			}
			j.vmovdqu64(x86::ptr(R_STATE, vreg_off + (int32_t)reg * slot + component_off, 64), x86::zmm0);
		} else {
			j.movd(x86::xmm1, x86::dword_ptr(R_STATE, scalar));
			j.pshufd(x86::xmm1, x86::xmm1, 0);
			for (u32 lane = 0; lane < 4; ++lane) {
				int32_t const co = component_off + (int32_t)lane * 16;
				j.movdqu(x86::xmm0, x86::ptr(R_STATE, vreg_off + (int32_t)vs2 * slot + co, 16));
				j.pmulld(x86::xmm0, x86::xmm1);
				if (ins->kind == Kind::MaccVX) {
					j.movdqu(x86::xmm2, x86::ptr(R_STATE, vreg_off + (int32_t)reg * slot + co, 16));
					j.paddd(x86::xmm0, x86::xmm2);
				}
				j.movdqu(x86::ptr(R_STATE, vreg_off + (int32_t)reg * slot + co, 16), x86::xmm0);
			}
		}
	} else {
		Panic("qemit: unsupported CCRF operation");
	}
	EmitRvvHitCount();
}

void QEmit::Emit_ccrfcompute(qir::InstCCRFComputeRegion *ins)
{
	namespace x86 = asmjit::x86;
	if (!ins->operations || !ins->operation_count || !ins->iterations || ins->vlenb != 128 ||
	    ins->component >= 2)
		Panic("qemit: malformed CCRF compute-region shape");
	auto const vreg_off = (int32_t)offsetof(CPUState, vec) +
		(int32_t)offsetof(rv32::VectorState, vreg);
	auto const slot = (int32_t)rv32::VLEN_MAX_BYTES;
	int32_t const component_off = (int32_t)ins->component * 64;

	// The certificate's live-in and live-out masks are derived from the raw stream. Keeping each
	// guest register in its same-numbered ZMM makes intermediate values register-resident across
	// every repeated member and makes the executed bytes straightforward to audit.
	for (u32 reg = 0; reg < 32; ++reg)
		if (ins->read_mask & (u32(1) << reg))
			j.vmovdqu64(x86::Zmm(reg), x86::ptr(R_STATE, vreg_off + (int32_t)reg * slot + component_off, 64));

	j.mov(x86::eax, ins->iterations);
	auto loop = j.newLabel();
	j.bind(loop);
	for (u32 i = 0; i < ins->operation_count; ++i) {
		u32 const raw = ins->operations[i];
		u32 const vd = (raw >> 7) & 31u, vs1 = (raw >> 15) & 31u, vs2 = (raw >> 20) & 31u;
		// Exact unmasked OPIVV vadd.vv only. This is deliberately duplicated at the final emitter
		// boundary so a malformed certificate cannot turn into executable code.
		if ((raw & 0x7fu) != 0x57u || ((raw >> 12) & 7u) != 0u ||
		    ((raw >> 26) & 0x3fu) != 0u || ((raw >> 25) & 1u) != 1u)
			Panic("qemit: unsupported CCRF compute operation");
		j.vpaddd(x86::Zmm(vd), x86::Zmm(vs2), x86::Zmm(vs1));
	}
	j.dec(x86::eax);
	j.jne(loop);
	for (u32 reg = 0; reg < 32; ++reg)
		if (ins->write_mask & (u32(1) << reg))
			j.vmovdqu64(x86::ptr(R_STATE, vreg_off + (int32_t)reg * slot + component_off, 64), x86::Zmm(reg));
	EmitRvvHitCount();
}

// ---------------------------------------------------------------------------------------------
// DIAGNOSTIC CONTROL ARM -- NOT THE METHOD.  See the block comment on InstRVVDiagChunkBegin in
// qir.h before citing anything measured from this path.
//
// The group is `rvvdiagchunkbegin`, one node per 512-bit host chunk, `rvvdiagchunkend`.  Relative
// to Emit_rvvaddv above it changes exactly two things: the chunk COUNT became a node count, and
// the access width became 512-bit EVEX instead of 128-bit SSE2.  It does not change the
// representation.  The nodes carry no operands, so:
//
//   * Every chunk still loads its sources from CPUState::vec and stores its result back, once per
//     guest instruction.  The memory round trip is the cost a real V512 QIR value would remove.
//   * `Zmm(ins->index)` is a HARDCODED register choice, not an allocation.  The allocator has no
//     vector register class, so nothing checks this against any other ZMM user, and the "chunks
//     are independent" property lives in this one line rather than in QIR.
//
// It is safe as written because ZMMs are ABI-volatile, hold no QIR value, and the whole group is
// a register-allocator call boundary.  It is not extensible: two ZMM users under this convention
// would silently clobber each other.
//
// Alignment: CPUState::vec.vreg is only 16-byte aligned, so the moves are `vmovdqu64`, never
// `vmovdqa64`. EVEX memory source operands carry no alignment requirement, so the add reads its
// second source straight from state memory.
//
// The guard, the counters and the fallback are the same structure Emit_rvvaddv uses, and for the
// same reason: even if this block were reached without executing the in-block vsetvli, the
// run-time vtype/vl/vstart would not match and the already-verified helper would run.
void QEmit::Emit_rvvdiagchunkbegin(qir::InstRVVDiagChunkBegin *ins)
{
	namespace x86 = asmjit::x86;
	if (unlikely(rvv_diag_chunk_open))
		Panic("rvv chunk group opened inside another group");

	auto const vec_off = (int32_t)offsetof(CPUState, vec);

	rvv_diag_chunk_fallback = j.newLabel();
	rvv_diag_chunk_done = j.newLabel();
	rvv_diag_chunk_open = true;
	rvv_diag_chunk_next_index = 0;

	// Guard: the architectural state must be exactly what translation assumed. LMUL=1 and the
	// unmasked form are translation-time facts (vtype below pins LMUL; the decoder only routes
	// vm=1 encodings to this opcode), so only vtype, vl and vstart need checking here.
	j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vtype)),
	      (int32_t)ins->vtype);
	j.jne(rvv_diag_chunk_fallback);
	j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vl)),
	      (int32_t)ins->vlmax);
	j.jne(rvv_diag_chunk_fallback);
	j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vstart)), 0);
	j.jne(rvv_diag_chunk_fallback);
}

void QEmit::Emit_rvvdiagchunkadd(qir::InstRVVDiagChunkAdd *ins)
{
	namespace x86 = asmjit::x86;
	if (unlikely(!rvv_diag_chunk_open))
		Panic("rvv chunk op outside a chunk group");
	if (unlikely(ins->index != rvv_diag_chunk_next_index))
		Panic("rvv chunk ops out of order");
	rvv_diag_chunk_next_index++;

	auto const vreg_off =
	    (int32_t)offsetof(CPUState, vec) + (int32_t)offsetof(rv32::VectorState, vreg);
	auto const slot = (int32_t)rv32::VLEN_MAX_BYTES;
	auto const co = (int32_t)ins->index * 64;

	// Chunk i is hardcoded to zmm<i>. This is a fixed assignment made here in the emitter, NOT a
	// register allocation and NOT a QIR value: no other emitter may use a ZMM under the same
	// convention, and no pass can see or reason about this choice.
	auto const acc = x86::Zmm(ins->index);

	auto add_id = [&]() -> uint32_t {
		switch (ins->sew_bytes) {
		case 1:
			return x86::Inst::kIdVpaddb; // AVX512_BW
		case 2:
			return x86::Inst::kIdVpaddw; // AVX512_BW
		case 4:
			return x86::Inst::kIdVpaddd; // AVX512_F
		default:
			return x86::Inst::kIdVpaddq; // AVX512_F
		}
	}();

	j.vmovdqu64(acc, x86::ptr(R_STATE, vreg_off + ins->vs2 * slot + co, 64));
	j.emit(add_id, acc, acc, x86::ptr(R_STATE, vreg_off + ins->vs1 * slot + co, 64));
	j.vmovdqu64(x86::ptr(R_STATE, vreg_off + ins->vd * slot + co, 64), acc);
}

void QEmit::Emit_rvvdiagchunkend(qir::InstRVVDiagChunkEnd *ins)
{
	namespace x86 = asmjit::x86;
	if (unlikely(!rvv_diag_chunk_open))
		Panic("rvv chunk group end without begin");
	if (unlikely(rvv_diag_chunk_next_index == 0))
		Panic("rvv chunk group with no chunks");

	EmitRvvHitCount();
	j.jmp(rvv_diag_chunk_done);

	// Fallback: the verified helper, reached from the guard in Emit_rvvdiagchunkbegin. The register
	// allocator spilled call-clobbered registers before that guard (qra.cpp), so this path is
	// covered even though it branches over the chunk ops.
	j.bind(rvv_diag_chunk_fallback);
	j.inc(x86::qword_ptr(R_STATE, (int32_t)offsetof(CPUState, rvv_direct_fallbacks)));
	j.mov(x86::rdi, R_STATE);
	j.mov(x86::rsi, (uint64_t)ins->raw);
	j.emit(x86::Inst::kIdCall, make_stubcall_target(ins->stub));

	j.bind(rvv_diag_chunk_done);
	rvv_diag_chunk_open = false;
	rvv_diag_chunk_next_index = 0;
}

// ---------------------------------------------------------------------------------------------
// TYPED chunk group.  Same guard/counter/fallback structure as the diagnostic arm above and for
// the same reason, but what sits between `begin` and `end` is now typed V512 QIR values rather
// than opaque nodes, so the emitter picks no register.
//
// The one extra job here is the invariant from qir.h: everything between the guard and the
// fallback label is branched over when the guard fails, so nothing may be emitted there except
// the typed chunk ops themselves.  `TypedChunkAccount` is called by each typed emitter and
// Emit_mov Panics while a group is open, which is what turns a future allocator change from a
// silent fallback-path miscompile into a loud translation failure.
void QEmit::Emit_rvvtypedchunkbegin(qir::InstRVVTypedChunkBegin *ins)
{
	namespace x86 = asmjit::x86;
	if (unlikely(rvv_typed_chunk_open))
		Panic("rvv typed chunk group opened inside another group");
	if (unlikely(rvv_diag_chunk_open))
		Panic("rvv typed chunk group opened inside a diagnostic group");

	auto const vec_off = (int32_t)offsetof(CPUState, vec);

	rvv_typed_chunk_fallback = j.newLabel();
	rvv_typed_chunk_done = j.newLabel();
	rvv_typed_chunk_partial = j.newLabel();
	rvv_typed_chunk_join = j.newLabel();
	rvv_typed_chunk_body_done = j.newLabel(); // S1-1
	rvv_typed_chunk_bound_open = false;
	rvv_typed_chunk_has_partial =
	    ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeVlOrPartialVstart ||
	    ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeIntegerTwoArm ||
	    ins->guard_kind ==
		qir::InstRVVTypedChunkBegin::GuardKind::VTypeVlOrPartialVstartBaseLimit;
	rvv_typed_chunk_open = true;
	rvv_typed_chunk_expected = ins->n_typed;
	rvv_typed_chunk_seen = 0;
	rvv_typed_chunk_members = ins->n_members;
	rvv_typed_chunk_component_major = ins->body_component_major; // C4e
	rvv_typed_chunk_census_slot = ins->frame_census_slot; // P7M-E; nullptr unless armed
	rvv_typed_chunk_fp_masks = 0; // A12
	// G11-A. Derived from the node's own guard kind by the shared predicate in qir.h -- the same
	// one RvvEmitFpSharedMasks consults -- so the translator's decision not to build shared lane
	// masks and this decision not to emit a lane mask cannot disagree about which frames are
	// admitted. If they ever do, Emit_vchunkmaskset below turns it into a translation failure.
	rvv_typed_chunk_full_vl =
	    dbt::config::rvv_qcg_full_vl_fast_body &&
	    qir::InstRVVTypedChunkBegin::GuardProvesFullVl(ins->guard_kind);
	rvv_body_mask_known_vl = qir::InstRVVTypedChunkBegin::GuardProvesFullVl(ins->guard_kind)
	    ? ins->vlmax : 0;
	// S1-3. Same shape and the same reason as the line above: whether this frame's guard leaves
	// `vec.vl` bounded by `vlmax` -- and therefore whether `vec.vl` IS this frame's live element
	// count -- is decided once, in qir.h, and read here rather than re-derived from the kind list
	// below. Unconditional on any switch: it states what the guard proves, not what we do with it.
	rvv_typed_chunk_vl_guarded =
	    qir::InstRVVTypedChunkBegin::GuardBoundsVlByVlmax(ins->guard_kind);

	// Guard: the architectural state must be exactly what translation assumed. WHICH state that
	// is depends on the opcode, and the node says which -- see InstRVVTypedChunkBegin::GuardKind.
	if (ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VlenbVstart ||
	    ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VlenbRestartable ||
	    ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VlenbVstartBaseLimit) {
		// Native-2, vtype-INDEPENDENT transfers. A whole-register load/store moves whole
		// registers irrespective of SEW, LMUL and vl, and is valid even under vill, so vtype
		// and vl are not preconditions and are deliberately not read. What the frame DOES
		// depend on is the width it was compiled for: the translator turned config::vlen_bits
		// into a chunk count and a set of displacements, and `vlenb` is the architectural
		// register that states the executing VLEN. vstart is checked for the same reason every
		// other frame checks it -- a resumed partial transfer is not what this straight-line
		// body performs, so it fails closed to the helper that implements it.
		j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vlenb)),
		      (int32_t)ins->vlenb);
		j.jne(rvv_typed_chunk_fallback);
		if(ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VlenbRestartable)
			return;
		j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vstart)), 0);
		j.jne(rvv_typed_chunk_fallback);
		// A14: the whole-register frame's base-range test, with the opcode's own transfer
		// length folded into base_limit by the translator (nregs * VLEN/8, not vl).
		if (ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VlenbVstartBaseLimit) {
			if (unlikely((size_t)ins->base_state_offs + sizeof(u32) > sizeof(CPUState)))
				Panic("qemit: base-limit guard offset lies outside CPUState");
			j.mov(x86::eax, x86::dword_ptr(R_STATE, (int32_t)ins->base_state_offs));
			j.cmp(x86::eax, (int32_t)(u32)ins->base_limit);
			j.ja(rvv_typed_chunk_fallback);
		}
		return;
	}
	// The accepted eight routes. SEW, LMUL and the unmasked form are translation-time facts --
	// vtype pins SEW and LMUL, and rv32_decode.h routes only vm=1 encodings to those opcodes --
	// so only vtype, vl and vstart are runtime state and only they are checked here.
	auto const dynamic_falu = ins->guard_kind ==
		qir::InstRVVTypedChunkBegin::GuardKind::VTypeE32OrE64M2PartialVlVstartFrmRNE;
	if (dynamic_falu) {
		auto vtype_ok = j.newLabel();
		// e32/e64,m2,ta,ma: the complete two-vtype T7R envelope.
		j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vtype)), 0xd1);
		j.je(vtype_ok);
		j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vtype)), 0xd9);
		j.jne(rvv_typed_chunk_fallback);
		j.bind(vtype_ok);
	} else {
		j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vtype)),
		      (int32_t)ins->vtype);
		j.jne(rvv_typed_chunk_fallback);
	}
	if (ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeInteger ||
	    ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeFpAnyRM ||
	    ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeFpAnyRMNoRestart ||
	    ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeIntegerTwoArm ||
	    ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeIntegerNoRestart) {
		j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vl)),
		      (int32_t)ins->vlmax);
		j.ja(rvv_typed_chunk_fallback);
		if(ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeFpAnyRM ||
		   ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeFpAnyRMNoRestart){
			j.mov(x86::eax,x86::dword_ptr(R_STATE,offsetof(CPUState,fpu)+offsetof(rv32::FPUState,fcsr)));
			j.shr(x86::eax,5);j.and_(x86::eax,7);j.cmp(x86::eax,4);j.ja(rvv_typed_chunk_fallback);
		}
		if (ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeIntegerNoRestart ||
		    ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeFpAnyRMNoRestart) {
			j.cmp(x86::dword_ptr(R_STATE,vec_off+offsetof(rv32::VectorState,vstart)),0);
			j.jne(rvv_typed_chunk_fallback);
		}
		if (ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeIntegerTwoArm) {
			j.jne(rvv_typed_chunk_partial);
			j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vstart)), 0);
			j.jne(rvv_typed_chunk_partial);
		}
		return;
	}
	if (dynamic_falu) {
		// ins->vlmax is e32 VLMAX. e64 has half as many lanes and is checked separately.
		auto check_e64 = j.newLabel(), vl_ok = j.newLabel();
		j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vtype)), 0xd1);
		j.jne(check_e64);
		j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vl)),
		      (int32_t)ins->vlmax);
		j.ja(rvv_typed_chunk_fallback);
		j.jmp(vl_ok);
		j.bind(check_e64);
		j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vl)),
		      (int32_t)(ins->vlmax / 2));
		j.ja(rvv_typed_chunk_fallback);
		j.bind(vl_ok);
	} else if (rvv_typed_chunk_has_partial) {
		// A3: vstart first (it is a frame-wide precondition of BOTH arms), then the three-way
		// split on vl: == VLMAX falls through into the unchanged full body, > VLMAX is a
		// helper (fail-closed), < VLMAX is the partial arm.
		if (ins->guard_kind ==
		    qir::InstRVVTypedChunkBegin::GuardKind::VTypeVlOrPartialVstartBaseLimit) {
			if (unlikely((size_t)ins->base_state_offs + sizeof(u32) > sizeof(CPUState)))
				Panic("qemit: partial-memory base guard offset lies outside CPUState");
			j.mov(x86::eax,
			      x86::dword_ptr(R_STATE, (int32_t)ins->base_state_offs));
			j.cmp(x86::eax, (int32_t)(u32)ins->base_limit);
			j.ja(rvv_typed_chunk_fallback);
		}
		j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vstart)), 0);
		j.jne(rvv_typed_chunk_fallback);
		j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vl)),
		      (int32_t)ins->vlmax);
		j.ja(rvv_typed_chunk_fallback);
		j.jne(rvv_typed_chunk_partial);
		return;
	} else {
		j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vl)),
		      (int32_t)ins->vlmax);
		// A13: VTypeVlVstartBaseLimit takes the `jne` arm too (vl == VLMAX exactly); its
		// extra base-range test is emitted after the vstart check below.
		// P7M-A: `VTypeVlVstartFrmRNE` deliberately takes the `jne` arm. It is the kind a run
		// containing BOTH an integer and an FP member gets, and the integer members' host
		// chunk operations are unmasked and full width, so `vl == VLMAX` is exactly what they
		// need; only the frm test below is added.
		if (ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypePartialVlVstartFrmRNE ||
		    ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeFpNoRestart ||
		    ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypePartialVlVstartFrmHost)
			j.ja(rvv_typed_chunk_fallback);
		else
			j.jne(rvv_typed_chunk_fallback);
	}
	if (ins->guard_kind != qir::InstRVVTypedChunkBegin::GuardKind::VTypePartialVlVstartFrmHost) {
		j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vstart)), 0);
		j.jne(rvv_typed_chunk_fallback);
	}
	// A13. THE BASE-RANGE GUARD. The body reads the base GPR from CPUState (HAS_CALLS synced every
	// global before the guard) and forms [R_MEMBASE + zext(base) + c*chunk]; that window stays
	// inside the 4 GiB guest reservation iff base <= 2^32 - VLEN/8 = base_limit. Unsigned
	// compare, fail closed to the helper. eax is the frame-internal scratch (R_SCRATCH).
	if (ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartBaseLimit) {
		if (unlikely((size_t)ins->base_state_offs + sizeof(u32) > sizeof(CPUState)))
			Panic("qemit: base-limit guard offset lies outside CPUState");
		j.mov(x86::eax, x86::dword_ptr(R_STATE, (int32_t)ins->base_state_offs));
		j.cmp(x86::eax, (int32_t)(u32)ins->base_limit);
		j.ja(rvv_typed_chunk_fallback);
	}
	if (ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNEBaseMask ||
	    ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartBaseMask) {
		for (u32 r = 1; r < 32; ++r) {
			if (!(ins->base_state_mask & (1u << r)))
				continue;
			u32 const offs = (u32)(offsetof(CPUState, gpr) + 4u * r);
			j.mov(x86::eax, x86::dword_ptr(R_STATE, (int32_t)offs));
			j.cmp(x86::eax, (int32_t)(u32)ins->base_limit);
			j.ja(rvv_typed_chunk_fallback);
		}
	}
	if (ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypePartialVlVstartFrmRNE ||
	    ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNE ||
	    ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartFrmRNEBaseMask ||
	    dynamic_falu) {
		auto const fcsr_off = (int32_t)offsetof(CPUState, fpu) +
			(int32_t)offsetof(rv32::FPUState, fcsr);
		j.test(x86::dword_ptr(R_STATE, fcsr_off), 0xe0);
		j.jnz(rvv_typed_chunk_fallback);
	}
	if (ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypePartialVlVstartFrmHost ||
	    ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypeFpNoRestart) {
		j.mov(x86::eax, x86::dword_ptr(R_STATE, (int32_t)offsetof(CPUState, fpu) +
			(int32_t)offsetof(rv32::FPUState, fcsr)));
		j.and_(x86::eax, 0xe0); j.cmp(x86::eax, 3u << 5);
		j.ja(rvv_typed_chunk_fallback); // RMM and reserved modes are not MXCSR modes.
	}
	// A4. vl == 0 on a partial-vl FP frame takes the helper: RVV 1.0 requires that no
	// destination element is updated when vl == 0 (all lanes are tail AND nothing may be
	// written), and the masked lane ops above would still write their tail policy. The helper
	// returns without touching vd. One compare on the partial-capable FP frames only.
	if (ins->guard_kind == qir::InstRVVTypedChunkBegin::GuardKind::VTypePartialVlVstartFrmRNE ||
	    dynamic_falu) {
		j.cmp(x86::dword_ptr(R_STATE, vec_off + (int32_t)offsetof(rv32::VectorState, vl)), 0);
		j.je(rvv_typed_chunk_fallback);
	}
}

// R1A.3b. The join, the hit counter and the ORDERED fallback arm.
//
// For `n_members == 1` every instruction below is the one this function emitted before R1A.3b, in
// the same order -- the run loop degenerates to the single call, and `EmitRunMemberIp` emits
// nothing. That is what makes every accepted single-instruction frame byte-identical, and it is
// checked against a pinned pre-R1A.3b disassembly golden by the focused test.
//
// For a run the two arms differ in exactly the way R1A.2b section 4 requires:
//
//   fast arm      ... typed body ... ; state->ip = pc_{m-1} ; hits++    ; jmp done
//   fallback arm  state->ip = pc_0 ; call stub_0 ; state->ip = pc_1 ; call stub_1 ; ...
//
// WHY THE FALLBACK PCs ARE MANDATORY: the helpers take `(state, raw)` and read their trap PC out of
// `state->ip` (rv32_interp.cpp's stub wrapper does `u32 gip = state->ip;`). Members 1..m-1 have no
// PreSideeff of their own -- the translator consumed them into this frame -- so without these
// stores helper `i` would report member 0's PC on a trap.
//
// WHY THE FAST ARM WRITES ONLY pc_{m-1}: R1A.2b section 1 established that a guard hit is exactly
// the complement of the helper's own trap predicate and the emitted fast body contains no trap
// source, and section 3 established that rvdbt delivers no guest asynchronous signal, so no guest-
// observable consumer can sample `state->ip` inside the run. What both arms MUST agree on is the
// value left at the join, because a region exit or `gbr` after this frame may read it -- hence this
// one store of the LAST member's PC. `MayTrap` is not removed from any opcode; a guard MISS still
// runs helpers that can trap, with correct per-member PCs.
//
// WHY BACKEND-NATIVE STORES AND NOT QIR: PreSideeff writes `state->ip` with `qb.Create_mov`, and
// Emit_mov Panics while a group is open (qir.h). These stores are emitted here, arm by arm, exactly
// as `mov rdi/rsi` and the two counters already are. That is legal against the register allocator's
// model for the same reason Emit_vchunkload's indirect form is: `rvvtypedchunkbegin` carries
// HAS_CALLS, so QRegAlloc::CallOp(true) spilled and RELEASED every global -- including `ip` -- into
// its CPUState slot immediately before the guard, so no physical register holds a copy that these
// stores could make stale.
void QEmit::EmitRunMemberIp(u32 pc)
{
	namespace x86 = asmjit::x86;
	// Nothing at all for a single-member frame: its PreSideeff already stored this PC.
	if (rvv_typed_chunk_members <= 1)
		return;
	if (unlikely(pc == qir::RVVRunMember::PC_UNUSED))
		Panic("rvv run member reached the emitter without a guest pc");
	j.mov(x86::dword_ptr(R_STATE, (int32_t)offsetof(CPUState, ip)), (int32_t)pc);
}

void QEmit::EmitRvvRunScalarRaw(u32 raw, bool count_body_op)
{
	namespace x86 = asmjit::x86;
	u32 const opcode = raw & 0x7fu;
	u32 const funct3 = (raw >> 12) & 7u;
	u32 const funct7 = raw >> 25;
	u32 const rd = (raw >> 7) & 31u;
	u32 const rs1 = (raw >> 15) & 31u;
	u32 const rs2 = (raw >> 20) & 31u;
	bool const addi = opcode == 0x13u && funct3 == 0u;
	bool const add = opcode == 0x33u && funct3 == 0u && funct7 == 0u;
	bool const sub = opcode == 0x33u && funct3 == 0u && funct7 == 0x20u;
	if (unlikely(!addi && !add && !sub))
		Panic("qemit: unsupported scalar member inside RVV run");
	if (rd) {
		if (rs1)
			j.mov(x86::eax, x86::dword_ptr(R_STATE,
				(int32_t)(offsetof(CPUState, gpr) + rs1 * sizeof(u32))));
		else
			j.xor_(x86::eax, x86::eax);
		if (addi) {
			i32 const imm = (i32)raw >> 20;
			if (imm)
				j.add(x86::eax, imm);
		} else if (rs2) {
			auto const rhs = x86::dword_ptr(
			    R_STATE, (int32_t)(offsetof(CPUState, gpr) + rs2 * sizeof(u32)));
			if (add)
				j.add(x86::eax, rhs);
			else
				j.sub(x86::eax, rhs);
		}
		j.mov(x86::dword_ptr(R_STATE,
			(int32_t)(offsetof(CPUState, gpr) + rd * sizeof(u32))), x86::eax);
	}
	if (count_body_op)
		rvv_typed_chunk_seen++;
}

void QEmit::Emit_rvvrunscalar(qir::InstRVVRunScalar *ins)
{
	if (unlikely(!rvv_typed_chunk_open))
		Panic("qemit: scalar RVV-run member outside a run frame");
	EmitRvvRunScalarRaw(ins->raw, true);
}

void QEmit::Emit_rvvtypedchunkend(qir::InstRVVTypedChunkEnd *ins)
{
	namespace x86 = asmjit::x86;
	if (unlikely(rvv_instruction_work_last))
		Panic("rvv instruction work scope crosses its frame boundary");
	if (unlikely(!rvv_typed_chunk_open))
		Panic("rvv typed chunk group end without begin");
	if (unlikely(rvv_typed_chunk_seen != rvv_typed_chunk_expected))
		Panic("rvv typed chunk group body is not the shape begin declared");
	if (unlikely(rvv_typed_chunk_members != ins->n_members))
		Panic("rvv typed chunk group end covers a different run than begin declared");
	// A3: a frame that declared a partial arm must have emitted its marker, or the guard's
	// `jne partial` would target an unbound label; and an arm the guard cannot reach is dead.
	if (unlikely(rvv_typed_chunk_has_partial != rvv_typed_chunk_partial_seen))
		Panic("rvv typed chunk group partial arm does not match its guard kind");
	// S1-3. WHO CLEARS vec.vstart, CHECKED BEFORE ANYTHING IS EMITTED.
	//
	// An FP frame binds the body-done label in Emit_rvvqcgfpend, inside the MXCSR bracket, and
	// reaches here with `rvv_typed_chunk_bound_open` already cleared -- so for every FP frame this
	// whole block is inert and not one byte moves. An INTEGER frame has no such epilogue: its
	// `vstart = 0` is written by the LAST chunk's own node (InstVChunkPartialAlu::finish_instruction
	// and its siblings), which an early exit would jump straight past. A bounded integer frame
	// therefore clears `finish_instruction` on every chunk and moves that single write HERE.
	//
	// `ins->frame_clears_vstart` is the translator's half of that decision and
	// `rvv_typed_chunk_bound_open` is QEmit's. They are two statements of one fact, so a
	// disagreement is refused rather than emitted: the silent form is a frame in which NEITHER side
	// writes vstart, and a residual vstart does not corrupt this instruction -- it makes the NEXT
	// vector instruction start at a wrong prestart index, arbitrarily far away.
	if (unlikely(ins->frame_clears_vstart != rvv_typed_chunk_bound_open))
		Panic("rvv active-vl bound: frame and body disagree about who clears vstart");
	if (rvv_typed_chunk_bound_open) {
		// A partial arm reaches `join` from OUTSIDE the bounded body, so the vstart write
		// below would sit on a path no bound guards and the partial body would clear vstart
		// twice or not at all depending on where it jumped. No route builds both today.
		if (unlikely(rvv_typed_chunk_has_partial))
			Panic("rvv active-vl bound in a frame with a partial arm");
		// AFTER the label (the early exit must execute the write) and BEFORE the join (the ip
		// write and the counters live there and must see a settled vstart). Deliberately NOT
		// at the fallback label, which is emitted past `jmp done` below: landing there would
		// run the ordered helpers on top of chunks the body already stored.
		j.bind(rvv_typed_chunk_body_done);
		rvv_typed_chunk_bound_open = false;
		j.mov(x86::dword_ptr(R_STATE, (int32_t)offsetof(CPUState, vec) +
					      (int32_t)offsetof(rv32::VectorState, vstart)),
		      0);
	}

	// Fast arm exit: leave the LAST member's PC, so both arms reach the join with the same
	// architectural `ip`. No-op for a single-member frame. A3: the partial arm jumps here too.
	j.bind(rvv_typed_chunk_join);
	EmitRunMemberIp(ins->members[ins->n_members - 1].pc);
	EmitRvvHitCount();
	EmitRvvFrameCensusIncr();
	// P2a. THE NATIVE-FRAME JOIN CONTRIBUTION, and the reason the helper arm contributes nothing.
	//
	// This label is reached only when the frame's guard PASSED; the guard-miss arm binds
	// `rvv_typed_chunk_fallback` BELOW the `jmp done` that follows and never crosses these adds.
	// That is the same argument `EmitRvvFrameCensusIncr` makes one line above, and it is what makes
	// these counts a population of NATIVE body executions rather than of frame encounters.
	//
	// An early-exited bounded body reaches here too (its `jbe` targets `rvv_typed_chunk_body_done`,
	// bound just above), so `chunks_available` is credited on every native execution whatever the
	// live `vec.vl` was -- which is exactly what "the units this frame WOULD execute with suffix
	// skipping off" has to mean.
	//
	// BOTH IMMEDIATES COME OFF THE END NODE, where `rvvfinal::CloseFrame` put the geometry it had
	// already derived from the emitted body and checked against the producer. They are zero for
	// every frame the common close classified ineligible, so no run, memory, whole-register,
	// reduction or cross-lane frame appears in either count.
	EmitRvvActiveChunkCensusAdd(&rv32::g_rvv_chunks_available, ins->census_units);
	EmitRvvActiveChunkCensusAdd(&rv32::g_rvv_chunks_executed, ins->census_prefix_units);
	j.jmp(rvv_typed_chunk_done);

	// Fallback: the already-verified helpers, in GUEST ORDER, reached from the guard in begin.
	// The call boundary was placed before that guard (HAS_CALLS on begin -> QRegAlloc::CallOp),
	// so every call-clobbered register and every dirty global was dealt with on both paths, and
	// the helpers communicate with each other only through CPUState -- which is why helper `i`
	// sees exactly what instruction `i-1` left, with no merged value anywhere.
	j.bind(rvv_typed_chunk_fallback);
	j.inc(x86::qword_ptr(R_STATE, (int32_t)offsetof(CPUState, rvv_direct_fallbacks)));
	if (ins->whole_regbytes) {
		// The packed copy's vstart/range restrictions do not require a C++ call.
		// Reuse the native element loop, including RV32 wrapping and restart publication.
		// Only an actual VLEN mismatch still needs the runtime-sized helper.
		auto helper = j.newLabel();
		j.cmp(x86::dword_ptr(R_STATE, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vlenb)),
		      ins->whole_regbytes);
		j.jne(helper);
		bool const store = ins->stub == RuntimeStubId::id_rv32_vsNr;
		u8 const eew = store ? 1 : (u8)(1u << (rv32::eew_log2_from_width((ins->raw >> 12) & 7) - 3));
		qir::InstVMemory memory((ins->raw >> 7) & 31, (ins->raw >> 15) & 31,
			(ins->raw >> 29) + 1, eew, eew, 4, ins->whole_regbytes, store, false);
		Emit_vmemorynative(&memory);
		j.jmp(rvv_typed_chunk_done);
		j.bind(helper);
	}
	for (u8 i = 0; i < ins->n_members; ++i) {
		EmitRunMemberIp(ins->members[i].pc);
		if (ins->members[i].scalar_passthrough) {
			EmitRvvRunScalarRaw(ins->members[i].raw, false);
			continue;
		}
		j.mov(x86::rdi, R_STATE);
		j.mov(x86::rsi, (uint64_t)ins->members[i].raw);
		j.emit(x86::Inst::kIdCall, make_stubcall_target(ins->members[i].stub));
	}

	j.bind(rvv_typed_chunk_done);
	rvv_typed_chunk_open = false;
	rvv_typed_chunk_expected = 0;
	rvv_typed_chunk_seen = 0;
	rvv_typed_chunk_members = 0;
	rvv_typed_chunk_component_major = false; // C4e: nothing outlives the frame
	rvv_typed_chunk_has_partial = false;
	rvv_typed_chunk_partial_seen = false;
	rvv_typed_chunk_full_vl = false; // G11-A: nothing outlives the frame
	rvv_body_mask_known_vl = 0;
	rvv_typed_chunk_bound_open = false; // S1-1: same rule
	rvv_typed_chunk_vl_guarded = false; // S1-3: same rule
}


// Typed V512 chunk ops.  Contrast with Emit_rvvdiagchunkadd directly above: there the ZMM number
// comes from the node's `index` and the data comes from a fixed CPUState offset, so the emitter
// decides where every value lives.  Here every register number is read out of an operand that
// QRegAlloc assigned, and the address is an ordinary QIR value in a GPR (or a constant).  The
// emitter picks nothing.  These three functions therefore contain no register literal at all --
// that absence is the property the phase is trying to establish, so keep it.
// M2C: any of the three host vector widths, but it must be an ALLOCATED physical register -- the
// width itself is then read back out of the operand's type by make_vpr.
static inline void assert_pvpr(qir::VOperand opr)
{
	if (unlikely(!opr.IsPVPR() || !qir::IsVectorVType(opr.GetType()))) {
		Panic("qemit: typed chunk operand is not an allocated vector register");
	}
}

// A3. The boundary between the full-vl body and the partial-vl arm: end the full body by jumping
// to the frame's join (ip write + hit count live there, once, for both arms), then bind the label
// the guard jumps to for vl < VLMAX. Not a typed body op.
void QEmit::Emit_rvvtypedchunkpartial(qir::InstRVVTypedChunkPartial *)
{
	if (unlikely(!rvv_typed_chunk_open))
		Panic("rvv partial arm outside a typed chunk group");
	if (unlikely(rvv_typed_chunk_partial_seen))
		Panic("rvv typed chunk group has two partial arms");
	rvv_typed_chunk_partial_seen = true;
	// G11-A. Everything after this label is reached because the guard's vl test FAILED, so the
	// full-VL fact the frame proved on the fall-through does not hold here. No guard kind that
	// GuardProvesFullVl admits has a partial arm today, which is why this is a clear rather than
	// a Panic: it keeps the invariant true by construction if one ever does.
	rvv_typed_chunk_full_vl = false;
	rvv_body_mask_known_vl = 0;
	j.jmp(rvv_typed_chunk_join);
	j.bind(rvv_typed_chunk_partial);
}

// A3. k(1+chunk) := lanes [0, clamp(vl - chunk*lanes, 0, lanes)). The SAME prologue
// Emit_vchunkfalu computes inline per lane op, hoisted into one node per chunk per frame. eax/edx
// are the frame-internal scratch registers that emitter already uses; no allocated value lives in
// them across a typed body op (the enclosing begin carries HAS_CALLS).
void QEmit::EmitRvvFpLaneMask(u32 lanes, u32 base)
{
	namespace x86 = asmjit::x86;
	auto const vl_off = (int32_t)offsetof(CPUState, vec) + (int32_t)offsetof(rv32::VectorState, vl);
	auto have = j.newLabel(), mask_ready = j.newLabel();
	j.mov(x86::eax, x86::dword_ptr(R_STATE, vl_off));
	if (rvv_fused_active_mask) {
		// This is the original suffix predicate, now consuming the VL load
		// already required by the lane mask. Prestart handling below is unchanged.
		j.cmp(x86::eax, base);
		j.jbe(rvv_typed_chunk_body_done);
		if (base) j.sub(x86::eax, base);
	} else if (base) {
		j.cmp(x86::eax, base); j.ja(have); j.xor_(x86::eax, x86::eax);
		j.jmp(mask_ready); j.bind(have); j.sub(x86::eax, base);
	}
	j.cmp(x86::eax, lanes); j.mov(x86::edx, lanes); j.cmova(x86::eax, x86::edx);
	j.bind(mask_ready); j.mov(x86::edx, -1); j.bzhi(x86::edx, x86::edx, x86::eax);
	// Remove prestart lanes. Clamp before BZHI: its count uses only the low byte.
	auto done = j.newLabel(), empty = j.newLabel();
	j.mov(x86::eax, x86::dword_ptr(R_STATE, (int32_t)offsetof(CPUState, vec) +
		(int32_t)offsetof(rv32::VectorState, vstart)));
	j.cmp(x86::eax, base); j.jbe(done);
	if (base) j.sub(x86::eax, base);
	j.cmp(x86::eax, lanes); j.jae(empty);
	j.bzhi(x86::eax, x86::edx, x86::eax); j.xor_(x86::edx, x86::eax);
	j.jmp(done); j.bind(empty); j.xor_(x86::edx, x86::edx); j.bind(done);
}

void QEmit::Emit_vchunkmaskset(qir::InstVChunkMaskSet *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	// G11-A. THE COHERENCE CHECK BETWEEN THE TWO PASSES. A frame this node lands in holds a
	// resident k(1+chunk) that its lane ops consume; a frame the full-VL predicate admits emits
	// its lane ops UNMASKED. A frame cannot be both, so RvvEmitFpSharedMasks refuses to build
	// these nodes for an admitted frame. Reaching here anyway means the translator and QEmit
	// disagree about GuardProvesFullVl, and the emitted result would be a lane op that claims to
	// be unmasked while a mask register was written for it -- fail the translation instead.
	if (unlikely(rvv_typed_chunk_full_vl))
		Panic("rvv shared lane mask inside a frame whose guard proved full VL");
	EmitRvvFpLaneMask(ins->lanes, ins->chunk * ins->lanes);
	u8 const slot = ins->chunk % qir::RVV_FP_SHARED_MASK_MAX_CHUNKS;
	j.kmovw(x86::KReg(1 + slot), x86::edx);
	// Recycling a slot invalidates its previous owner; stale consumers fail closed.
	for (unsigned c = slot; c < 64; c += qir::RVV_FP_SHARED_MASK_MAX_CHUNKS)
		rvv_typed_chunk_fp_masks &= ~(u64{1} << c);
	rvv_typed_chunk_fp_masks |= u64{1} << ins->chunk;
	if (rvv_fused_active_mask)
		EmitRvvActiveChunkCensusAdd(&rv32::g_rvv_chunks_executed, 1);
}

void QEmit::EmitActiveMaskPair(qir::InstVChunkActive *bound, qir::InstVChunkMaskSet *mask)
{
	if (rvv_fused_active_mask || bound->chunk != mask->chunk ||
	    bound->element_base != (u32)mask->chunk * mask->lanes)
		Panic("incompatible active-suffix and lane-mask pair");
	rvv_fused_active_mask = true;
	Emit_vchunkactive(bound);
	Emit_vchunkmaskset(mask);
	rvv_fused_active_mask = false;
}

// S1-1. THE ACTIVE-VL BOUND. Two instructions and no state: compare the LIVE vec.vl against this
// chunk's first element index and leave the body when the chunk is entirely tail.
//
//     cmp   dword ptr [R_STATE + vec.vl], <chunk * lanes>
//     jbe   body_done
//
// UNSIGNED, because vec.vl is a u32 and every comparison the frame's own guard makes against it is
// unsigned too (Emit_rvvtypedchunkbegin's `ja`/`jne` against vlmax). `jbe` rather than `jb` is the
// whole point: `vl == base` means the chunk's FIRST element is already at the tail boundary, so the
// chunk is inactive. At chunk 0 the immediate is 0 and the test degenerates to `vl == 0` -- the
// architecturally empty vector, handled by the same instruction rather than by a special case.
//
// The immediate is DERIVED, never a literal: `element_base` comes from the node and is the same
// element index Emit_vchunkfalu, Emit_vstatechunkstore and Emit_vchunkpartialalu hand to their lane
// masks. There is no VLEN, no AVL and no workload constant anywhere in this function.
//
// The four Panics are the frame contract, not defensive noise.
//
//   * Outside a frame there is no label to jump to.
//   * Inside a frame whose guard already proved `vl == VLMAX && vstart == 0` (G11-A) the comparison
//     is a translation-time constant `false`, so a bound there means the translator and QEmit
//     disagree about GuardProvesFullVl -- the same disagreement Emit_vchunkmaskset refuses just
//     above, and refused here for the same reason rather than silently emitting dead code.
//   * S1-3: inside a frame whose guard does NOT bound `vec.vl` by `vlmax` the compare would be
//     against a register the frame never validated. That is the `Vlenb*` whole-register family,
//     whose EVL is `nregs * VLEN / EEW` and is independent of `vl` and of `vtype` entirely -- an
//     early exit there is wrong, not merely unprofitable.
//   * S1-3: inside a multi-member run frame the early exit would jump past LATER MEMBERS, which are
//     different guest instructions with no per-member exit of their own.
void QEmit::Emit_vchunkactive(qir::InstVChunkActive *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	if (unlikely(!rvv_typed_chunk_open))
		Panic("rvv active-vl bound outside a typed chunk group");
	if (unlikely(rvv_typed_chunk_full_vl))
		Panic("rvv active-vl bound inside a frame whose guard proved full VL");
	if (unlikely(!rvv_typed_chunk_vl_guarded))
		Panic("rvv active-vl bound inside a frame whose guard does not bound vec.vl");
	// C4e. A MULTI-MEMBER FRAME MAY CARRY A BOUND ONLY WHEN ITS BODY IS COMPONENT-MAJOR.
	// The original refusal read `members != 1`, which is the property "the early exit cannot skip
	// a later member's live work" stated through the only frame shape that had it. A
	// component-major run body has the same property for a different and stated reason: a run has
	// ONE vtype, so every member shares one element -> work-unit map, and in that order the units
	// after this one are inactive for EVERY member at once. The claim is the node's
	// (`InstRVVTypedChunkBegin::body_component_major`) and rvvfinal::CloseFrame refuses a frame
	// whose emitted units do not match it, so this test is the emitter's half of one fact.
	if (unlikely(rvv_typed_chunk_members != 1 && !rvv_typed_chunk_component_major))
		Panic("rvv active-vl bound inside a member-major multi-member run frame");
	if (rvv_fused_active_mask || rvv_fused_body_mask) {
		// The paired mask emits the actual comparison and reached-unit census.
		rvv_typed_chunk_bound_open = true;
		return;
	}
	auto const vl_off =
	    (int32_t)offsetof(CPUState, vec) + (int32_t)offsetof(rv32::VectorState, vl);
	j.cmp(x86::dword_ptr(R_STATE, vl_off), (int32_t)ins->element_base);
	j.jbe(rvv_typed_chunk_body_done);
	// P2a. ONE REACHED WORK UNIT, on the bound's FALL-THROUGH path only -- after the `jbe`, so an
	// early exit is not credited with the unit it just skipped, and before the unit's own first
	// node, which is the next thing emitted. The frame's unbounded prefix is credited once at the
	// join instead; the two together are `chunks_executed`.
	//
	// NO ELIGIBILITY TEST HERE, and none is needed: `rvvfinal::CloseFrame` Panics on an ineligible
	// frame that carries a bound ("an ineligible frame carries an active-vl bound"), so every frame
	// that reaches this function has a non-zero `census_units` on its end node and will contribute
	// its available count at the join. A bound without a matching join contribution is therefore a
	// translation failure, not a skewed ratio.
	EmitRvvActiveChunkCensusAdd(&rv32::g_rvv_chunks_executed, 1);
	rvv_typed_chunk_bound_open = true;
}

// A3-fix. The bounded partial-arm member. ONLY the two reserved scratch vectors (VPR_FIXED = {0,1},
// never allocated; the CCRF and vx emitters in this file already use them as frame-internal
// scratch) and the frame's k(1+chunk). The width is the node's own chunk width, so the same node
// is xmm/ymm/zmm. Every instruction is EVEX; the masked store `vmovdqu32 [rd]{k}` writes the
// active dword lanes only and leaves the tail bytes of the CPUState window untouched.
void QEmit::EmitRvvBodyMask(u32 lanes, u32 base, bool masked)
{
	namespace x86 = asmjit::x86;
	if (lanes == 0 || lanes > 64) Panic("qemit: invalid body mask width");
	u32 const vo = offsetof(CPUState, vec);
	bool const fused = rvv_fused_body_mask;
	if (fused && (base != rvv_fused_body_base || !rvv_typed_chunk_open))
		Panic("body-mask fusion changed the suffix predicate");
	if (rvv_body_mask_known_vl) {
		if (fused) Panic("full-VL body unexpectedly has a suffix bound");
		u32 const n = base >= rvv_body_mask_known_vl ? 0 : std::min(lanes, rvv_body_mask_known_vl - base);
		j.mov(x86::rdi, n == 64 ? ~u64(0) : (u64(1) << n) - 1);
		if (masked) {
			u32 const mo = vo + offsetof(rv32::VectorState, vreg) + base / 8;
			j.mov(x86::rax, x86::qword_ptr(R_STATE, mo));
			if (base % 8) j.shr(x86::rax, base % 8);
			j.and_(x86::rdi, x86::rax);
		}
		return;
	}
	auto prefix = [&](u32 off, x86::Gp out) {
		auto empty = j.newLabel(), ready = j.newLabel();
		j.mov(x86::eax, x86::dword_ptr(R_STATE, off));
		bool const suffix = fused && off == vo + offsetof(rv32::VectorState, vl);
		j.cmp(x86::eax, base); j.jbe(suffix ? rvv_typed_chunk_body_done : empty);
		if (base) j.sub(x86::eax, base);
		j.cmp(x86::eax, lanes); j.mov(x86::edx, lanes); j.cmova(x86::eax, x86::edx);
		j.mov(out, uint64_t(-1)); j.bzhi(out, out, x86::rax);
		if (!suffix) {
			j.jmp(ready); j.bind(empty); j.xor_(out, out); j.bind(ready);
		}
	};
	prefix(vo + offsetof(rv32::VectorState, vl), x86::rdi);
	prefix(vo + offsetof(rv32::VectorState, vstart), x86::rsi);
	j.not_(x86::rsi); j.and_(x86::rdi, x86::rsi);
	if (masked) {
		u32 const mo = vo + offsetof(rv32::VectorState, vreg) + base / 8;
		j.mov(x86::rax, x86::qword_ptr(R_STATE, mo));
		if (base % 8) j.shr(x86::rax, base % 8);
		j.and_(x86::rdi, x86::rax);
	}
	if (fused) {
		EmitRvvActiveChunkCensusAdd(&rv32::g_rvv_chunks_executed, 1);
		rvv_fused_body_mask = false;
	}
}

void QEmit::BeginBodyMaskPair(qir::InstVChunkActive *bound)
{
	if (rvv_fused_body_mask || rvv_fused_active_mask)
		Panic("nested body-mask fusion");
	rvv_fused_body_mask = true;
	rvv_fused_body_base = bound->element_base;
	Emit_vchunkactive(bound);
}

void QEmit::EndBodyMaskPair()
{
	if (rvv_fused_body_mask)
		Panic("fused suffix bound had no consuming body mask");
}

void QEmit::Emit_vchunkextend(qir::InstVChunkExtend *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	u32 const input_bytes = ins->bytes * ins->src_sew / ins->dst_sew;
	if (ins->rd + ins->bytes > sizeof(CPUState) || ins->rs2 + input_bytes > sizeof(CPUState))
		Panic("qemit: extension window outside CPUState");
	EmitRvvBodyMask(ins->bytes / ins->dst_sew, ins->base, ins->masked);
	j.kmovq(x86::k1, x86::rdi);
	u32 id;
	if (ins->src_sew == 1) {
		if (ins->dst_sew == 2) id = ins->sign ? x86::Inst::kIdVpmovsxbw : x86::Inst::kIdVpmovzxbw;
		else if (ins->dst_sew == 4) id = ins->sign ? x86::Inst::kIdVpmovsxbd : x86::Inst::kIdVpmovzxbd;
		else id = ins->sign ? x86::Inst::kIdVpmovsxbq : x86::Inst::kIdVpmovzxbq;
	} else if (ins->src_sew == 2) {
		if (ins->dst_sew == 4) id = ins->sign ? x86::Inst::kIdVpmovsxwd : x86::Inst::kIdVpmovzxwd;
		else id = ins->sign ? x86::Inst::kIdVpmovsxwq : x86::Inst::kIdVpmovzxwq;
	} else id = ins->sign ? x86::Inst::kIdVpmovsxdq : x86::Inst::kIdVpmovzxdq;
	x86::Vec const tmp = ins->bytes == 16 ? x86::Vec(x86::xmm0) : ins->bytes == 32 ? x86::Vec(x86::ymm0) : x86::Vec(x86::zmm0);
	EvexOnly(j); j.emit(id, tmp, x86::ptr(R_STATE, ins->rs2, input_bytes));
	EvexOnly(j); j.k(x86::k1).emit(ins->dst_sew == 2 ? x86::Inst::kIdVmovdqu16 :
		ins->dst_sew == 4 ? x86::Inst::kIdVmovdqu32 : x86::Inst::kIdVmovdqu64,
		x86::ptr(R_STATE, ins->rd, ins->bytes), tmp);
	if (ins->finish)
		j.mov(x86::dword_ptr(R_STATE, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart)), 0);
}

void QEmit::Emit_vchunkwiden(qir::InstVChunkWiden *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	using N = qir::InstVChunkWiden;
	u32 const ds = 2 * ins->sew, bytes = ins->bytes;
	if (ins->rd + bytes > sizeof(CPUState) || ins->rs2 + (ins->wide2 ? bytes : bytes / 2) > sizeof(CPUState) ||
	    ins->rs1 + (ins->scalar ? 4 : bytes / 2) > sizeof(CPUState))
		Panic("qemit: widening window outside CPUState");
	EmitRvvBodyMask(bytes / ds, ins->base, ins->masked);
	j.kmovq(x86::k1, x86::rdi);
	x86::Vec const a = bytes == 16 ? x86::Vec(x86::xmm0) : bytes == 32 ? x86::Vec(x86::ymm0) : x86::Vec(x86::zmm0);
	x86::Vec const b = bytes == 16 ? x86::Vec(x86::xmm1) : bytes == 32 ? x86::Vec(x86::ymm1) : x86::Vec(x86::zmm1);
	auto extend = [&](x86::Vec const &v, u32 off, bool sign) {
		u32 id = ins->sew == 1 ? (sign ? x86::Inst::kIdVpmovsxbw : x86::Inst::kIdVpmovzxbw) :
			ins->sew == 2 ? (sign ? x86::Inst::kIdVpmovsxwd : x86::Inst::kIdVpmovzxwd) :
			(sign ? x86::Inst::kIdVpmovsxdq : x86::Inst::kIdVpmovzxdq);
		EvexOnly(j); j.emit(id, v, x86::ptr(R_STATE, off, bytes / 2));
	};
	if (ins->wide2) { EvexOnly(j); j.vmovdqu64(a, x86::ptr(R_STATE, ins->rs2, bytes)); }
	else extend(a, ins->rs2, ins->sign2);
	if (ins->scalar) {
		if (ins->zero) j.xor_(x86::eax, x86::eax);
		else j.mov(x86::eax, x86::dword_ptr(R_STATE, ins->rs1));
		if (ins->sign1) {
			if (ins->sew == 1) j.movsx(x86::rax, x86::al);
			else if (ins->sew == 2) j.movsx(x86::rax, x86::ax);
			else j.movsxd(x86::rax, x86::eax);
		} else if (ins->sew < 4) j.and_(x86::eax, ins->sew == 1 ? 0xff : 0xffff);
		j.vmovq(x86::xmm1, x86::rax);
		EvexOnly(j); j.emit(ds == 2 ? x86::Inst::kIdVpbroadcastw : ds == 4 ? x86::Inst::kIdVpbroadcastd :
			x86::Inst::kIdVpbroadcastq, b, x86::xmm1);
	} else extend(b, ins->rs1, ins->sign1);
	u32 id;
	if (ins->op >= N::Mul) id = ds == 2 ? x86::Inst::kIdVpmullw : ds == 4 ? x86::Inst::kIdVpmulld : x86::Inst::kIdVpmullq;
	else if (ins->op == N::Sub) id = ds == 2 ? x86::Inst::kIdVpsubw : ds == 4 ? x86::Inst::kIdVpsubd : x86::Inst::kIdVpsubq;
	else id = ds == 2 ? x86::Inst::kIdVpaddw : ds == 4 ? x86::Inst::kIdVpaddd : x86::Inst::kIdVpaddq;
	EvexOnly(j); j.emit(id, a, a, b);
	if (ins->op == N::Macc) {
		EvexOnly(j); j.emit(ds == 2 ? x86::Inst::kIdVpaddw : ds == 4 ? x86::Inst::kIdVpaddd : x86::Inst::kIdVpaddq,
			a, a, x86::ptr(R_STATE, ins->rd, bytes));
	}
	EvexOnly(j); j.k(x86::k1).emit(ds == 2 ? x86::Inst::kIdVmovdqu16 : ds == 4 ? x86::Inst::kIdVmovdqu32 :
		x86::Inst::kIdVmovdqu64, x86::ptr(R_STATE, ins->rd, bytes), a);
	if (ins->finish)
		j.mov(x86::dword_ptr(R_STATE, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart)), 0);
}

void QEmit::Emit_vchunknarrowshift(qir::InstVChunkNarrowShift *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	u32 const ss = ins->sew * 2, bytes = ins->bytes;
	if (ins->rd + bytes / 2 > sizeof(CPUState) || ins->rs2 + bytes > sizeof(CPUState) ||
	    ins->rs1 + (ins->src == 0 ? bytes / 2 : 4) > sizeof(CPUState))
		Panic("qemit: narrowing shift window outside CPUState");
	EmitRvvBodyMask(bytes / ss, ins->base, ins->masked);
	j.kmovq(x86::k1, x86::rdi);
	x86::Vec const a = bytes == 16 ? x86::Vec(x86::xmm0) : bytes == 32 ? x86::Vec(x86::ymm0) : x86::Vec(x86::zmm0);
	x86::Vec const b = bytes == 16 ? x86::Vec(x86::xmm1) : bytes == 32 ? x86::Vec(x86::ymm1) : x86::Vec(x86::zmm1);
	EvexOnly(j); j.vmovdqu64(a, x86::ptr(R_STATE, ins->rs2, bytes));
	if (ins->src == 0) {
		EvexOnly(j); j.emit(ss == 2 ? x86::Inst::kIdVpmovzxbw : ss == 4 ? x86::Inst::kIdVpmovzxwd :
			x86::Inst::kIdVpmovzxdq, b, x86::ptr(R_STATE, ins->rs1, bytes / 2));
		// RVV truncates shift counts modulo the wide EEW; x86 saturates excessive counts.
		u32 const n = ss * 8 - (ss == 2 ? 4 : ss == 4 ? 5 : 6);
		EvexOnly(j); j.emit(ss == 2 ? x86::Inst::kIdVpsllw : ss == 4 ? x86::Inst::kIdVpslld : x86::Inst::kIdVpsllq,b,b,n);
		EvexOnly(j); j.emit(ss == 2 ? x86::Inst::kIdVpsrlw : ss == 4 ? x86::Inst::kIdVpsrld : x86::Inst::kIdVpsrlq,b,b,n);
	} else {
		if (ins->src == 1) { j.mov(x86::eax,x86::dword_ptr(R_STATE,ins->rs1)); j.and_(x86::eax,ss*8-1); }
		else j.mov(x86::eax,ins->imm & (ss*8-1));
		j.vmovd(x86::xmm1,x86::eax);
		EvexOnly(j); j.emit(ss == 2 ? x86::Inst::kIdVpbroadcastw : ss == 4 ? x86::Inst::kIdVpbroadcastd :
			x86::Inst::kIdVpbroadcastq,b,x86::xmm1);
	}
	u32 const id = ss == 2 ? (ins->arith ? x86::Inst::kIdVpsravw : x86::Inst::kIdVpsrlvw) :
		ss == 4 ? (ins->arith ? x86::Inst::kIdVpsravd : x86::Inst::kIdVpsrlvd) :
		(ins->arith ? x86::Inst::kIdVpsravq : x86::Inst::kIdVpsrlvq);
	EvexOnly(j); j.emit(id,a,a,b);
	EvexOnly(j); j.k(x86::k1).emit(ss == 2 ? x86::Inst::kIdVpmovwb : ss == 4 ? x86::Inst::kIdVpmovdw :
		x86::Inst::kIdVpmovqd,x86::ptr(R_STATE,ins->rd,bytes/2),a);
	if (ins->finish)
		j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)),0);
}

void QEmit::Emit_vchunkftoi(qir::InstVChunkFToI *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	u32 const sb=ins->bytes/ins->sew*ins->src_sew;
	if (ins->rd + ins->bytes > sizeof(CPUState) || ins->rs + sb > sizeof(CPUState))
		Panic("qemit: float-to-integer chunk outside CPUState");
	auto vec = [&](u32 n,u32 bytes) -> x86::Vec { return bytes == 64 ? x86::Vec(x86::zmm(n)) :
		bytes == 32 ? x86::Vec(x86::ymm(n)) : x86::Vec(x86::xmm(n)); };
	if(ins->sew==2){
		auto out=vec(0,sb),tmp=vec(1,sb);
		EmitRvvBodyMask(ins->bytes/2,ins->base,ins->masked);j.kmovq(x86::k1,x86::rdi);
		j.sub(x86::rsp,16);j.stmxcsr(x86::dword_ptr(x86::rsp));
		u32 op=ins->is_signed?(ins->rtz?x86::Inst::kIdVcvttps2dq:x86::Inst::kIdVcvtps2dq):
			(ins->rtz?x86::Inst::kIdVcvttps2udq:x86::Inst::kIdVcvtps2udq);
		EvexOnly(j);j.k(x86::k1).z().emit(op,out,x86::ptr(R_STATE,ins->rs,sb));
		auto broadcast=[&](u32 value){j.mov(x86::eax,value);j.vpbroadcastd(tmp,x86::eax);};
		if(ins->is_signed){
			broadcast(0xffff8000u);j.vpcmpd(x86::k2,out,tmp,5);
			broadcast(32767);j.vpcmpd(x86::k3,out,tmp,2);j.kandw(x86::k2,x86::k2,x86::k3);
		}else{broadcast(65535);j.vpcmpud(x86::k2,out,tmp,2);}
		j.kandw(x86::k2,x86::k2,x86::k1);
		// The host conversion is 32-bit, but RVV saturates to 16 bits. NX from a lane
		// invalid at 16 bits must not escape. Reconstruct NV/NX per active lane instead.
		EvexOnly(j);j.k(x86::k2).z().emit(ins->is_signed?x86::Inst::kIdVcvtdq2ps:x86::Inst::kIdVcvtudq2ps,tmp,out);
		j.k(x86::k2).vcmpps(x86::k3,tmp,x86::ptr(R_STATE,ins->rs,sb),4);
		j.kandnw(x86::k4,x86::k2,x86::k1);
		j.kmovw(x86::eax,x86::k3);j.test(x86::eax,x86::eax);j.setne(x86::dl);j.movzx(x86::edx,x86::dl);j.shl(x86::edx,5);
		j.kmovw(x86::eax,x86::k4);j.test(x86::eax,x86::eax);j.setne(x86::al);j.movzx(x86::eax,x86::al);j.or_(x86::edx,x86::eax);
		j.or_(x86::edx,x86::dword_ptr(x86::rsp));j.mov(x86::dword_ptr(x86::rsp,4),x86::edx);
		j.ldmxcsr(x86::dword_ptr(x86::rsp,4));j.add(x86::rsp,16);
		j.vmovdqu32(tmp,x86::ptr(R_STATE,ins->rs,sb));j.vpmovd2m(x86::k5,tmp);
		j.k(x86::k1).vcmpps(x86::k6,tmp,tmp,3);j.knotw(x86::k5,x86::k5);j.korw(x86::k5,x86::k5,x86::k6);
		j.kandw(x86::k5,x86::k5,x86::k4);j.kandnw(x86::k6,x86::k5,x86::k4);
		broadcast(ins->is_signed?32767:65535);j.k(x86::k5).vmovdqu32(out,tmp);
		broadcast(ins->is_signed?0xffff8000u:0);j.k(x86::k6).vmovdqu32(out,tmp);
		EvexOnly(j);j.k(x86::k1).vpmovdw(x86::ptr(R_STATE,ins->rd,ins->bytes),out);
		return;
	}
	auto out = vec(0,ins->bytes), in = vec(1,sb), tmp=vec(1,ins->bytes);
	EmitRvvBodyMask(ins->bytes / ins->sew, ins->base, ins->masked);
	j.kmovq(x86::k1, x86::rdi);
	if(sb==8)j.vmovq(x86::xmm1,x86::qword_ptr(R_STATE,ins->rs));
	else j.vmovdqu64(in, x86::ptr(R_STATE, ins->rs, sb));
	u32 op;
	if (ins->src_sew==4 && ins->sew==8) op=ins->is_signed?
		(ins->rtz?x86::Inst::kIdVcvttps2qq:x86::Inst::kIdVcvtps2qq):
		(ins->rtz?x86::Inst::kIdVcvttps2uqq:x86::Inst::kIdVcvtps2uqq);
	else if (ins->src_sew==8 && ins->sew==4) op=ins->is_signed?
		(ins->rtz?x86::Inst::kIdVcvttpd2dq:x86::Inst::kIdVcvtpd2dq):
		(ins->rtz?x86::Inst::kIdVcvttpd2udq:x86::Inst::kIdVcvtpd2udq);
	else if (ins->sew == 4) op = ins->is_signed ?
		(ins->rtz ? x86::Inst::kIdVcvttps2dq : x86::Inst::kIdVcvtps2dq) :
		(ins->rtz ? x86::Inst::kIdVcvttps2udq : x86::Inst::kIdVcvtps2udq);
	else op = ins->is_signed ?
		(ins->rtz ? x86::Inst::kIdVcvttpd2qq : x86::Inst::kIdVcvtpd2qq) :
		(ins->rtz ? x86::Inst::kIdVcvttpd2uqq : x86::Inst::kIdVcvtpd2uqq);
	EvexOnly(j); j.k(x86::k1).z().emit(op, out, in);
	if (ins->src_sew == 4) {
		j.vpmovd2m(x86::k2, in);
		j.k(x86::k1).vcmpps(x86::k3, in, in, 3);
	} else {
		j.vpmovq2m(x86::k2, in);
		j.k(x86::k1).vcmppd(x86::k3, in, in, 3);
	}
	auto broadcast = [&](u64 bits) {
		j.mov(x86::rax, bits);
		if (ins->sew == 4) j.vpbroadcastd(tmp, x86::eax);
		else j.vpbroadcastq(tmp, x86::rax);
	};
	u64 const sign = u64(1) << (ins->sew * 8 - 1);
	broadcast(ins->is_signed ? sign : ~u64(0));
	if (ins->sew == 4) j.vpcmpud(x86::k4, out, tmp, 0);
	else j.vpcmpuq(x86::k4, out, tmp, 0);
	// x86 returns an indefinite value on NV; RVV saturates by sign, with all NaNs positive.
	if (ins->is_signed) {
		j.knotw(x86::k2, x86::k2); j.korw(x86::k2, x86::k2, x86::k3);
		j.kandw(x86::k4, x86::k4, x86::k2); broadcast(sign - 1);
	} else {
		j.kandnw(x86::k2, x86::k3, x86::k2);
		j.kandw(x86::k4, x86::k4, x86::k2); j.vpxord(tmp, tmp, tmp);
	}
	if (ins->sew == 4) {
		j.k(x86::k4).vmovdqu32(out, tmp);
		j.k(x86::k1).vmovdqu32(x86::ptr(R_STATE, ins->rd), out);
	} else {
		j.k(x86::k4).vmovdqu64(out, tmp);
		j.k(x86::k1).vmovdqu64(x86::ptr(R_STATE, ins->rd), out);
	}
}

void QEmit::Emit_vchunkitof(qir::InstVChunkIToF *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	if (ins->rd + ins->bytes > sizeof(CPUState) || ins->rs + ins->bytes/ins->sew*ins->src_sew > sizeof(CPUState))
		Panic("qemit: integer-to-float chunk outside CPUState");
	x86::Vec out = ins->bytes == 64 ? x86::Vec(x86::zmm0) :
		ins->bytes == 32 ? x86::Vec(x86::ymm0) : x86::Vec(x86::xmm0);
	u32 const sb=ins->bytes/ins->sew*ins->src_sew;
	EmitRvvBodyMask(ins->bytes / ins->sew, ins->base, ins->masked);
	j.kmovq(x86::k1, x86::rdi);
	u32 const op = ins->src_sew==4&&ins->sew==8 ?
		(ins->is_signed?x86::Inst::kIdVcvtdq2pd:x86::Inst::kIdVcvtudq2pd) :
		ins->src_sew==8&&ins->sew==4 ?
		(ins->is_signed?x86::Inst::kIdVcvtqq2ps:x86::Inst::kIdVcvtuqq2ps) : ins->sew == 4 ?
		(ins->is_signed ? x86::Inst::kIdVcvtdq2ps : x86::Inst::kIdVcvtudq2ps) :
		(ins->is_signed ? x86::Inst::kIdVcvtqq2pd : x86::Inst::kIdVcvtuqq2pd);
	// Mask the conversion itself: inactive large integers must not contribute NX.
	if(ins->src_sew==2){
		x86::Vec tmp=ins->bytes==64?x86::Vec(x86::zmm1):ins->bytes==32?x86::Vec(x86::ymm1):x86::Vec(x86::xmm1);
		j.emit(ins->is_signed?x86::Inst::kIdVpmovsxwd:x86::Inst::kIdVpmovzxwd,tmp,x86::ptr(R_STATE,ins->rs,sb));
		EvexOnly(j);j.k(x86::k1).z().emit(op,out,tmp);
	}else{EvexOnly(j); j.k(x86::k1).z().emit(op, out, x86::ptr(R_STATE, ins->rs, sb));}
	if (ins->sew == 4) j.k(x86::k1).vmovdqu32(x86::ptr(R_STATE, ins->rd), out);
	else j.k(x86::k1).vmovdqu64(x86::ptr(R_STATE, ins->rd), out);
}

void QEmit::Emit_vchunkftof(qir::InstVChunkFToF *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86=asmjit::x86;
	u32 const ss=ins->sew==4?8:4,sb=ins->bytes/ins->sew*ss;
	if(ins->rd+ins->bytes>sizeof(CPUState)||ins->rs+sb>sizeof(CPUState))Panic("qemit: float conversion outside CPUState");
	x86::Vec out=ins->bytes==64?x86::Vec(x86::zmm0):ins->bytes==32?x86::Vec(x86::ymm0):x86::Vec(x86::xmm0);
	x86::Vec tmp=ins->bytes==64?x86::Vec(x86::zmm1):ins->bytes==32?x86::Vec(x86::ymm1):x86::Vec(x86::xmm1);
	EmitRvvBodyMask(ins->bytes/ins->sew,ins->base,ins->masked);j.kmovq(x86::k1,x86::rdi);
	if(ins->rod){
		// Round-to-odd is RTZ followed by jamming an inexact result's low bit.
		// Change RC locally, retaining the enclosing FP bracket and its accumulated flags.
		j.sub(x86::rsp,16);j.stmxcsr(x86::dword_ptr(x86::rsp));
		j.mov(x86::eax,x86::dword_ptr(x86::rsp));j.and_(x86::eax,~0x6000u);j.or_(x86::eax,0x6000);
		j.mov(x86::dword_ptr(x86::rsp,4),x86::eax);j.ldmxcsr(x86::dword_ptr(x86::rsp,4));
	}
	EvexOnly(j);j.k(x86::k1).z().emit(ins->sew==4?x86::Inst::kIdVcvtpd2ps:x86::Inst::kIdVcvtps2pd,
		out,x86::ptr(R_STATE,ins->rs,sb));
	if(ins->rod){
		x86::Vec back=sb==64?x86::Vec(x86::zmm1):sb==32?x86::Vec(x86::ymm1):x86::Vec(x86::xmm1);
		EvexOnly(j);j.k(x86::k1).z().vcvtps2pd(back,out);
		j.k(x86::k1).vcmppd(x86::k2,back,x86::ptr(R_STATE,ins->rs,sb),4);
		j.mov(x86::eax,1);j.vpbroadcastd(tmp,x86::eax);j.k(x86::k2).vpord(out,out,tmp);
		j.stmxcsr(x86::dword_ptr(x86::rsp,4));j.mov(x86::eax,x86::dword_ptr(x86::rsp));j.and_(x86::eax,0x6000);
		j.mov(x86::edx,x86::dword_ptr(x86::rsp,4));j.and_(x86::edx,~0x6000u);j.or_(x86::eax,x86::edx);
		j.mov(x86::dword_ptr(x86::rsp,4),x86::eax);j.ldmxcsr(x86::dword_ptr(x86::rsp,4));j.add(x86::rsp,16);
	}
	if(ins->sew==4){
		j.k(x86::k1).vcmpps(x86::k2,out,out,3);j.mov(x86::eax,0x7fc00000);j.vpbroadcastd(tmp,x86::eax);
		j.k(x86::k2).vmovaps(out,tmp);j.k(x86::k1).vmovdqu32(x86::ptr(R_STATE,ins->rd),out);
	}else{
		j.k(x86::k1).vcmppd(x86::k2,out,out,3);j.mov(x86::rax,0x7ff8000000000000ull);j.vpbroadcastq(tmp,x86::rax);
		j.k(x86::k2).vmovapd(out,tmp);j.k(x86::k1).vmovdqu64(x86::ptr(R_STATE,ins->rd),out);
	}
}

// ORDER ITEM 4: the CHUNKED estimate node is an LLVM-route shape. QCG builds the WHOLE-REGISTER
// `vfestimate` node instead (RvvTryIntegerFamily, which refuses `aot_use_llvm`), so nothing on this
// backend can construct this one -- and a Panic is the fail-closed statement of that rather than a
// second, unreviewed implementation of the same semantics.
// Order item 4: the chunked float-merge node is an LLVM-route shape; QCG lowers `vfmerge` through
// `vchunkpartialalu`'s Merge/Mov kinds instead, so nothing on this backend constructs this one.
void QEmit::Emit_vchunkfmerge(qir::InstVChunkFMerge *)
{
	Panic("qemit: the chunked RVV float-merge node is an LLVM-route shape");
}

void QEmit::Emit_vchunkfestimate(qir::InstVChunkFEstimate *)
{
	Panic("qemit: the chunked RVV estimate node is an LLVM-route shape");
}

void QEmit::Emit_vchunkfclass(qir::InstVChunkFClass *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	if (ins->rd + ins->bytes > sizeof(CPUState) || ins->rs + ins->bytes > sizeof(CPUState))
		Panic("qemit: floating classification chunk outside CPUState");
	x86::Vec out = x86::xmm0, tmp = x86::xmm1;
	if (ins->bytes == 32) { out = x86::ymm0; tmp = x86::ymm1; }
	if (ins->bytes == 64) { out = x86::zmm0; tmp = x86::zmm1; }
	u64 const sign = u64(1) << (ins->sew * 8 - 1);
	u64 const frac = ins->sew == 4 ? 0x007fffffull : 0x000fffffffffffffull;
	u64 const exp = (sign - 1) ^ frac;
	auto broadcast = [&](x86::Vec reg, u64 value) {
		j.mov(x86::rax, value);
		if (ins->sew == 4) j.vpbroadcastd(reg, x86::eax);
		else j.vpbroadcastq(reg, x86::rax);
	};
	// These tests inspect bits only: even an sNaN must not change guest or host FP flags.
	auto field = [&](x86::KReg k, u64 bits, bool equal_all) {
		broadcast(out, bits);
		j.vpandq(tmp, out, x86::ptr(R_STATE, ins->rs, ins->bytes));
		if (equal_all) {
			if (ins->sew == 4) j.vpcmpud(k, tmp, out, 0);
			else j.vpcmpuq(k, tmp, out, 0);
		} else {
			if (ins->sew == 4) j.vptestmd(k, tmp, tmp);
			else j.vptestmq(k, tmp, tmp);
		}
	};
	field(x86::k2, sign, false);
	field(x86::k3, exp, false); j.knotw(x86::k3, x86::k3);
	field(x86::k4, exp, true);
	field(x86::k5, frac, false); j.knotw(x86::k5, x86::k5);
	field(x86::k6, (frac + 1) >> 1, false);
	j.vpxord(out, out, out);
	auto emit_class = [&](u32 bit) {
		broadcast(tmp, 1u << bit);
		if (ins->sew == 4) j.k(x86::k7).vpord(out, out, tmp);
		else j.k(x86::k7).vporq(out, out, tmp);
	};
	// k1 is a category before its sign split; k7 is the final per-element predicate.
	auto signed_class = [&](u32 negative, u32 positive) {
		j.kandw(x86::k7, x86::k1, x86::k2); emit_class(negative);
		j.kandnw(x86::k7, x86::k2, x86::k1); emit_class(positive);
	};
	j.kandw(x86::k1, x86::k4, x86::k5); signed_class(0, 7);
	j.korw(x86::k1, x86::k3, x86::k4); j.knotw(x86::k1, x86::k1); signed_class(1, 6);
	j.kandnw(x86::k1, x86::k5, x86::k3); signed_class(2, 5);
	j.kandw(x86::k1, x86::k3, x86::k5); signed_class(3, 4);
	j.kandnw(x86::k1, x86::k5, x86::k4);
	j.kandnw(x86::k7, x86::k6, x86::k1); emit_class(8);
	j.kandw(x86::k7, x86::k6, x86::k1); emit_class(9);
	EmitRvvBodyMask(ins->bytes / ins->sew, ins->base, ins->masked);
	j.kmovq(x86::k1, x86::rdi);
	if (ins->sew == 4) j.k(x86::k1).vmovdqu32(x86::ptr(R_STATE, ins->rd), out);
	else j.k(x86::k1).vmovdqu64(x86::ptr(R_STATE, ins->rd), out);
	if (ins->finish)
		j.mov(x86::dword_ptr(R_STATE, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart)), 0);
}

void QEmit::Emit_vchunkindex(qir::InstVChunkIndex *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86=asmjit::x86;
	if(ins->rd+ins->bytes>sizeof(CPUState))Panic("qemit: element-index chunk outside CPUState");
	u32 const lanes=ins->bytes/ins->sew;
	u8 values[64]{};
	for(u32 e=0;e<lanes;++e){u64 value=ins->base+e;memcpy(values+e*ins->sew,&value,ins->sew);}
	auto data=j.newLabel(),ready=j.newLabel();
	// Inline RIP-relative data is copied into the code object, never a translator-stack pointer.
	j.jmp(ready);j.bind(data);j.embed(values,ins->bytes);j.bind(ready);
	EmitRvvBodyMask(lanes,ins->base,ins->masked);
	j.kmovq(x86::k1,x86::rdi);
	x86::Vec v=x86::xmm0;
	if(ins->bytes==64)v=x86::zmm0;else if(ins->bytes==32)v=x86::ymm0;
	j.vmovdqu64(v,x86::ptr(data));
	auto dest=x86::ptr(R_STATE,ins->rd);
	switch(ins->sew) {
	case 1:j.k(x86::k1).vmovdqu8(dest,v);break;
	case 2:j.k(x86::k1).vmovdqu16(dest,v);break;
	case 4:j.k(x86::k1).vmovdqu32(dest,v);break;
	case 8:j.k(x86::k1).vmovdqu64(dest,v);break;
	}
	if(ins->finish)j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)),0);
}

void QEmit::Emit_vgathernative(qir::InstVGather *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	u32 const vo = offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg);
	u32 shift = 0; for (u32 n=ins->regbytes;n>1;n>>=1) ++shift;
	if (!ins->slide && ins->mode==0 && ins->sew>=4 &&
	    (config::rvv_qcg_typed_chunk_force_emit ||
	     (__builtin_cpu_supports("avx512f") && __builtin_cpu_supports("bmi2")))) {
		u32 const lanes=std::min(64u,u32(ins->regbytes))/ins->sew;
		for(u32 base=0;base<ins->vlmax;base+=lanes) {
			EmitRvvBodyMask(std::min(lanes,u32(ins->vlmax)-base),base,ins->masked);
			j.kmovq(x86::k1,x86::rdi);
			u32 const il=base*ins->isew;
			auto idx=x86::ptr(R_STATE,vo+(ins->index+il/ins->regbytes)*512+il%ins->regbytes);
			if(ins->isew==2) {
				if(ins->sew==4) j.k(x86::k1).z().vpmovzxwd(x86::zmm1,idx);
				else j.k(x86::k1).z().vpmovzxwq(x86::zmm1,idx);
			} else if(ins->sew==4) j.k(x86::k1).z().vmovdqu32(x86::zmm1,idx);
			else j.k(x86::k1).z().vmovdqu64(x86::zmm1,idx);
			j.mov(x86::eax,ins->vlmax);
			if(ins->sew==4) {
				j.vpbroadcastd(x86::zmm0,x86::eax);
				j.vpcmpud(x86::k2,x86::zmm1,x86::zmm0,1);
				j.vpslld(x86::zmm1,x86::zmm1,2);
				j.vpsrld(x86::zmm0,x86::zmm1,shift); j.vpslld(x86::zmm0,x86::zmm0,9);
				j.vpslld(x86::zmm1,x86::zmm1,32-shift); j.vpsrld(x86::zmm1,x86::zmm1,32-shift);
			} else {
				j.vpbroadcastq(x86::zmm0,x86::rax);
				j.vpcmpuq(x86::k2,x86::zmm1,x86::zmm0,1);
				j.vpsllq(x86::zmm1,x86::zmm1,3);
				j.vpsrlq(x86::zmm0,x86::zmm1,shift); j.vpsllq(x86::zmm0,x86::zmm0,9);
				j.vpsllq(x86::zmm1,x86::zmm1,64-shift); j.vpsrlq(x86::zmm1,x86::zmm1,64-shift);
			}
			j.vporq(x86::zmm1,x86::zmm1,x86::zmm0);
			j.kandq(x86::k2,x86::k2,x86::k1);
			j.vpxorq(x86::zmm0,x86::zmm0,x86::zmm0);
			j.lea(x86::r10,x86::ptr(R_STATE,vo+ins->data*512));
			if(ins->sew==4) j.k(x86::k2).vpgatherdd(x86::zmm0,x86::ptr(x86::r10,x86::zmm1));
			else j.k(x86::k2).vpgatherqq(x86::zmm0,x86::ptr(x86::r10,x86::zmm1));
			u32 const dl=base*ins->sew;
			auto dst=x86::ptr(R_STATE,vo+(ins->rd+dl/ins->regbytes)*512+dl%ins->regbytes);
			if(ins->sew==4) j.k(x86::k1).vmovdqu32(dst,x86::zmm0);
			else j.k(x86::k1).vmovdqu64(dst,x86::zmm0);
		}
		j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)),0);
		return;
	}
	auto address = [&](u32 width) {
		u32 log = 0; for (u32 n=width;n>1;n>>=1) ++log;
		j.shl(x86::eax,log);
		j.mov(x86::edx,x86::eax); j.shr(x86::edx,shift); j.shl(x86::edx,9);
		j.and_(x86::eax,ins->regbytes-1); j.add(x86::eax,x86::edx);
	};
	auto load = [&](x86::Gp dst,u32 width,u32 reg) {
		auto mem=x86::ptr(R_STATE,x86::rax,0,vo+reg*512).cloneResized(width);
		if(width<=2) j.movzx(dst.r32(),mem);
		else if(width==4) j.mov(dst.r32(),mem);
		else j.mov(dst,mem);
	};
	auto done=j.newLabel(),loop=j.newLabel(),next=j.newLabel(),store=j.newLabel();
	j.mov(x86::r8d,x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)));
	j.mov(x86::r9d,x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vl)));
	j.cmp(x86::r8d,x86::r9d); j.jae(done);
	if(ins->mode==1) {
		if(ins->index) j.mov(x86::r10d,x86::dword_ptr(R_STATE,offsetof(CPUState,gpr)+ins->index*4));
		else j.xor_(x86::r10d,x86::r10d);
		if(ins->slide>=3 && ins->sew==8) j.movsxd(x86::r10,x86::r10d);
	} else if(ins->mode==2) j.mov(x86::r10d,ins->index);
	else if(ins->mode==3) {
		j.mov(x86::r10,x86::qword_ptr(R_STATE,offsetof(CPUState,fpu)+offsetof(rv32::FPUState,f)+ins->index*8));
		if(ins->sew==4) {
			auto boxed=j.newLabel(); j.mov(x86::rax,x86::r10); j.shr(x86::rax,32);
			j.cmp(x86::eax,-1); j.je(boxed); j.mov(x86::r10d,0x7fc00000); j.bind(boxed);
		}
	}
	j.bind(loop);
	if(ins->masked) {
		j.mov(x86::eax,x86::r8d); j.shr(x86::eax,3);
		j.movzx(x86::edx,x86::byte_ptr(R_STATE,x86::rax,0,vo));
		j.mov(x86::eax,x86::r8d); j.and_(x86::eax,7); j.bt(x86::edx,x86::eax); j.jnc(next);
	}
	if(ins->slide) {
		j.mov(x86::edi,x86::r8d);
		if(ins->slide==1) {
			j.cmp(x86::rdi,x86::r10); j.jb(next); j.sub(x86::rdi,x86::r10);
		} else if(ins->slide==2) j.add(x86::rdi,x86::r10);
		else {
			auto read=j.newLabel();
			if(ins->slide==3) { j.test(x86::edi,x86::edi); j.jnz(read); }
			else { j.inc(x86::edi); j.cmp(x86::edi,x86::r9d); j.jb(read); }
			j.mov(x86::rcx,x86::r10); j.jmp(store);
			j.bind(read); if(ins->slide==3) j.dec(x86::edi);
		}
	} else if(ins->mode==0) {
		j.mov(x86::eax,x86::r8d); address(ins->isew); load(x86::rdi,ins->isew,ins->index);
	} else j.mov(x86::rdi,x86::r10);
	// Test the complete unsigned index before narrowing it to a state offset.
	j.xor_(x86::ecx,x86::ecx); j.cmp(x86::rdi,ins->vlmax); j.jae(store);
	j.mov(x86::eax,x86::edi); address(ins->sew); load(x86::rcx,ins->sew,ins->data);
	j.bind(store);
	j.mov(x86::eax,x86::r8d); address(ins->sew);
	auto dst=x86::ptr(R_STATE,x86::rax,0,vo+ins->rd*512).cloneResized(ins->sew);
	if(ins->sew==1) j.mov(dst,x86::cl); else if(ins->sew==2) j.mov(dst,x86::cx);
	else if(ins->sew==4) j.mov(dst,x86::ecx); else j.mov(dst,x86::rcx);
	j.bind(next); j.inc(x86::r8d); j.cmp(x86::r8d,x86::r9d); j.jb(loop);
	j.bind(done);
	j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)),0);
}

// Z3 (--rvv-qcg-typed-chunk-vlse-gather, default off): the AVX-512 gather body for `vlse32.v`.
// The admitted shape, the two runtime fallbacks and the accepted diagnostic divergence are stated
// in config.h at the switch; this comment is about the EMITTED FORM only.
//
// P1 -- WHY THE BASE IS BIASED BY 2^31. VPGATHERDD's VSIB index is a SIGNED dword: the SDM's
// operation section computes each lane's address as BASE_ADDR + SignExtend(VINDEX[i]) * SCALE,
// which in 64-bit mode sign-extends the 32-bit index to 64 bits before adding. A guest address in
// [2^31, 2^32) would therefore be applied to mmu::base as a NEGATIVE displacement in [-2^31, 0) --
// the top half of the guest address space would read the host mapping BELOW the reservation.
// The fix is exact for the whole space and has no lane cost: hold `host = mmu::base + 2^31` and
// give the lanes `index = guest_addr - 2^31` (mod 2^32). For every guest_addr in [0, 2^32) the
// signed value of that dword is exactly guest_addr - 2^31 in [-2^31, 2^31), so
// host + sext(index) == mmu::base + guest_addr identically. SCALE must be 1, and it is.
//
// P2 -- WHY EVERY CHUNK IS GUARDED BEFORE IT STORES. RV32 wraps an effective address modulo 2^32,
// and the element loop below implements that literally: for sew > 1 it compares the address with
// 0xFFFFFFFC and assembles the wrapping element byte by byte. A gather cannot wrap -- it would read
// the host bytes at mmu::base + 2^32 and beyond, which is where ukernel hints rvdbt's OWN heap, and
// which mmu::check_h2g does not even recognise as guest memory. So each chunk tests its ACTIVE lanes
// against the same 0xFFFFFFFC (as the biased constant 0x7FFFFFFC, signed) and leaves for the element
// loop if any of them exceeds it. The branch precedes that chunk's vmovdqu32, so a chunk that leaves
// has written nothing; a load is a pure function of guest memory, so rerunning the whole instruction
// from element zero in the element loop reproduces the architectural result exactly, and earlier
// chunks that already stored are simply stored again with the same bytes.
//
// REGISTERS. The two reserved scratch vectors (VPR_FIXED = {0,1}) and no others: zmm1 holds the
// index vector, zmm0 is the stride splat, then the limit splat, then the gather destination -- and
// VPGATHERDD requires its destination, index and mask to be three distinct registers, which
// zmm0/zmm1/k2 are. k1 is the architectural active mask for the chunk and is NOT handed to the
// gather, which clears the mask register it is given; the copy in k2 absorbs that. GPRs are the
// element loop's own scratch set (r8-r11, plus EmitRvvBodyMask's rax/rdx/rdi/rsi), so the fallback
// edge into the loop needs no register agreement: the loop reloads everything it uses.
bool QEmit::EmitRvvStridedGather(qir::InstVMemory *ins, asmjit::Label const &done)
{
	namespace x86 = asmjit::x86;
	if (!config::rvv_qcg_typed_chunk_vlse_gather)
		return false;
	// Translation-time admission. Every clause is a property of the ENCODING or of the vtype the
	// frame's guard already pinned, so this predicate is workload-independent and has no threshold.
	if (ins->store || ins->masked || ins->mode != 1 || ins->nf != 1 || ins->fieldregs != 1)
		return false;
	if (ins->sew != 4 || ins->isew != 4) // EEW 32 only: x86 has no byte/word gather.
		return false;
	if (ins->regbytes < 64) // VLEN >= 512, so the chunk is a whole ZMM and lanes == 16.
		return false;
	if (!ins->vlmax) // No recorded element count: the static chunk unroll has no trip count.
		return false;
	if (!(config::rvv_qcg_typed_chunk_vlse_gather_force_emit ||
	      (__builtin_cpu_supports("avx512f") && __builtin_cpu_supports("bmi2"))))
		return false;

	u32 const vo = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
	u32 const startoff = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart);
	u32 const lanes = 64u / ins->sew;
	auto scalar = j.newLabel(), data = j.newLabel(), ready = j.newLabel();

	// F3: a restarted execution keeps the element loop, which starts at vstart and publishes it.
	// Read from the live CPUState -- the VTypeInteger guard does not check vstart.
	j.cmp(x86::dword_ptr(R_STATE, startoff), 0);
	j.jne(scalar);

	// The lane-index constant, inline and RIP-relative, exactly as Emit_vchunkindex embeds its own:
	// copied into the code object, never a translator-stack pointer.
	u8 iota[64]{};
	for (u32 e = 0; e < lanes; ++e) { u32 const v = e; memcpy(iota + e * ins->sew, &v, ins->sew); }
	j.jmp(ready); j.bind(data); j.embed(iota, sizeof(iota)); j.bind(ready);

	if (ins->base) j.mov(x86::r10d, x86::dword_ptr(R_STATE, offsetof(CPUState, gpr) + ins->base * 4));
	else j.xor_(x86::r10d, x86::r10d);
	j.add(x86::r10d, 0x80000000u); // P1 bias; 32-bit, so it wraps with the guest's own arithmetic.
	if (ins->index) j.mov(x86::r11d, x86::dword_ptr(R_STATE, offsetof(CPUState, gpr) + ins->index * 4));
	else j.xor_(x86::r11d, x86::r11d); // rs2 == x0 is stride 0, a legal broadcast.
	j.mov(x86::r9d, x86::r11d); j.shl(x86::r9d, 4); // lanes*stride: the per-chunk base advance.
	j.mov(x86::r8d, 0x80000000u); // zero-extends to 64 bits, so this is +2^31 and not -2^31.
	j.add(x86::r8, R_MEMBASE);    // host = mmu::base + 2^31

	for (u32 base = 0; base < ins->vlmax; base += lanes) {
		u32 const n = std::min(lanes, (u32)ins->vlmax - base);
		if (base) j.add(x86::r10d, x86::r9d);
		// (e < vl) && (e >= vstart), from the live CPUState, for this chunk's element window.
		EmitRvvBodyMask(n, base, false);
		j.kmovw(x86::k1, x86::edi);
		j.vpbroadcastd(x86::zmm0, x86::r11d);
		j.vpmulld(x86::zmm0, x86::zmm0, x86::ptr(data)); // e*stride, lane-wise, mod 2^32
		j.vpbroadcastd(x86::zmm1, x86::r10d);
		j.vpaddd(x86::zmm1, x86::zmm1, x86::zmm0); // biased addr(e), bit-identical to imul+add
		j.mov(x86::eax, 0x7ffffffcu);
		j.vpbroadcastd(x86::zmm0, x86::eax);
		j.vpcmpd(x86::k2, x86::zmm1, x86::zmm0, 6); // signed >, i.e. guest addr > 0xfffffffc
		j.kandw(x86::k2, x86::k2, x86::k1);         // ...on an ACTIVE lane only
		j.kortestw(x86::k2, x86::k2);
		j.jnz(scalar); // P2, before this chunk's store and before any access
		j.kmovw(x86::k2, x86::k1);
		j.vpxord(x86::zmm0, x86::zmm0, x86::zmm0);
		j.k(x86::k2).vpgatherdd(x86::zmm0, x86::ptr(x86::r8, x86::zmm1));
		// The same chunk -> CPUState window formula the vrgather fast path uses: a chunk may cross
		// a 512-byte register slot inside an LMUL group. The store is masked by the ACTIVE mask, so
		// inactive and tail elements of the destination are undisturbed.
		u32 const dl = base * ins->sew;
		j.k(x86::k1).vmovdqu32(
		    x86::ptr(R_STATE, vo + (ins->data + dl / ins->regbytes) * 512 + dl % ins->regbytes),
		    x86::zmm0);
	}
	// Z4B: the fast path completed -- every chunk passed its P2 guard, gathered and stored. This
	// is the ONLY way to reach the jump over the element loop, so the counter is exactly
	// "executions that completed the gather body".
	EmitRvvGatherCensus(&g_vlse_gather_fast);
	j.mov(x86::dword_ptr(R_STATE, startoff), 0);
	j.jmp(done);
	j.bind(scalar);
	// Z4B: and this is the ONLY edge into the retained element loop while the fast path is
	// emitted -- a completed fast path jumps PAST this label. So one counter here covers both
	// runtime exits, the F3 `vstart != 0` precheck and every chunk's address-space-top guard,
	// without a second site and without distinguishing them.
	EmitRvvGatherCensus(&g_vlse_gather_fallback);
	return true;
}

// Z4B. The one place either gather-census increment is emitted. Off by default, so this emits
// nothing at all and the surrounding bytes are Z3's exactly; it is reached only from inside
// EmitRvvStridedGather, after that function has already decided the fast path is admitted.
//
// WHY rax IS FREE AT BOTH SITES, and not saved. This node's body owns rax outright: the element
// loop's own `stateaddr` writes it on its first iteration, the fast path's chunk loop uses it for
// the 0x7ffffffc limit, and EmitRvvBodyMask uses rax/rdx/rdi/rsi as scratch. Nothing can be live in
// it across the node, for the reason EmitRvvFrameCensusIncr states for the same register: the frame
// carries HAS_CALLS, so QRegAlloc assigned no virtual register to a call-clobbered host register
// anywhere inside it. Site 1 is followed by a store of an immediate and a jump; site 2 is followed
// by the element loop's `mov r8d, [state+vstart]`. Neither reads rax, and neither reads the flags
// `inc` writes.
void QEmit::EmitRvvGatherCensus(unsigned long long *counter)
{
	namespace x86 = asmjit::x86;
	if (!config::rvv_qcg_typed_chunk_vlse_gather_census)
		return;
	j.mov(x86::rax, (uint64_t)(uintptr_t)counter);
	j.inc(x86::qword_ptr(x86::rax));
}

void QEmit::Emit_vmemorynative(qir::InstVMemory *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86=asmjit::x86;
	u32 const vo=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg);
	u32 const startoff=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart);
	// Z3: the optional gather body, and its fallback edge into the element loop below. With the
	// switch off this emits nothing and `gathered` is false, so the emitted bytes are unchanged.
	auto gather_done=j.newLabel();
	bool const gathered=EmitRvvStridedGather(ins,gather_done);
	u32 shift=0;for(u32 n=ins->regbytes;n>1;n>>=1)++shift;
	auto stateaddr=[&](u32 width){
		u32 lg=0;for(u32 n=width;n>1;n>>=1)++lg;
		j.mov(x86::eax,x86::r8d);j.shl(x86::eax,lg);
		static_assert(rv32::VLEN_MAX_BYTES==512, "native memory mapping assumes 512-byte physical register slots");
		// Equal logical and physical strides make group remapping an identity.
		if(ins->regbytes==rv32::VLEN_MAX_BYTES)return;
		j.mov(x86::edx,x86::eax);j.shr(x86::edx,shift);j.shl(x86::edx,9);
		j.and_(x86::eax,ins->regbytes-1);j.add(x86::eax,x86::edx);
	};
	auto read=[&](x86::Mem mem,u32 width){
		mem.setSize(width);
		if(width<=2)j.movzx(x86::ecx,mem);else if(width==4)j.mov(x86::ecx,mem);else j.mov(x86::rcx,mem);
	};
	auto write=[&](x86::Mem mem,u32 width){
		mem.setSize(width);
		if(width==1)j.mov(mem,x86::cl);else if(width==2)j.mov(mem,x86::cx);
		else if(width==4)j.mov(mem,x86::ecx);else j.mov(mem,x86::rcx);
	};
	auto done=j.newLabel(),loop=j.newLabel(),next=j.newLabel();
	auto mask_search=j.newLabel(),access=j.newLabel();
	bool const enumerate_mask=ins->masked && ins->mode<=2 && config::rvv_qcg_active_mask_memory;
	j.mov(x86::r8d,x86::dword_ptr(R_STATE,startoff));
	if(ins->mode==4)j.mov(x86::r9d,(u32)ins->index*ins->regbytes/ins->sew);
	else j.mov(x86::r9d,x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vl)));
	if(ins->mode==3){j.add(x86::r9d,7);j.shr(x86::r9d,3);}
	j.cmp(x86::r8d,x86::r9d);j.jae(done);
	if(ins->base)j.mov(x86::r10d,x86::dword_ptr(R_STATE,offsetof(CPUState,gpr)+ins->base*4));
	else j.xor_(x86::r10d,x86::r10d);
	if(ins->mode==1){
		if(ins->index)j.mov(x86::r11d,x86::dword_ptr(R_STATE,offsetof(CPUState,gpr)+ins->index*4));
		else j.xor_(x86::r11d,x86::r11d);
	}
	j.bind(loop);
	if(ins->masked){
		j.mov(x86::eax,x86::r8d);j.shr(x86::eax,3);
		j.movzx(x86::edx,x86::byte_ptr(R_STATE,x86::rax,0,vo));
		j.mov(x86::eax,x86::r8d);j.and_(x86::eax,7);j.bt(x86::edx,x86::eax);
		j.jnc(enumerate_mask ? mask_search : next);
	}
	j.bind(access);
	if(ins->mode==2){
		stateaddr(ins->isew);read(x86::ptr(R_STATE,x86::rax,0,vo+ins->index*512),ins->isew);
		j.mov(x86::edi,x86::ecx);
	}else{
		j.mov(x86::edi,x86::r8d);
		if(ins->mode==1)j.imul(x86::edi,x86::r11d);
		else j.imul(x86::edi,ins->sew*ins->nf);
	}
	j.add(x86::edi,x86::r10d); // RV32 address arithmetic wraps at XLEN, not at host pointer width.
	// Publish the current element before the access, so a host fault does not report a stale restart index.
	j.mov(x86::dword_ptr(R_STATE,startoff),x86::r8d);
	for(u32 field=0;field<ins->nf;++field){
	u32 const dataoff=vo+(ins->data+field*ins->fieldregs)*512;
	if(field)j.add(x86::edi,ins->sew);
	auto regular=j.newLabel(),copied=j.newLabel();
	if(ins->store){stateaddr(ins->sew);read(x86::ptr(R_STATE,x86::rax,0,dataoff),ins->sew);}
	if(ins->sew>1){
		j.cmp(x86::edi,u32(0xffffffffu-(ins->sew-1)));j.jbe(regular);
		if(!ins->store)j.xor_(x86::ecx,x86::ecx);
		for(u32 b=0;b<ins->sew;++b){
			j.mov(x86::edx,x86::edi);j.add(x86::edx,b);
			if(ins->store){j.mov(x86::rsi,x86::rcx);if(b)j.shr(x86::rsi,8*b);j.mov(x86::byte_ptr(R_MEMBASE,x86::rdx),x86::sil);}
			else{j.movzx(x86::eax,x86::byte_ptr(R_MEMBASE,x86::rdx));if(b)j.shl(x86::rax,8*b);j.or_(x86::rcx,x86::rax);}
		}
		j.jmp(copied);
	}
	j.bind(regular);
	if(ins->store)write(x86::ptr(R_MEMBASE,x86::rdi),ins->sew);
	else read(x86::ptr(R_MEMBASE,x86::rdi),ins->sew);
	j.bind(copied);
	if(!ins->store){stateaddr(ins->sew);write(x86::ptr(R_STATE,x86::rax,0,dataoff),ins->sew);}
	}
	j.bind(next);j.inc(x86::r8d);j.cmp(x86::r8d,x86::r9d);j.jb(loop);
	if(enumerate_mask){
		j.jmp(done);
		j.bind(mask_search);
		// Read the current mask again on every search, not a cached snapshot.
		// Only host-side v0 storage is read here; guest accesses retain their order.
		j.mov(x86::eax,x86::r8d);j.shr(x86::eax,6);
		j.mov(x86::rdx,x86::qword_ptr(R_STATE,x86::rax,3,vo));
		j.mov(x86::ecx,x86::r8d);j.and_(x86::ecx,63);j.shr(x86::rdx,x86::cl);
		auto found=j.newLabel();
		j.test(x86::rdx,x86::rdx);j.jnz(found);
		j.or_(x86::r8d,63);j.inc(x86::r8d);
		j.cmp(x86::r8d,x86::r9d);j.jb(mask_search);j.jmp(done);
		j.bind(found);j.bsf(x86::rdx,x86::rdx);j.add(x86::r8d,x86::edx);
		j.cmp(x86::r8d,x86::r9d);j.jb(access);
	}
	j.bind(done);j.mov(x86::dword_ptr(R_STATE,startoff),0);
	if(gathered)j.bind(gather_done);
}

void QEmit::Emit_vwholemove(qir::InstVWholeMove *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86=asmjit::x86;
	u32 const vo=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg);
	u32 const so=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart);
	auto done=j.newLabel();
	if(ins->rd!=ins->src){
		u32 shift=0;for(u32 n=ins->regbytes;n>1;n>>=1)++shift;
		u32 width=16;
#if defined(__x86_64__) || defined(__i386__)
		if(ins->regbytes>=64&&__builtin_cpu_supports("avx512f"))width=64;
#endif
		// Unlike memory whole-register transfers, move's restart unit is current SEW.
		j.mov(x86::r8d,x86::dword_ptr(R_STATE,so));
		// The common completed-instruction state starts at byte zero. Keep the
		// restartable loop below for every nonzero vstart; a short straight-line
		// copy avoids its per-chunk address calculation without using vl or vtype.
		if ((u32)ins->nregs * ins->regbytes / width <= 8) {
			auto restart = j.newLabel();
			j.test(x86::r8d,x86::r8d);j.jnz(restart);
			for (u32 reg=0;reg<ins->nregs;++reg)
				for (u32 off=0;off<ins->regbytes;off+=width) {
					u32 const src=vo+(ins->src+reg)*512+off;
					u32 const dst=vo+(ins->rd+reg)*512+off;
					if(width==64){
						j.vmovdqu64(x86::zmm0,x86::ptr(R_STATE,src));
						j.vmovdqu64(x86::ptr(R_STATE,dst),x86::zmm0);
					}else{
						j.movdqu(x86::xmm0,x86::ptr(R_STATE,src));
						j.movdqu(x86::ptr(R_STATE,dst),x86::xmm0);
					}
				}
			j.jmp(done);j.bind(restart);
		}
		j.mov(x86::ecx,x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vtype)));
		j.shr(x86::ecx,3);j.and_(x86::ecx,7);j.shl(x86::r8,x86::cl);
		j.cmp(x86::r8,(u32)ins->nregs*ins->regbytes);j.jae(done);
		auto loop=j.newLabel(),packed=j.newLabel(),next=j.newLabel();
		j.bind(loop);
		j.mov(x86::eax,x86::r8d);j.shr(x86::eax,shift);j.shl(x86::eax,9);
		j.mov(x86::edx,x86::r8d);j.and_(x86::edx,ins->regbytes-1);j.add(x86::eax,x86::edx);
		j.test(x86::r8d,width-1);j.jz(packed);
		j.movzx(x86::ecx,x86::byte_ptr(R_STATE,x86::rax,0,vo+ins->src*512));
		j.mov(x86::byte_ptr(R_STATE,x86::rax,0,vo+ins->rd*512),x86::cl);
		j.inc(x86::r8d);j.jmp(next);
		j.bind(packed);
		if(width==64){
			j.vmovdqu64(x86::zmm0,x86::ptr(R_STATE,x86::rax,0,vo+ins->src*512));
			j.vmovdqu64(x86::ptr(R_STATE,x86::rax,0,vo+ins->rd*512),x86::zmm0);
		}else{
			j.movdqu(x86::xmm0,x86::ptr(R_STATE,x86::rax,0,vo+ins->src*512));
			j.movdqu(x86::ptr(R_STATE,x86::rax,0,vo+ins->rd*512),x86::xmm0);
		}
		j.add(x86::r8d,width);
		j.bind(next);j.cmp(x86::r8d,(u32)ins->nregs*ins->regbytes);j.jb(loop);
	}
	j.bind(done);j.mov(x86::dword_ptr(R_STATE,so),0);
}

void QEmit::Emit_vfestimate(qir::InstVFEstimate *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86=asmjit::x86;
	u32 const vo=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg);
	u32 const fo=offsetof(CPUState,fpu)+offsetof(rv32::FPUState,fcsr);
	u32 const mant=ins->sew==4?23:52,bias=ins->sew==4?127:1023,emax=2*bias+1;
	u64 const frac=(u64(1)<<mant)-1,sign=u64(1)<<(ins->sew*8-1),inf=u64(emax)<<mant;
	u64 const qnan=inf|(u64(1)<<(mant-1));
	u32 shift=0;for(u32 n=ins->regbytes;n>1;n>>=1)++shift;
	auto addr=[&](){
		j.mov(x86::eax,x86::r8d);j.shl(x86::eax,ins->sew==4?2:3);
		j.mov(x86::edx,x86::eax);j.shr(x86::edx,shift);j.shl(x86::edx,9);
		j.and_(x86::eax,ins->regbytes-1);j.add(x86::eax,x86::edx);
	};
	auto done=j.newLabel(),loop=j.newLabel(),next=j.newLabel(),store=j.newLabel();
	auto special=j.newLabel(),zero=j.newLabel(),invalid=j.newLabel(),nan=j.newLabel();
	auto normal=j.newLabel(),normalize=j.newLabel(),normalized=j.newLabel(),overflow=j.newLabel();
	j.mov(x86::r8d,x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)));
	j.mov(x86::r9d,x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vl)));
	j.cmp(x86::r8d,x86::r9d);j.jae(done);
	j.bind(loop);
	if(ins->masked){
		j.mov(x86::eax,x86::r8d);j.shr(x86::eax,3);
		j.movzx(x86::edx,x86::byte_ptr(R_STATE,x86::rax,0,vo));
		j.mov(x86::eax,x86::r8d);j.and_(x86::eax,7);j.bt(x86::edx,x86::eax);j.jnc(next);
	}
	addr();
	if(ins->sew==4)j.mov(x86::esi,x86::dword_ptr(R_STATE,x86::rax,0,vo+ins->src*512));
	else j.mov(x86::rsi,x86::qword_ptr(R_STATE,x86::rax,0,vo+ins->src*512));
	j.mov(x86::r10,sign);j.and_(x86::r10,x86::rsi);
	j.mov(x86::rdi,frac);j.and_(x86::rdi,x86::rsi);
	j.mov(x86::rcx,x86::rsi);j.shr(x86::rcx,mant);j.and_(x86::ecx,emax);
	j.cmp(x86::ecx,emax);j.je(special);
	j.test(x86::ecx,x86::ecx);j.jnz(normal);
	j.test(x86::rdi,x86::rdi);j.jz(zero);
	j.bind(normal);
	if(ins->sqrt){j.test(x86::r10,x86::r10);j.jnz(invalid);}
	j.test(x86::ecx,x86::ecx);j.jnz(normalized);
	// Subnormal normalization uses integer shifts; host DAZ/FTZ cannot change the answer.
	j.mov(x86::ecx,1);j.bind(normalize);
	j.shl(x86::rdi,1);j.dec(x86::ecx);j.bt(x86::rdi,mant);j.jnc(normalize);
	j.btr(x86::rdi,mant);
	j.bind(normalized);
	j.mov(x86::rax,x86::rdi);
	j.shr(x86::rax,mant-(ins->sqrt?6:7));
	if(ins->sqrt){
		j.mov(x86::edx,x86::ecx);j.and_(x86::edx,1);j.shl(x86::edx,6);j.or_(x86::eax,x86::edx);
	}
	j.mov(x86::r11,ins->table);j.movzx(x86::edi,x86::byte_ptr(x86::r11,x86::rax));
	j.shl(x86::rdi,mant-7);
	j.mov(x86::eax,(ins->sqrt?3:2)*bias-1);j.sub(x86::eax,x86::ecx);
	if(ins->sqrt)j.shr(x86::eax,1);
	else {
		j.cmp(x86::eax,emax);j.jge(overflow);
		auto finite=j.newLabel();j.test(x86::eax,x86::eax);j.jg(finite);
		j.mov(x86::ecx,1);j.sub(x86::ecx,x86::eax);j.bts(x86::rdi,mant);j.shr(x86::rdi,x86::cl);
		j.xor_(x86::eax,x86::eax);j.bind(finite);
	}
	j.shl(x86::rax,mant);j.or_(x86::rax,x86::rdi);j.or_(x86::rax,x86::r10);
	j.mov(x86::rsi,x86::rax);j.jmp(store);
	j.bind(special);
	j.test(x86::rdi,x86::rdi);j.jnz(nan);
	if(ins->sqrt){j.test(x86::r10,x86::r10);j.jnz(invalid);}
	j.mov(x86::rsi,x86::r10);j.jmp(store);
	j.bind(nan);
	j.bt(x86::rdi,mant-1);j.jnc(invalid);
	j.mov(x86::rsi,qnan);j.jmp(store);
	j.bind(invalid);j.or_(x86::dword_ptr(R_STATE,fo),0x10);
	j.mov(x86::rsi,qnan);j.jmp(store);
	j.bind(zero);j.or_(x86::dword_ptr(R_STATE,fo),0x08);
	j.mov(x86::rsi,inf);j.or_(x86::rsi,x86::r10);j.jmp(store);
	j.bind(overflow);
	if(!ins->sqrt){
		j.or_(x86::dword_ptr(R_STATE,fo),0x05);
		j.mov(x86::eax,x86::dword_ptr(R_STATE,fo));j.shr(x86::eax,5);j.and_(x86::eax,7);
		auto infinity=j.newLabel(),bounded=j.newLabel(),selected=j.newLabel();
		j.test(x86::eax,x86::eax);j.jz(infinity);j.cmp(x86::eax,4);j.je(infinity);
		j.cmp(x86::eax,1);j.je(bounded);
		j.test(x86::r10,x86::r10);auto positive=j.newLabel();j.jz(positive);
		j.cmp(x86::eax,2);j.je(infinity);j.jmp(bounded);
		j.bind(positive);j.cmp(x86::eax,3);j.je(infinity);
		j.bind(bounded);j.mov(x86::rsi,inf-1);j.jmp(selected);
		j.bind(infinity);j.mov(x86::rsi,inf);
		j.bind(selected);j.or_(x86::rsi,x86::r10);
	}
	j.bind(store);addr();
	if(ins->sew==4)j.mov(x86::dword_ptr(R_STATE,x86::rax,0,vo+ins->rd*512),x86::esi);
	else j.mov(x86::qword_ptr(R_STATE,x86::rax,0,vo+ins->rd*512),x86::rsi);
	j.bind(next);j.inc(x86::r8d);j.cmp(x86::r8d,x86::r9d);j.jb(loop);
	j.bind(done);j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)),0);
}

void QEmit::Emit_vfreducenative(qir::InstVFReduce *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	u32 const vo = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
	u32 const ds = ins->wide ? 8 : ins->sew;
	auto done = j.newLabel(), loop = j.newLabel(), next = j.newLabel(), store = j.newLabel();
	j.mov(x86::r9d, x86::dword_ptr(R_STATE, offsetof(CPUState,vec)+offsetof(rv32::VectorState,vl)));
	j.test(x86::r9d,x86::r9d); j.jz(done);
	if (ds == 4) j.vmovss(x86::xmm0,x86::dword_ptr(R_STATE,vo+ins->seed*512));
	else j.vmovsd(x86::xmm0,x86::qword_ptr(R_STATE,vo+ins->seed*512));
	j.xor_(x86::r8d,x86::r8d); j.xor_(x86::ecx,x86::ecx);
	j.bind(loop);
	if (ins->masked) {
		j.mov(x86::eax,x86::r8d); j.shr(x86::eax,3);
		j.movzx(x86::edx,x86::byte_ptr(R_STATE,x86::rax,0,vo));
		j.mov(x86::eax,x86::r8d); j.and_(x86::eax,7);
		j.bt(x86::edx,x86::eax); j.jnc(next);
	}
	// Register groups are logically contiguous, but rvdbt stores each register in a 512-byte slot.
	u32 shift = 0; for (u32 n=ins->regbytes;n>1;n>>=1) ++shift;
	j.mov(x86::eax,x86::r8d); j.shl(x86::eax,ins->sew==4?2:3);
	j.mov(x86::edx,x86::eax); j.shr(x86::edx,shift); j.shl(x86::edx,9);
	j.and_(x86::eax,ins->regbytes-1); j.add(x86::eax,x86::edx);
	if (ins->sew == 4) j.vmovss(x86::xmm1,x86::dword_ptr(R_STATE,x86::rax,0,vo+ins->data*512));
	else j.vmovsd(x86::xmm1,x86::qword_ptr(R_STATE,x86::rax,0,vo+ins->data*512));
	if (ins->wide) j.vcvtss2sd(x86::xmm1,x86::xmm1,x86::xmm1);
	if (ins->op == 0) {
		// Ordered reduction has a real accumulator dependence; no reassociation is legal here.
		if (ds == 4) j.vaddss(x86::xmm0,x86::xmm0,x86::xmm1);
		else j.vaddsd(x86::xmm0,x86::xmm0,x86::xmm1);
	} else {
		auto nan = j.newLabel(), equal = j.newLabel(), take = j.newLabel(), combined = j.newLabel();
		// UCOMIS raises NV only on sNaN. x86 MIN/MAX instead signal even on qNaN.
		if (ds == 4) j.vucomiss(x86::xmm0,x86::xmm1);
		else j.vucomisd(x86::xmm0,x86::xmm1);
		j.jp(nan); j.je(equal);
		if (ins->op == 1) j.ja(take); else j.jb(take);
		j.jmp(combined);
		j.bind(nan);
		if (ds == 4) {
			j.vmovd(x86::eax,x86::xmm0); j.and_(x86::eax,0x7fffffff);
			j.cmp(x86::eax,0x7f800000);
		} else {
			j.vmovq(x86::rax,x86::xmm0); j.btr(x86::rax,63);
			j.mov(x86::rdx,0x7ff0000000000000ull); j.cmp(x86::rax,x86::rdx);
		}
		j.ja(take); j.jmp(combined); // Numeric acc wins over NaN; NaN acc selects the other operand.
		j.bind(equal);
		if (ins->op == 1) j.vorps(x86::xmm0,x86::xmm0,x86::xmm1);
		else j.vandps(x86::xmm0,x86::xmm0,x86::xmm1);
		j.jmp(combined); // Equal values differ only in the sign bit of zero.
		j.bind(take); j.vmovaps(x86::xmm0,x86::xmm1);
		j.bind(combined);
	}
	j.mov(x86::ecx,1);
	j.bind(next); j.inc(x86::r8d); j.cmp(x86::r8d,x86::r9d); j.jb(loop);
	// Canonicalize only after an actual addition. All-masked reductions copy the seed bit-exactly.
	j.test(x86::ecx,x86::ecx); j.jz(store);
	if (ds == 4) {
		j.vmovd(x86::eax,x86::xmm0); j.and_(x86::eax,0x7fffffff);
		j.cmp(x86::eax,0x7f800000); j.jbe(store);
		j.mov(x86::eax,0x7fc00000); j.vmovd(x86::xmm0,x86::eax);
	} else {
		j.vmovq(x86::rax,x86::xmm0); j.btr(x86::rax,63);
		j.mov(x86::rdx,0x7ff0000000000000ull); j.cmp(x86::rax,x86::rdx); j.jbe(store);
		j.mov(x86::rax,0x7ff8000000000000ull); j.vmovq(x86::xmm0,x86::rax);
	}
	j.bind(store);
	if (ds == 4) j.vmovss(x86::dword_ptr(R_STATE,vo+ins->rd*512),x86::xmm0);
	else j.vmovsd(x86::qword_ptr(R_STATE,vo+ins->rd*512),x86::xmm0);
	j.bind(done);
}

void QEmit::Emit_vreducenative(qir::InstVReduce *ins)
{
	rvv_typed_chunk_seen+=rvv_typed_chunk_open;
	namespace x86=asmjit::x86;
	u32 const vo=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg);
	bool const wide=ins->op>=8;
	u32 const sew=ins->sew*(wide?2:1),bytes=std::min(wide?32u:64u,u32(ins->regbytes)),lanes=bytes/ins->sew;
	bool const sign=ins->op==5||ins->op==7;
	u64 const top=u64(1)<<(sew*8-1),all=top|(top-1);
	u64 const neutral=ins->op==1||ins->op==4?all:ins->op==5?top-1:ins->op==7?top:0;
	auto done=j.newLabel();
	j.cmp(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vl)),0);j.je(done);
	auto seed=x86::ptr(R_STATE,vo+ins->seed*512);
	if(sew==1){if(sign)j.movsx(x86::r8,seed.cloneResized(1));else j.movzx(x86::r8d,seed.cloneResized(1));}
	else if(sew==2){if(sign)j.movsx(x86::r8,seed.cloneResized(2));else j.movzx(x86::r8d,seed.cloneResized(2));}
	else if(sew==4){if(sign)j.movsxd(x86::r8,seed.cloneResized(4));else j.mov(x86::r8d,seed.cloneResized(4));}
	else j.mov(x86::r8,seed.cloneResized(8));
	auto combine=[&](){
		auto a=x86::zmm0,b=x86::zmm1;
#define REDUCE_SIZE(B,W,D,Q) do{if(sew==1)j.B(a,a,b);else if(sew==2)j.W(a,a,b);else if(sew==4)j.D(a,a,b);else j.Q(a,a,b);}while(0)
		switch(ins->op){case 0:case 8:case 9:REDUCE_SIZE(vpaddb,vpaddw,vpaddd,vpaddq);break;
		case 1:j.vpandq(a,a,b);break;case 2:j.vporq(a,a,b);break;case 3:j.vpxorq(a,a,b);break;
		case 4:REDUCE_SIZE(vpminub,vpminuw,vpminud,vpminuq);break;
		case 5:REDUCE_SIZE(vpminsb,vpminsw,vpminsd,vpminsq);break;
		case 6:REDUCE_SIZE(vpmaxub,vpmaxuw,vpmaxud,vpmaxuq);break;
		case 7:REDUCE_SIZE(vpmaxsb,vpmaxsw,vpmaxsd,vpmaxsq);break;}
#undef REDUCE_SIZE
	};
	for(u32 base=0;base<ins->vlmax;base+=lanes){
		EmitRvvBodyMask(std::min(lanes,u32(ins->vlmax)-base),base,ins->masked);
		auto next=j.newLabel();j.test(x86::rdi,x86::rdi);j.jz(next);j.kmovq(x86::k1,x86::rdi);
		j.mov(x86::rax,neutral);
		if(sew==1)j.vpbroadcastb(x86::zmm0,x86::eax);else if(sew==2)j.vpbroadcastw(x86::zmm0,x86::eax);
		else if(sew==4)j.vpbroadcastd(x86::zmm0,x86::eax);else j.vpbroadcastq(x86::zmm0,x86::rax);
		u32 logical=base*ins->sew;auto src=x86::ptr(R_STATE,vo+(ins->data+logical/ins->regbytes)*512+logical%ins->regbytes);
		if(wide){
			if(ins->op==9){if(sew==2)j.k(x86::k1).vpmovsxbw(x86::zmm0,src);else if(sew==4)j.k(x86::k1).vpmovsxwd(x86::zmm0,src);else j.k(x86::k1).vpmovsxdq(x86::zmm0,src);}
			else {if(sew==2)j.k(x86::k1).vpmovzxbw(x86::zmm0,src);else if(sew==4)j.k(x86::k1).vpmovzxwd(x86::zmm0,src);else j.k(x86::k1).vpmovzxdq(x86::zmm0,src);}
		}
		else if(sew==1)j.k(x86::k1).vmovdqu8(x86::zmm0,src);else if(sew==2)j.k(x86::k1).vmovdqu16(x86::zmm0,src);
		else if(sew==4)j.k(x86::k1).vmovdqu32(x86::zmm0,src);else j.k(x86::k1).vmovdqu64(x86::zmm0,src);
		// Tree reduction. Only the low element is consumed after the final two stages.
		j.vshufi64x2(x86::zmm1,x86::zmm0,x86::zmm0,0x4e);combine();
		j.vshufi64x2(x86::zmm1,x86::zmm0,x86::zmm0,0xb1);combine();
		j.vpshufd(x86::zmm1,x86::zmm0,0x4e);combine();
		if(sew<=4){j.vpshufd(x86::zmm1,x86::zmm0,0xb1);combine();}
		if(sew<=2){j.vpsrld(x86::zmm1,x86::zmm0,16);combine();}
		if(sew==1){j.vpsrlw(x86::zmm1,x86::zmm0,8);combine();}
		j.vmovq(x86::rax,x86::xmm0);
		if(sew==1){if(sign)j.movsx(x86::rax,x86::al);else j.movzx(x86::eax,x86::al);}
		else if(sew==2){if(sign)j.movsx(x86::rax,x86::ax);else j.movzx(x86::eax,x86::ax);}
		else if(sew==4){if(sign)j.movsxd(x86::rax,x86::eax);else j.mov(x86::eax,x86::eax);}
		switch(ins->op){case 0:case 8:case 9:j.add(x86::r8,x86::rax);break;case 1:j.and_(x86::r8,x86::rax);break;
		case 2:j.or_(x86::r8,x86::rax);break;case 3:j.xor_(x86::r8,x86::rax);break;
		case 4:j.cmp(x86::r8,x86::rax);j.cmova(x86::r8,x86::rax);break;
		case 5:j.cmp(x86::r8,x86::rax);j.cmovg(x86::r8,x86::rax);break;
		case 6:j.cmp(x86::r8,x86::rax);j.cmovb(x86::r8,x86::rax);break;
		case 7:j.cmp(x86::r8,x86::rax);j.cmovl(x86::r8,x86::rax);break;}
		j.bind(next);
	}
	auto dst=x86::ptr(R_STATE,vo+ins->rd*512);
	if(sew==1)j.mov(dst,x86::r8b);else if(sew==2)j.mov(dst,x86::r8w);else if(sew==4)j.mov(dst,x86::r8d);else j.mov(dst,x86::r8);
	j.bind(done);j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)),0);
}

void QEmit::Emit_vcompressnative(qir::InstVCompress *ins)
{
	rvv_typed_chunk_seen+=rvv_typed_chunk_open;
	namespace x86=asmjit::x86;
	u32 const vo=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg);
	u32 const bytes=std::min(64u,u32(ins->regbytes)),lanes=bytes/ins->sew;
	u32 const shift=__builtin_ctz(ins->sew),rbshift=__builtin_ctz(ins->regbytes);
	j.xor_(x86::r8d,x86::r8d); // Number of elements already packed into the destination.
	for(u32 base=0;base<ins->vlmax;base+=lanes) {
		EmitRvvBodyMask(std::min(lanes,u32(ins->vlmax)-base),base,false);
		j.mov(x86::r9,x86::qword_ptr(R_STATE,vo+ins->mask*512+base/8));
		if(base%8)j.shr(x86::r9,base%8);
		j.and_(x86::r9,x86::rdi);
		auto next=j.newLabel(),part=j.newLabel();j.test(x86::r9,x86::r9);j.jz(next);
		u32 const logical=base*ins->sew;
		j.vmovdqu64(x86::zmm0,x86::ptr(R_STATE,vo+(ins->data+logical/ins->regbytes)*512+logical%ins->regbytes));
		j.bind(part);
		// Limit each packed store to one architectural register's physical slot.
		j.mov(x86::r10d,x86::r8d);j.shl(x86::r10d,shift);j.mov(x86::r11d,x86::r10d);
		j.and_(x86::r10d,ins->regbytes-1);j.shr(x86::r11d,rbshift);j.shl(x86::r11d,9);
		j.mov(x86::ecx,ins->regbytes);j.sub(x86::ecx,x86::r10d);j.shr(x86::ecx,shift);
		j.mov(x86::eax,64);j.cmp(x86::ecx,64);j.cmova(x86::ecx,x86::eax);
		j.add(x86::r10d,x86::r11d);
		j.mov(x86::rax,~u64(0));j.bzhi(x86::rax,x86::rax,x86::rcx);
		j.pdep(x86::rax,x86::rax,x86::r9);j.kmovq(x86::k1,x86::rax);
		auto dst=x86::ptr(R_STATE,x86::r10,0,vo+ins->rd*512);
		switch(ins->sew){case 1:j.k(x86::k1).vpcompressb(dst,x86::zmm0);break;
		case 2:j.k(x86::k1).vpcompressw(dst,x86::zmm0);break;
		case 4:j.k(x86::k1).vpcompressd(dst,x86::zmm0);break;
		case 8:j.k(x86::k1).vpcompressq(dst,x86::zmm0);break;}
		j.xor_(x86::r9,x86::rax);j.popcnt(x86::rax,x86::rax);j.add(x86::r8d,x86::eax);
		j.test(x86::r9,x86::r9);j.jnz(part);j.bind(next);
	}
	j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)),0);
}

void QEmit::Emit_vscalarmove(qir::InstVScalarMove *ins)
{
	rvv_typed_chunk_seen+=rvv_typed_chunk_open;
	namespace x86=asmjit::x86;
	u32 const vo=offsetof(CPUState,vec),elem=vo+offsetof(rv32::VectorState,vreg)+ins->vreg*512;
	u32 const scalar=ins->floating ? offsetof(CPUState,fpu)+offsetof(rv32::FPUState,f)+ins->greg*8 :
		offsetof(CPUState,gpr)+ins->greg*4;
	u32 const start=vo+offsetof(rv32::VectorState,vstart);
	if(ins->to_vector) {
		auto done=j.newLabel();
		j.mov(x86::eax,x86::dword_ptr(R_STATE,start));
		j.cmp(x86::eax,x86::dword_ptr(R_STATE,vo+offsetof(rv32::VectorState,vl)));j.jae(done);
		if(ins->floating) {
			j.mov(x86::rax,x86::qword_ptr(R_STATE,scalar));
			if(ins->sew==4) {
				// Invalid NaN boxing is read as canonical qNaN, without FP arithmetic.
				j.mov(x86::rdx,x86::rax);j.shr(x86::rdx,32);j.cmp(x86::edx,-1);
				j.mov(x86::edx,0x7fc00000u);j.cmovne(x86::eax,x86::edx);
			}
		}
		else if(!ins->greg)j.xor_(x86::eax,x86::eax);
		else if(ins->sew==8)j.movsxd(x86::rax,x86::dword_ptr(R_STATE,scalar));
		else j.mov(x86::eax,x86::dword_ptr(R_STATE,scalar));
		auto dest=x86::ptr(R_STATE,elem);
		switch(ins->sew){case 1:j.mov(dest,x86::al);break;case 2:j.mov(dest,x86::ax);break;
		case 4:j.mov(dest,x86::eax);break;case 8:j.mov(dest,x86::rax);break;}
		j.bind(done);
	} else if(ins->floating) {
		if(ins->sew==4) {
			j.mov(x86::eax,x86::dword_ptr(R_STATE,elem));
			j.mov(x86::rdx,0xffffffff00000000ull);j.or_(x86::rax,x86::rdx);
		} else j.mov(x86::rax,x86::qword_ptr(R_STATE,elem));
		j.mov(x86::qword_ptr(R_STATE,scalar),x86::rax);
	} else if(ins->greg) {
		if(ins->sew==1)j.movsx(x86::eax,x86::byte_ptr(R_STATE,elem));
		else if(ins->sew==2)j.movsx(x86::eax,x86::word_ptr(R_STATE,elem));
		else j.mov(x86::eax,x86::dword_ptr(R_STATE,elem));
		j.mov(x86::dword_ptr(R_STATE,scalar),x86::eax);
	}
	j.mov(x86::dword_ptr(R_STATE,start),0);
}

void QEmit::Emit_vmaskiota(qir::InstVMaskIota *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86=asmjit::x86;
	u32 const lastbyte=(ins->vlmax-1)*ins->sew;
	if(ins->rd+(lastbyte/ins->regbytes)*512+lastbyte%ins->regbytes+ins->sew>sizeof(CPUState)||
	   ins->source+(ins->vlmax+63)/64*8>sizeof(CPUState))Panic("qemit: iota outside CPUState");
	j.xor_(x86::r8d,x86::r8d);
	for(u32 base=0;base<ins->vlmax;base+=64) {
		u32 const lanes=std::min(64u,ins->vlmax-base);
		EmitRvvBodyMask(lanes,base,ins->masked);
		j.mov(x86::r9,x86::qword_ptr(R_STATE,ins->source+base/8));j.and_(x86::r9,x86::rdi);
		auto loop=j.newLabel(),skip=j.newLabel(),done=j.newLabel();
		j.test(x86::rdi,x86::rdi);j.jz(done);j.xor_(x86::ecx,x86::ecx);j.bind(loop);
		j.bt(x86::rdi,x86::rcx);j.jnc(skip);
		// A prefix count in this word plus the total of all preceding words.
		j.bzhi(x86::rax,x86::r9,x86::rcx);j.popcnt(x86::rax,x86::rax);j.add(x86::rax,x86::r8);
		j.mov(x86::r10d,x86::ecx);j.add(x86::r10d,base);j.shl(x86::r10d,__builtin_ctz(ins->sew));
		j.mov(x86::r11d,x86::r10d);j.and_(x86::r10d,ins->regbytes-1);
		j.shr(x86::r11d,__builtin_ctz(ins->regbytes));j.shl(x86::r11d,9);j.add(x86::r10d,x86::r11d);
		auto dest=x86::ptr(R_STATE,x86::r10,0,ins->rd);
		switch(ins->sew){case 1:j.mov(dest,x86::al);break;case 2:j.mov(dest,x86::ax);break;case 4:j.mov(dest,x86::eax);break;case 8:j.mov(dest,x86::rax);break;}
		j.bind(skip);j.inc(x86::ecx);j.cmp(x86::ecx,lanes);j.jb(loop);
		j.popcnt(x86::rax,x86::r9);j.add(x86::r8,x86::rax);j.bind(done);
	}
	j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)),0);
}

void QEmit::Emit_vmaskscalar(qir::InstVMaskScalar *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86=asmjit::x86;
	if (ins->source + (ins->vlmax+63)/64*8 > sizeof(CPUState)) Panic("qemit: mask scalar source outside CPUState");
	j.mov(x86::r8d,ins->first?u32(-1):0u);
	auto done=j.newLabel();
	for(u32 base=0;base<ins->vlmax;base+=64) {
		EmitRvvBodyMask(std::min(64u,ins->vlmax-base),base,ins->masked);
		j.mov(x86::rax,x86::qword_ptr(R_STATE,ins->source+base/8));
		j.and_(x86::rax,x86::rdi);
		if(ins->first) {
			auto next=j.newLabel();j.jz(next);
			j.bsf(x86::rax,x86::rax);j.add(x86::eax,base);j.mov(x86::r8d,x86::eax);j.jmp(done);
			j.bind(next);
		} else { j.popcnt(x86::rax,x86::rax);j.add(x86::r8d,x86::eax); }
	}
	j.bind(done);
	if(ins->rd)j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,gpr)+ins->rd*4),x86::r8d);
	j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)),0);
}

void QEmit::Emit_vmaskprefix(qir::InstVMaskPrefix *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86=asmjit::x86;
	for(u32 off:{ins->rd,ins->source})
		if(off+(ins->vlmax+63)/64*8>sizeof(CPUState))Panic("qemit: mask prefix outside CPUState");
	j.xor_(x86::r8d,x86::r8d); // Carry whether an earlier mask word contained the first bit.
	for(u32 base=0;base<ins->vlmax;base+=64) {
		EmitRvvBodyMask(std::min(64u,ins->vlmax-base),base,ins->masked);
		auto store=j.newLabel(),empty=j.newLabel();
		j.xor_(x86::eax,x86::eax);
		j.test(x86::r8d,x86::r8d);j.jnz(store);
		j.mov(x86::rax,x86::qword_ptr(R_STATE,ins->source+base/8));j.and_(x86::rax,x86::rdi);j.jz(empty);
		j.mov(x86::rdx,x86::rax);j.neg(x86::rdx);j.and_(x86::rax,x86::rdx);
		if(ins->kind==0)j.dec(x86::rax);
		if(ins->kind==1){j.lea(x86::rdx,x86::ptr(x86::rax,-1));j.or_(x86::rax,x86::rdx);}
		j.mov(x86::r8d,1);j.jmp(store);
		j.bind(empty);if(ins->kind!=2)j.mov(x86::rax,u64(-1));
		j.bind(store);
		j.and_(x86::rax,x86::rdi);j.not_(x86::rdi);
		j.and_(x86::rdi,x86::qword_ptr(R_STATE,ins->rd+base/8));j.or_(x86::rax,x86::rdi);
		j.mov(x86::qword_ptr(R_STATE,ins->rd+base/8),x86::rax);
	}
	j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)),0);
}

void QEmit::Emit_vmasklogic(qir::InstVMaskLogic *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	for (u32 o : {ins->rd, ins->rs2, ins->rs1})
		if (o + sizeof(u64) > sizeof(CPUState)) Panic("qemit: mask word outside CPUState");
	u32 const vo = offsetof(CPUState, vec);
	EmitRvvBodyMask(64, ins->base, false);
	j.mov(x86::rax, x86::qword_ptr(R_STATE, ins->rs2));
	j.mov(x86::rdx, x86::qword_ptr(R_STATE, ins->rs1));
	switch (ins->op) {
	case 0: j.not_(x86::rdx); j.and_(x86::rax, x86::rdx); break;
	case 1: j.and_(x86::rax, x86::rdx); break;
	case 2: j.or_(x86::rax, x86::rdx); break;
	case 3: j.xor_(x86::rax, x86::rdx); break;
	case 4: j.not_(x86::rdx); j.or_(x86::rax, x86::rdx); break;
	case 5: j.and_(x86::rax, x86::rdx); j.not_(x86::rax); break;
	case 6: j.or_(x86::rax, x86::rdx); j.not_(x86::rax); break;
	case 7: j.xor_(x86::rax, x86::rdx); j.not_(x86::rax); break;
	}
	j.and_(x86::rax, x86::rdi);
	j.not_(x86::rdi); j.and_(x86::rdi, x86::qword_ptr(R_STATE, ins->rd));
	j.or_(x86::rax, x86::rdi); j.mov(x86::qword_ptr(R_STATE, ins->rd), x86::rax);
	if (ins->finish) j.mov(x86::dword_ptr(R_STATE, vo + offsetof(rv32::VectorState, vstart)), 0);
}

void QEmit::Emit_vchunkpartialalu(qir::InstVChunkPartialAlu *ins)
{
	namespace x86 = asmjit::x86;
	if (!rvv_instruction_work_last && rvv_typed_chunk_open &&
	    rvv_typed_chunk_partial_seen && config::rvv_qcg_active_vl_int_bound &&
	    !config::aot_use_llvm) {
		auto const scope = rv32::rvvfinal::PlanInstructionWorkScope(ins->getIter(), bb->ilist.end());
		if (scope.units > 1) {
			rvv_instruction_work_last = scope.last;
			rvv_instruction_work_done = j.newLabel();
		}
	}
	bool const bounded = rvv_instruction_work_last != nullptr;
	if (bounded) {
		j.cmp(x86::dword_ptr(R_STATE, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vl)),
		      ins->element_base);
		j.jbe(rvv_instruction_work_done);
	}
	EmitPartialAluBody(ins, ins->finish_instruction && !bounded);
	if (bounded && ins == rvv_instruction_work_last) {
		// All exits execute this instruction's completion, then the next member.
		j.bind(rvv_instruction_work_done);
		j.mov(x86::dword_ptr(R_STATE, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart)), 0);
		rvv_instruction_work_last = nullptr;
	}
}

void QEmit::EmitPartialAluBody(qir::InstVChunkPartialAlu *ins, bool finish_instruction)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	if (unlikely(!ins->architectural_mask && ins->sew_bytes != 4))
		Panic("qemit: vchunkpartialalu with an unsupported SEW");
	u32 const bytes = ins->chunk_bytes;
	using Src1 = qir::InstVChunkPartialAlu::Src1;
	using Kind = qir::InstVChunkPartialAlu::Kind;
	auto const op = (Kind)ins->op;
	bool const clip = op == Kind::ClipU || op == Kind::ClipS;
	u32 const dest_bytes = clip ? bytes / 2 : bytes;
	if (unlikely((size_t)ins->rd_offs + dest_bytes > sizeof(CPUState) || (size_t)ins->rs2_offs + bytes > sizeof(CPUState)))
		Panic("qemit: vchunkpartialalu window lies outside CPUState");
	if ((Src1)ins->src1_kind == Src1::Vector && unlikely((size_t)ins->rs1_offs + dest_bytes > sizeof(CPUState)))
		Panic("qemit: vchunkpartialalu window lies outside CPUState");
	if ((Src1)ins->src1_kind == Src1::GprWord && unlikely((size_t)ins->rs1_offs + 4u > sizeof(CPUState)))
		Panic("qemit: vchunkpartialalu GPR word lies outside CPUState");
	if ((Src1)ins->src1_kind == Src1::FprBoxed && unlikely((size_t)ins->rs1_offs + 8u > sizeof(CPUState)))
		Panic("qemit: floating bit-move source outside CPUState");
	bool const shift = op == Kind::Sll || op == Kind::Srl || op == Kind::Sra;
	bool const round_shift = op == Kind::RoundSrl || op == Kind::RoundSra || clip;
	if (clip && ins->sew_bytes < 2) Panic("qemit: clip requires a wide source");
	bool const accumulate = op == Kind::Macc || op == Kind::Nmsac || op == Kind::Madd || op == Kind::Nmsub;
	bool const dest_multiplicand = op == Kind::Madd || op == Kind::Nmsub;
	bool const high_multiply = op == Kind::MulHU || op == Kind::MulH || op == Kind::MulHSU;
	bool const fractional = op == Kind::FracMul;
	bool const divide = op == Kind::DivU || op == Kind::DivS || op == Kind::RemU || op == Kind::RemS;
	bool const carry = op >= Kind::Adc && op <= Kind::Msbc;
	bool const compare = (op >= Kind::Eq && op <= Kind::GtS) || op == Kind::Madc || op == Kind::Msbc;
	u32 const result_bits = bytes / ins->sew_bytes;
	bool const overwrite_mask = compare && !ins->masked && ins->element_base % 8u == 0 &&
	    (result_bits == 8 || result_bits == 16 || result_bits == 32 || result_bits == 64) &&
	    rvv_body_mask_known_vl >= ins->element_base + result_bits;
	bool const widen_bytes = (shift || round_shift || op == Kind::Mul || accumulate) && ins->sew_bytes == 1;
	bool const widen_high = (high_multiply || fractional) && ins->sew_bytes < 8;
	if ((widen_bytes || widen_high) && bytes > 32) Panic("qemit: widened elements exceed host capacity");
	u32 const host_bytes = widen_bytes || widen_high ? bytes * 2 : bytes;
	auto vec = [host_bytes](u32 n) -> x86::Vec {
		return host_bytes == 16 ? x86::Vec(x86::xmm(n)) : host_bytes == 32 ? x86::Vec(x86::ymm(n)) : x86::Vec(x86::zmm(n));
	};
	auto const s0 = vec(0), s1 = vec(1);
	auto const k = x86::KReg(ins->architectural_mask ? 1 : 1 + ins->chunk);
	if (ins->architectural_mask && !(overwrite_mask && !carry)) {
		// These state-backed nodes run behind a HAS_CALLS guard: caller-saved GPRs and
		// the two reserved vector temporaries are available, with no live globals.
		EmitRvvBodyMask(bytes / ins->sew_bytes, ins->element_base, ins->masked && op != Kind::Merge && !carry);
		j.kmovq(k, x86::rdi);
	}
	if (divide || ((high_multiply || fractional) && ins->sew_bytes == 8)) {
		// AVX-512 has neither packed integer divide nor 64x64 high-product. Emit
		// exact host scalar operations for active lanes, without a C++ helper call.
		if (!ins->architectural_mask) Panic("qemit: scalar integer lanes require architectural mask");
		u32 const sew = ins->sew_bytes, bits = sew * 8;
		bool const signed_div = op == Kind::DivS || op == Kind::RemS;
		bool const rem = op == Kind::RemU || op == Kind::RemS;
		auto load = [&](x86::Gp dst, u32 offset) {
			if (sew == 1) j.movzx(dst.r32(), x86::byte_ptr(R_STATE, offset));
			else if (sew == 2) j.movzx(dst.r32(), x86::word_ptr(R_STATE, offset));
			else if (sew == 4) j.mov(dst.r32(), x86::dword_ptr(R_STATE, offset));
			else j.mov(dst, x86::qword_ptr(R_STATE, offset));
		};
		for (u32 lane = 0; lane < bytes / sew; ++lane) {
			auto skip = j.newLabel(), write = j.newLabel();
			j.bt(x86::rdi, lane); j.jnc(skip);
			load(x86::rax, ins->rs2_offs + lane * sew);
			if ((Src1)ins->src1_kind == Src1::Vector) load(x86::rsi, ins->rs1_offs + lane * sew);
			else if ((Src1)ins->src1_kind == Src1::GprWord)
				j.movsxd(x86::rsi, x86::dword_ptr(R_STATE, ins->rs1_offs));
			else j.mov(x86::rsi, (u64)(i64)(i32)ins->imm);
			if (bits < 64) {
				j.shl(x86::rsi, 64 - bits);
				if (signed_div) {
					j.sar(x86::rsi, 64 - bits);
					j.shl(x86::rax, 64 - bits); j.sar(x86::rax, 64 - bits);
				} else j.shr(x86::rsi, 64 - bits);
			}
			if (fractional) {
				auto ordinary=j.newLabel(),ready=j.newLabel(),even=j.newLabel(),truncate=j.newLabel();
				j.mov(x86::rcx,u64(1)<<63);j.cmp(x86::rax,x86::rcx);j.jne(ordinary);
				j.cmp(x86::rsi,x86::rcx);j.jne(ordinary);
				j.dec(x86::rcx);j.mov(x86::rax,x86::rcx);
				j.or_(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vxsat)),1);
				j.jmp(write);
				j.bind(ordinary);j.imul(x86::rsi); // full signed RDX:RAX product
				j.mov(x86::rsi,x86::rax);j.shrd(x86::rax,x86::rdx,63);
				j.mov(x86::rcx,x86::rsi);j.shl(x86::rcx,2);
				j.setne(x86::cl);j.movzx(x86::ecx,x86::cl); // lower discarded bits
				j.shr(x86::rsi,62);j.and_(x86::esi,1); // rounding bit
				j.mov(x86::rdx,x86::rax);j.and_(x86::edx,1); // retained bit
				j.mov(x86::r8d,x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vxrm)));
				j.and_(x86::r8d,3);j.jz(ready);
				j.cmp(x86::r8d,2);j.je(truncate);j.cmp(x86::r8d,1);j.je(even);
				j.or_(x86::esi,x86::ecx);j.xor_(x86::edx,1);j.and_(x86::esi,x86::edx);j.jmp(ready);
				j.bind(even);j.or_(x86::ecx,x86::edx);j.and_(x86::esi,x86::ecx);j.jmp(ready);
				j.bind(truncate);j.xor_(x86::esi,x86::esi);
				j.bind(ready);j.add(x86::rax,x86::rsi);
			} else if (high_multiply) {
				if (op == Kind::MulHSU) {
					j.mov(x86::rcx, x86::rax); j.sar(x86::rcx, 63); j.and_(x86::rcx, x86::rsi);
				}
				if (op == Kind::MulH) j.imul(x86::rsi); else j.mul(x86::rsi);
				if (op == Kind::MulHSU) j.sub(x86::rdx, x86::rcx);
				j.mov(x86::rax, x86::rdx);
			} else {
				auto nonzero = j.newLabel(), ordinary = j.newLabel();
				j.test(x86::rsi, x86::rsi); j.jnz(nonzero);
				if (!rem) j.mov(x86::rax, uint64_t(-1));
				j.jmp(write); j.bind(nonzero);
				if (signed_div && bits == 64) {
					j.cmp(x86::rsi, -1); j.jne(ordinary);
					j.mov(x86::rcx, uint64_t(1) << 63); j.cmp(x86::rax, x86::rcx); j.jne(ordinary);
					if (rem) j.xor_(x86::eax, x86::eax);
					j.jmp(write);
				}
				j.bind(ordinary);
				if (signed_div) { j.cqo(); j.idiv(x86::rsi); }
				else { j.xor_(x86::edx, x86::edx); j.div(x86::rsi); }
				if (rem) j.mov(x86::rax, x86::rdx);
			}
			j.bind(write);
			j.mov(x86::ptr(R_STATE, ins->rd_offs + lane * sew, sew),
				sew == 1 ? x86::Gp(x86::al) : sew == 2 ? x86::Gp(x86::ax) : sew == 4 ? x86::Gp(x86::eax) : x86::Gp(x86::rax));
			j.bind(skip);
		}
		if (finish_instruction)
			j.mov(x86::dword_ptr(R_STATE, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart)), 0);
		return;
	}
	if (widen_high) {
		// A full double-width product followed by truncation of its low half.
		auto wide_load = [&](x86::Vec dst, u32 offset, bool sign) {
			EvexOnly(j);
			uint32_t id = ins->sew_bytes == 1 ? (sign ? x86::Inst::kIdVpmovsxbw : x86::Inst::kIdVpmovzxbw) :
				ins->sew_bytes == 2 ? (sign ? x86::Inst::kIdVpmovsxwd : x86::Inst::kIdVpmovzxwd) :
				(sign ? x86::Inst::kIdVpmovsxdq : x86::Inst::kIdVpmovzxdq);
			j.emit(id, dst, x86::ptr(R_STATE, offset, bytes));
		};
		wide_load(s0, ins->rs2_offs, op != Kind::MulHU);
		if ((Src1)ins->src1_kind == Src1::Vector) wide_load(s1, ins->rs1_offs, op == Kind::MulH || fractional);
		else {
			if ((Src1)ins->src1_kind == Src1::GprWord) j.movsxd(x86::rax, x86::dword_ptr(R_STATE, ins->rs1_offs));
			else j.mov(x86::rax, (u64)(i64)(i32)ins->imm);
			j.shl(x86::rax, 64 - 8 * ins->sew_bytes);
			if (op == Kind::MulH || fractional) j.sar(x86::rax, 64 - 8 * ins->sew_bytes);
			else j.shr(x86::rax, 64 - 8 * ins->sew_bytes);
			EvexOnly(j);
			if (ins->sew_bytes == 1) j.vpbroadcastw(s1, x86::eax);
			else if (ins->sew_bytes == 2) j.vpbroadcastd(s1, x86::eax);
			else j.vpbroadcastq(s1, x86::rax);
		}
		EvexOnly(j);
		j.emit(ins->sew_bytes == 1 ? x86::Inst::kIdVpmullw : ins->sew_bytes == 2 ? x86::Inst::kIdVpmulld : x86::Inst::kIdVpmullq, s0, s0, s1);
		if (fractional) {
			u32 const bits=ins->sew_bytes*16,shift=ins->sew_bytes*8-1;
			auto pick=[&](u32 w,u32 d,u32 q){return bits==16?w:bits==32?d:q;};
			u32 const left=pick(x86::Inst::kIdVpsllw,x86::Inst::kIdVpslld,x86::Inst::kIdVpsllq);
			u32 const signs=pick(x86::Inst::kIdVpmovw2m,x86::Inst::kIdVpmovd2m,x86::Inst::kIdVpmovq2m);
			EvexOnly(j);j.emit(left,s1,s0,bits-shift);
			EvexOnly(j);j.emit(signs,x86::k2,s1);
			EvexOnly(j);j.emit(left,s1,s0,bits-shift+1);
			EvexOnly(j);j.emit(pick(x86::Inst::kIdVptestmw,x86::Inst::kIdVptestmd,x86::Inst::kIdVptestmq),x86::k3,s1,s1);
			EvexOnly(j);j.emit(pick(x86::Inst::kIdVpsraw,x86::Inst::kIdVpsrad,x86::Inst::kIdVpsraq),s0,s0,shift);
			EvexOnly(j);j.emit(left,s1,s0,bits-1);
			EvexOnly(j);j.emit(signs,x86::k4,s1);
			j.mov(x86::eax,x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vxrm)));
			j.and_(x86::eax,3);
			auto ready=j.newLabel(),even=j.newLabel(),truncate=j.newLabel();
			j.test(x86::eax,x86::eax);j.jz(ready);j.cmp(x86::eax,2);j.je(truncate);j.cmp(x86::eax,1);j.je(even);
			j.korq(x86::k2,x86::k2,x86::k3);j.knotq(x86::k4,x86::k4);j.kandq(x86::k2,x86::k2,x86::k4);j.jmp(ready);
			j.bind(even);j.korq(x86::k3,x86::k3,x86::k4);j.kandq(x86::k2,x86::k2,x86::k3);j.jmp(ready);
			j.bind(truncate);j.kxorq(x86::k2,x86::k2,x86::k2);j.bind(ready);
			auto broadcast=[&](u64 v) {
				j.mov(x86::rax,v);EvexOnly(j);
				j.emit(pick(x86::Inst::kIdVpbroadcastw,x86::Inst::kIdVpbroadcastd,x86::Inst::kIdVpbroadcastq),
					s1,bits==64?x86::Gp(x86::rax):x86::Gp(x86::eax));
			};
			broadcast(1);
			EvexOnly(j);j.k(x86::k2).emit(pick(x86::Inst::kIdVpaddw,x86::Inst::kIdVpaddd,x86::Inst::kIdVpaddq),s0,s0,s1);
			broadcast((u64(1)<<shift)-1);
			EvexOnly(j);j.emit(pick(x86::Inst::kIdVpcmpw,x86::Inst::kIdVpcmpd,x86::Inst::kIdVpcmpq),x86::k2,s0,s1,6);
			EvexOnly(j);j.k(x86::k2).emit(pick(x86::Inst::kIdVmovdqu16,x86::Inst::kIdVmovdqu32,x86::Inst::kIdVmovdqu64),s0,s1);
			j.kmovq(x86::rax,x86::k2);j.and_(x86::rax,x86::rdi);j.setne(x86::al);j.movzx(x86::eax,x86::al);
			j.or_(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vxsat)),x86::eax);
			EvexOnly(j);j.k(k).emit(pick(x86::Inst::kIdVpmovwb,x86::Inst::kIdVpmovdw,x86::Inst::kIdVpmovqd),
				x86::ptr(R_STATE,ins->rd_offs,bytes),s0);
			if(finish_instruction)j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)),0);
			return;
		}
		EvexOnly(j);
		j.emit(ins->sew_bytes == 1 ? x86::Inst::kIdVpsrlw : ins->sew_bytes == 2 ? x86::Inst::kIdVpsrld : x86::Inst::kIdVpsrlq, s0, s0, 8 * ins->sew_bytes);
		EvexOnly(j);
		j.k(k).emit(ins->sew_bytes == 1 ? x86::Inst::kIdVpmovwb : ins->sew_bytes == 2 ? x86::Inst::kIdVpmovdw : x86::Inst::kIdVpmovqd,
			x86::ptr(R_STATE, ins->rd_offs, bytes), s0);
		if (finish_instruction)
			j.mov(x86::dword_ptr(R_STATE, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart)), 0);
		return;
	}
	bool const is_mov = (Kind)ins->op == Kind::Mov; // A7: no vs2, s1 is stored as-is
	auto load_left = [&](x86::Vec dst, bool sign) {
		EvexOnly(j);
		auto const mem = x86::ptr(R_STATE, (int32_t)(dest_multiplicand ? ins->rd_offs : ins->rs2_offs), bytes);
		if (widen_bytes && sign) j.vpmovsxbw(dst, mem);
		else if (widen_bytes) j.vpmovzxbw(dst, mem);
		else j.vmovdqu64(dst, mem);
	};
	if (!is_mov) load_left(s0, op == Kind::Sra);
	// A6: source 1 by kind. The Vector kind is the A3 node unchanged; GprWord splats the GPR
	// slot with the memory-operand vpbroadcastd; Imm materialises the constant in the fixed
	// scratch GPR (ArchTraits::AX) exactly as the immediate vchunkbroadcast does.
	auto load_right = [&]() {
	switch ((Src1)ins->src1_kind) {
	case Src1::FprBoxed:
		j.mov(x86::rax, x86::qword_ptr(R_STATE, ins->rs1_offs));
		if (ins->sew_bytes == 4) {
			auto boxed = j.newLabel();
			j.mov(x86::rdx, x86::rax); j.shr(x86::rdx, 32);
			j.cmp(x86::edx, -1); j.je(boxed);
			j.mov(x86::eax, 0x7fc00000u); j.bind(boxed);
			EvexOnly(j); j.vpbroadcastd(s1, x86::eax);
		} else { EvexOnly(j); j.vpbroadcastq(s1, x86::rax); }
		break;
	case Src1::Vector:
		EvexOnly(j);
		if (clip) j.emit(ins->sew_bytes == 2 ? x86::Inst::kIdVpmovzxbw :
			ins->sew_bytes == 4 ? x86::Inst::kIdVpmovzxwd : x86::Inst::kIdVpmovzxdq,
			s1, x86::ptr(R_STATE, ins->rs1_offs, bytes / 2));
		else if (widen_bytes) j.vpmovzxbw(s1, x86::ptr(R_STATE, (int32_t)ins->rs1_offs, bytes));
		else j.vmovdqu64(s1, x86::ptr(R_STATE, (int32_t)ins->rs1_offs, bytes));
		break;
	case Src1::GprWord:
		if (ins->sew_bytes == 4) {
			EvexOnly(j);
			j.vpbroadcastd(s1, x86::ptr(R_STATE, (int32_t)ins->rs1_offs, 4));
		} else {
			j.movsxd(x86::rax, x86::dword_ptr(R_STATE, (int32_t)ins->rs1_offs));
			EvexOnly(j);
			if (widen_bytes) j.vpbroadcastw(s1, x86::eax);
			else if (ins->sew_bytes == 1) j.vpbroadcastb(s1, x86::eax);
			else if (ins->sew_bytes == 2) j.vpbroadcastw(s1, x86::eax);
			else j.vpbroadcastq(s1, x86::rax);
		}
		break;
	case Src1::Imm: {
		auto const scratch32 = make_gpr(ArchTraits::AX, qir::VType::I32);
		if (ins->sew_bytes == 8) j.mov(x86::rax, (uint64_t)(int64_t)(int32_t)ins->imm);
		else j.mov(scratch32, (int32_t)ins->imm);
		EvexOnly(j);
		if (widen_bytes) j.vpbroadcastw(s1, scratch32);
		else if (ins->sew_bytes == 1) j.vpbroadcastb(s1, scratch32);
		else if (ins->sew_bytes == 2) j.vpbroadcastw(s1, scratch32);
		else if (ins->sew_bytes == 4) j.vpbroadcastd(s1, scratch32);
		else j.vpbroadcastq(s1, x86::rax);
		break;
	}
	default:
		Panic("qemit: vchunkpartialalu with an unsupported source-1 kind");
	}
	};
	load_right();
	auto const element_op = [&](uint32_t b, uint32_t w, uint32_t d, uint32_t q) {
		return ins->sew_bytes == 1 ? b : ins->sew_bytes == 2 ? w : ins->sew_bytes == 4 ? d : q;
	};
	if (round_shift) {
		if (!ins->architectural_mask) Panic("qemit: rounding shift requires architectural mask");
		bool const arith = op == Kind::RoundSra || op == Kind::ClipS;
		u32 const bits = widen_bytes ? 16 : ins->sew_bytes * 8;
		u32 const keep = ins->sew_bytes == 1 ? 3 : ins->sew_bytes == 2 ? 4 : ins->sew_bytes == 4 ? 5 : 6;
		u32 const left = element_op(x86::Inst::kIdVpsllw,x86::Inst::kIdVpsllw,x86::Inst::kIdVpslld,x86::Inst::kIdVpsllq);
		u32 const right = element_op(x86::Inst::kIdVpsrlw,x86::Inst::kIdVpsrlw,x86::Inst::kIdVpsrld,x86::Inst::kIdVpsrlq);
		u32 const logical = element_op(x86::Inst::kIdVpsrlvw,x86::Inst::kIdVpsrlvw,x86::Inst::kIdVpsrlvd,x86::Inst::kIdVpsrlvq);
		u32 const variable_left = element_op(x86::Inst::kIdVpsllvw,x86::Inst::kIdVpsllvw,x86::Inst::kIdVpsllvd,x86::Inst::kIdVpsllvq);
		u32 const signs = element_op(x86::Inst::kIdVpmovw2m,x86::Inst::kIdVpmovw2m,x86::Inst::kIdVpmovd2m,x86::Inst::kIdVpmovq2m);
		u32 const add = element_op(x86::Inst::kIdVpaddw,x86::Inst::kIdVpaddw,x86::Inst::kIdVpaddd,x86::Inst::kIdVpaddq);
		auto normalize = [&]() {
			EvexOnly(j); j.emit(left,s1,s1,bits-keep);
			EvexOnly(j); j.emit(right,s1,s1,bits-keep);
		};
		normalize();
		EvexOnly(j); j.vpternlogd(s0,s0,s0,255);
		EvexOnly(j); j.emit(add,s1,s1,s0); // count-1; zero underflows to an oversized x86 shift.
		load_left(s0,false);
		EvexOnly(j); j.emit(logical,s0,s0,s1);
		EvexOnly(j); j.emit(left,s0,s0,bits-1);
		EvexOnly(j); j.emit(signs,x86::k2,s0); // highest discarded bit
		load_left(s0,false);
		EvexOnly(j); j.emit(logical,s0,s0,s1);
		EvexOnly(j); j.emit(variable_left,s0,s0,s1);
		load_left(s1,false);
		EvexOnly(j); j.emit(element_op(x86::Inst::kIdVpcmpuw,x86::Inst::kIdVpcmpuw,
			x86::Inst::kIdVpcmpud,x86::Inst::kIdVpcmpuq),x86::k3,s0,s1,4); // any lower discarded bit
		load_right(); normalize(); load_left(s0,arith);
		EvexOnly(j); j.emit(arith ? element_op(x86::Inst::kIdVpsravw,x86::Inst::kIdVpsravw,
			x86::Inst::kIdVpsravd,x86::Inst::kIdVpsravq) : logical,s0,s0,s1);
		EvexOnly(j); j.emit(left,s1,s0,bits-1);
		EvexOnly(j); j.emit(signs,x86::k4,s1); // retained low bit
		j.mov(x86::eax,x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vxrm)));
		j.and_(x86::eax,3);
		auto ready=j.newLabel(),even=j.newLabel(),truncate=j.newLabel();
		j.test(x86::eax,x86::eax);j.jz(ready);
		j.cmp(x86::eax,2);j.je(truncate);
		j.cmp(x86::eax,1);j.je(even);
		j.korq(x86::k2,x86::k2,x86::k3);j.knotq(x86::k4,x86::k4);
		j.kandq(x86::k2,x86::k2,x86::k4);j.jmp(ready);
		j.bind(even);j.korq(x86::k3,x86::k3,x86::k4);j.kandq(x86::k2,x86::k2,x86::k3);j.jmp(ready);
		j.bind(truncate);j.kxorq(x86::k2,x86::k2,x86::k2);
		j.bind(ready);
		// A zero shift discards no bits, including in round-to-odd mode.
		load_right(); normalize();
		EvexOnly(j); j.emit(element_op(x86::Inst::kIdVptestmw,x86::Inst::kIdVptestmw,
			x86::Inst::kIdVptestmd,x86::Inst::kIdVptestmq),x86::k3,s1,s1);
		j.kandq(x86::k2,x86::k2,x86::k3);
		j.mov(x86::eax,1);
		EvexOnly(j);j.emit(element_op(x86::Inst::kIdVpbroadcastw,x86::Inst::kIdVpbroadcastw,
			x86::Inst::kIdVpbroadcastd,x86::Inst::kIdVpbroadcastq),s1,bits==64?x86::Gp(x86::rax):x86::Gp(x86::eax));
		EvexOnly(j);j.k(x86::k2).emit(add,s0,s0,s1);
		if (clip) {
			u32 const dest_bits = bits / 2;
			u32 const move = element_op(x86::Inst::kIdVmovdqu16,x86::Inst::kIdVmovdqu16,
				x86::Inst::kIdVmovdqu32,x86::Inst::kIdVmovdqu64);
			u32 const compare = arith ? element_op(x86::Inst::kIdVpcmpw,x86::Inst::kIdVpcmpw,
				x86::Inst::kIdVpcmpd,x86::Inst::kIdVpcmpq) : element_op(x86::Inst::kIdVpcmpuw,
				x86::Inst::kIdVpcmpuw,x86::Inst::kIdVpcmpud,x86::Inst::kIdVpcmpuq);
			auto bound = [&](u64 value) {
				j.mov(x86::rax,value);
				EvexOnly(j);j.emit(element_op(x86::Inst::kIdVpbroadcastw,x86::Inst::kIdVpbroadcastw,
					x86::Inst::kIdVpbroadcastd,x86::Inst::kIdVpbroadcastq),s1,
					bits==64?x86::Gp(x86::rax):x86::Gp(x86::eax));
			};
			bound((u64(1) << (arith ? dest_bits-1 : dest_bits))-1);
			EvexOnly(j);j.emit(compare,x86::k2,s0,s1,6);
			EvexOnly(j);j.k(x86::k2).emit(move,s0,s1);
			if (arith) {
				bound(u64(0)-(u64(1)<<(dest_bits-1)));
				EvexOnly(j);j.emit(compare,x86::k3,s0,s1,1);
				EvexOnly(j);j.k(x86::k3).emit(move,s0,s1);
				j.korq(x86::k2,x86::k2,x86::k3);
			}
			j.kmovq(x86::rax,x86::k2);j.and_(x86::rax,x86::rdi);
			j.setne(x86::al);j.movzx(x86::eax,x86::al);
			j.or_(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vxsat)),x86::eax);
			EvexOnly(j);j.k(k).emit(ins->sew_bytes==2?x86::Inst::kIdVpmovwb:
				ins->sew_bytes==4?x86::Inst::kIdVpmovdw:x86::Inst::kIdVpmovqd,
				x86::ptr(R_STATE,ins->rd_offs,bytes/2),s0);
			if(finish_instruction)
				j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)),0);
			return;
		}
		EvexOnly(j);j.k(k).emit(element_op(x86::Inst::kIdVpmovwb,x86::Inst::kIdVmovdqu16,
			x86::Inst::kIdVmovdqu32,x86::Inst::kIdVmovdqu64),x86::ptr(R_STATE,ins->rd_offs,bytes),s0);
		if(finish_instruction)
			j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)),0);
		return;
	}
	if (op >= Kind::AvgAddU && op <= Kind::AvgSubS) {
		if (!ins->architectural_mask) Panic("qemit: averaging requires architectural mask");
		bool const sign = op == Kind::AvgAddS || op == Kind::AvgSubS;
		bool const sub = op == Kind::AvgSubU || op == Kind::AvgSubS;
		u32 const bits = ins->sew_bytes * 8;
		u32 const signs = element_op(x86::Inst::kIdVpmovb2m, x86::Inst::kIdVpmovw2m,
			x86::Inst::kIdVpmovd2m, x86::Inst::kIdVpmovq2m);
		u32 const cmp = element_op(x86::Inst::kIdVpcmpub, x86::Inst::kIdVpcmpuw,
			x86::Inst::kIdVpcmpud, x86::Inst::kIdVpcmpuq);
		u32 const add = element_op(x86::Inst::kIdVpaddb, x86::Inst::kIdVpaddw,
			x86::Inst::kIdVpaddd, x86::Inst::kIdVpaddq);
		u32 const left = element_op(x86::Inst::kIdVpsllw, x86::Inst::kIdVpsllw,
			x86::Inst::kIdVpslld, x86::Inst::kIdVpsllq);
		auto broadcast = [&](u64 value) {
			j.mov(x86::rax, value);
			EvexOnly(j); j.emit(element_op(x86::Inst::kIdVpbroadcastb, x86::Inst::kIdVpbroadcastw,
				x86::Inst::kIdVpbroadcastd, x86::Inst::kIdVpbroadcastq), s1,
				ins->sew_bytes == 8 ? x86::Gp(x86::rax) : x86::Gp(x86::eax));
		};
		// Preserve bit SEW of the full sum/difference in k3 before shifting the
		// wrapped SIMD result. This avoids both widening temporaries and e64 overflow.
		if (sign) {
			EvexOnly(j); j.emit(signs, x86::k2, s0);
			EvexOnly(j); j.emit(signs, x86::k3, s1);
		} else if (sub) { EvexOnly(j); j.emit(cmp, x86::k3, s0, s1, 1); }
		EvexOnly(j); j.emit(sub ? element_op(x86::Inst::kIdVpsubb, x86::Inst::kIdVpsubw,
			x86::Inst::kIdVpsubd, x86::Inst::kIdVpsubq) : add, s0, s0, s1);
		if (sign) {
			EvexOnly(j); j.emit(signs, x86::k4, s0);
			j.kxorq(x86::k3, x86::k3, x86::k2);
			if (!sub) j.knotq(x86::k3, x86::k3);
			j.kxorq(x86::k2, x86::k2, x86::k4);
			j.kandq(x86::k3, x86::k3, x86::k2);
			j.kxorq(x86::k3, x86::k3, x86::k4);
		} else if (!sub) {
			EvexOnly(j); j.emit(cmp, x86::k3, s0, x86::ptr(R_STATE, ins->rs2_offs, bytes), 1);
		}
		EvexOnly(j); j.emit(left, s1, s0, bits - 1);
		EvexOnly(j); j.emit(signs, x86::k2, s1);
		EvexOnly(j); j.emit(left, s1, s0, bits - 2);
		EvexOnly(j); j.emit(signs, x86::k4, s1);
		// Shift-by-one rounding: rnu=b0, rne=b0&b1, rdn=0, rod=b0&~b1.
		j.kmovq(x86::rax, x86::k2); j.kmovq(x86::rsi, x86::k4);
		j.mov(x86::edx, x86::dword_ptr(R_STATE, offsetof(CPUState,vec)+offsetof(rv32::VectorState,vxrm)));
		j.and_(x86::edx, 3);
		auto rounded = j.newLabel(), even = j.newLabel(), truncate = j.newLabel();
		j.test(x86::edx, x86::edx); j.jz(rounded);
		j.cmp(x86::edx, 2); j.je(truncate);
		j.cmp(x86::edx, 1); j.je(even);
		j.not_(x86::rsi);
		j.bind(even); j.and_(x86::rax, x86::rsi); j.jmp(rounded);
		j.bind(truncate); j.xor_(x86::eax, x86::eax);
		j.bind(rounded); j.kmovq(x86::k2, x86::rax);
		EvexOnly(j); j.emit(element_op(x86::Inst::kIdVpsrlw, x86::Inst::kIdVpsrlw,
			x86::Inst::kIdVpsrld, x86::Inst::kIdVpsrlq), s0, s0, 1);
		broadcast(u64(1) << (bits - 1));
		EvexOnly(j); j.vpandnd(s0, s1, s0); // Also removes cross-byte shift contamination.
		EvexOnly(j); j.k(x86::k3).emit(add, s0, s0, s1);
		broadcast(1);
		EvexOnly(j); j.k(x86::k2).emit(add, s0, s0, s1);
		EvexOnly(j); j.k(k).emit(element_op(x86::Inst::kIdVmovdqu8, x86::Inst::kIdVmovdqu16,
			x86::Inst::kIdVmovdqu32, x86::Inst::kIdVmovdqu64), x86::ptr(R_STATE, ins->rd_offs, bytes), s0);
		if (finish_instruction)
			j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)),0);
		return;
	}
	if (op >= Kind::SatAddU && op <= Kind::SatSubS) {
		if (!ins->architectural_mask) Panic("qemit: saturation requires architectural mask");
		bool const sign = op == Kind::SatAddS || op == Kind::SatSubS;
		bool const sub = op == Kind::SatSubU || op == Kind::SatSubS;
		u32 const signs = element_op(x86::Inst::kIdVpmovb2m,x86::Inst::kIdVpmovw2m,x86::Inst::kIdVpmovd2m,x86::Inst::kIdVpmovq2m);
		u32 const cmp = element_op(x86::Inst::kIdVpcmpub,x86::Inst::kIdVpcmpuw,x86::Inst::kIdVpcmpud,x86::Inst::kIdVpcmpuq);
		if (sign) {
			EvexOnly(j); j.emit(signs,x86::k2,s0);
			EvexOnly(j); j.emit(signs,x86::k3,s1);
		} else if (sub) { EvexOnly(j); j.emit(cmp,x86::k3,s0,s1,1); }
		EvexOnly(j);
		j.emit(sub ? element_op(x86::Inst::kIdVpsubb,x86::Inst::kIdVpsubw,x86::Inst::kIdVpsubd,x86::Inst::kIdVpsubq) :
			element_op(x86::Inst::kIdVpaddb,x86::Inst::kIdVpaddw,x86::Inst::kIdVpaddd,x86::Inst::kIdVpaddq),s0,s0,s1);
		if (sign) {
			EvexOnly(j); j.emit(signs,x86::k4,s0);
			j.kxorq(x86::k3,x86::k3,x86::k2);
			if (!sub) j.knotq(x86::k3,x86::k3);
			j.kxorq(x86::k4,x86::k4,x86::k2);
			j.kandq(x86::k3,x86::k3,x86::k4);
		} else if (!sub) {
			EvexOnly(j); j.emit(cmp,x86::k3,s0,x86::ptr(R_STATE,ins->rs2_offs,bytes),1);
		}
		// Only active overflow lanes set the sticky flag; inactive/tail/prestart do not.
		j.kmovq(x86::rax,x86::k3); j.and_(x86::rax,x86::rdi);
		j.setne(x86::al); j.movzx(x86::eax,x86::al);
		j.or_(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vxsat)),x86::eax);
		if (sign && ins->sew_bytes <= 2) {
			// x86 has packed signed saturation for bytes/words. Reload the original left
			// operand after detecting overflow; both scratch operands are still available.
			EvexOnly(j); j.vmovdqu64(s0,x86::ptr(R_STATE,ins->rs2_offs,bytes));
			EvexOnly(j); j.emit(ins->sew_bytes == 1 ? (sub ? x86::Inst::kIdVpsubsb : x86::Inst::kIdVpaddsb) :
				(sub ? x86::Inst::kIdVpsubsw : x86::Inst::kIdVpaddsw),s0,s0,s1);
		} else {
			EvexOnly(j); j.vpternlogd(s1,s1,s1,(!sign && sub) ? 0 : 255);
			if (sign) {
				// MAX for positive overflow, MIN for negative overflow; no third vector temporary.
				EvexOnly(j); j.emit(ins->sew_bytes == 4 ? x86::Inst::kIdVpsrld : x86::Inst::kIdVpsrlq,s1,s1,1);
				EvexOnly(j); j.k(x86::k2).emit(ins->sew_bytes == 4 ? x86::Inst::kIdVpslld : x86::Inst::kIdVpsllq,
					s1,s1,ins->sew_bytes*8-1);
			}
			EvexOnly(j); j.k(x86::k3).emit(element_op(x86::Inst::kIdVmovdqu8,x86::Inst::kIdVmovdqu16,
				x86::Inst::kIdVmovdqu32,x86::Inst::kIdVmovdqu64),s0,s1);
		}
		EvexOnly(j); j.k(k).emit(element_op(x86::Inst::kIdVmovdqu8,x86::Inst::kIdVmovdqu16,
			x86::Inst::kIdVmovdqu32,x86::Inst::kIdVmovdqu64),x86::ptr(R_STATE,ins->rd_offs,bytes),s0);
		if (finish_instruction)
			j.mov(x86::dword_ptr(R_STATE,offsetof(CPUState,vec)+offsetof(rv32::VectorState,vstart)),0);
		return;
	}
	if (shift) {
		// RVV masks the shift count modulo SEW; x86 saturates oversized counts.
		// Keep the low log2(SEW) count bits without consuming another vector register.
		u32 const keep = ins->sew_bytes == 1 ? 3 : ins->sew_bytes == 2 ? 4 : ins->sew_bytes == 4 ? 5 : 6;
		u32 const bits = widen_bytes ? 16 : 8 * ins->sew_bytes;
		EvexOnly(j);
		j.emit(element_op(x86::Inst::kIdVpsllw, x86::Inst::kIdVpsllw,
				  x86::Inst::kIdVpslld, x86::Inst::kIdVpsllq), s1, s1, bits - keep);
		EvexOnly(j);
		j.emit(element_op(x86::Inst::kIdVpsrlw, x86::Inst::kIdVpsrlw,
				  x86::Inst::kIdVpsrld, x86::Inst::kIdVpsrlq), s1, s1, bits - keep);
	}
	EvexOnly(j);
	switch ((Kind)ins->op) {
	case Kind::Add:
		j.emit(element_op(x86::Inst::kIdVpaddb, x86::Inst::kIdVpaddw,
				  x86::Inst::kIdVpaddd, x86::Inst::kIdVpaddq), s0, s0, s1); break;
	case Kind::Sub: case Kind::RSub:
		j.emit(element_op(x86::Inst::kIdVpsubb, x86::Inst::kIdVpsubw,
				  x86::Inst::kIdVpsubd, x86::Inst::kIdVpsubq), s0,
		       (Kind)ins->op == Kind::Sub ? s0 : s1,
		       (Kind)ins->op == Kind::Sub ? s1 : s0); break;
	case Kind::Mul:
		j.emit(element_op(x86::Inst::kIdVpmullw, x86::Inst::kIdVpmullw,
				  x86::Inst::kIdVpmulld, x86::Inst::kIdVpmullq), s0, s0, s1); break;
	case Kind::Macc: case Kind::Nmsac: case Kind::Madd: case Kind::Nmsub: {
		j.emit(element_op(x86::Inst::kIdVpmullw, x86::Inst::kIdVpmullw,
				  x86::Inst::kIdVpmulld, x86::Inst::kIdVpmullq), s0, s0, s1);
		// Product no longer needs source 1. Reuse that scratch for the old addend,
		// before any destination write, including vd==vs1 or vd==vs2.
		auto const addend = x86::ptr(R_STATE, (int32_t)(dest_multiplicand ? ins->rs2_offs : ins->rd_offs), bytes);
		EvexOnly(j);
		if (widen_bytes) j.vpmovzxbw(s1, addend);
		else j.vmovdqu64(s1, addend);
		EvexOnly(j);
		bool const subtract = op == Kind::Nmsac || op == Kind::Nmsub;
		j.emit(subtract ? element_op(x86::Inst::kIdVpsubw, x86::Inst::kIdVpsubw,
					    x86::Inst::kIdVpsubd, x86::Inst::kIdVpsubq)
				: element_op(x86::Inst::kIdVpaddw, x86::Inst::kIdVpaddw,
					    x86::Inst::kIdVpaddd, x86::Inst::kIdVpaddq), s0, s1, s0);
		break;
	}
	case Kind::And: j.vpandd(s0, s0, s1); break;
	case Kind::Or: j.vpord(s0, s0, s1); break;
	case Kind::Xor: j.vpxord(s0, s0, s1); break;
	case Kind::MinU:
		j.emit(element_op(x86::Inst::kIdVpminub, x86::Inst::kIdVpminuw,
				  x86::Inst::kIdVpminud, x86::Inst::kIdVpminuq), s0, s0, s1); break;
	case Kind::MinS:
		j.emit(element_op(x86::Inst::kIdVpminsb, x86::Inst::kIdVpminsw,
				  x86::Inst::kIdVpminsd, x86::Inst::kIdVpminsq), s0, s0, s1); break;
	case Kind::MaxU:
		j.emit(element_op(x86::Inst::kIdVpmaxub, x86::Inst::kIdVpmaxuw,
				  x86::Inst::kIdVpmaxud, x86::Inst::kIdVpmaxuq), s0, s0, s1); break;
	case Kind::MaxS:
		j.emit(element_op(x86::Inst::kIdVpmaxsb, x86::Inst::kIdVpmaxsw,
				  x86::Inst::kIdVpmaxsd, x86::Inst::kIdVpmaxsq), s0, s0, s1); break;
	case Kind::Sll:
		j.emit(element_op(x86::Inst::kIdVpsllvw, x86::Inst::kIdVpsllvw,
				  x86::Inst::kIdVpsllvd, x86::Inst::kIdVpsllvq), s0, s0, s1); break;
	case Kind::Srl:
		j.emit(element_op(x86::Inst::kIdVpsrlvw, x86::Inst::kIdVpsrlvw,
				  x86::Inst::kIdVpsrlvd, x86::Inst::kIdVpsrlvq), s0, s0, s1); break;
	case Kind::Sra:
		j.emit(element_op(x86::Inst::kIdVpsravw, x86::Inst::kIdVpsravw,
				  x86::Inst::kIdVpsravd, x86::Inst::kIdVpsravq), s0, s0, s1); break;
	case Kind::Mov: break;
	case Kind::Adc: case Kind::Sbc: case Kind::Madc: case Kind::Msbc: {
		if (!ins->architectural_mask) Panic("qemit: carry operation needs architectural body mask");
		// The RVV vm bit selects a carry input, never suppresses a body write.
		if (ins->masked) {
			u32 const mo = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg) + ins->element_base / 8;
			j.mov(x86::rcx, x86::qword_ptr(R_STATE, mo));
			if (ins->element_base % 8) j.shr(x86::rcx, ins->element_base % 8);
		} else j.xor_(x86::ecx, x86::ecx);
		j.kmovq(x86::k2, x86::rcx);
		if (op != Kind::Msbc) {
			EvexOnly(j);
			j.emit(op == Kind::Sbc ? element_op(x86::Inst::kIdVpsubb, x86::Inst::kIdVpsubw,
					x86::Inst::kIdVpsubd, x86::Inst::kIdVpsubq)
				: element_op(x86::Inst::kIdVpaddb, x86::Inst::kIdVpaddw,
					x86::Inst::kIdVpaddd, x86::Inst::kIdVpaddq), s0, s0, s1);
			if (ins->masked) {
				j.mov(x86::eax, 1); EvexOnly(j);
				j.emit(element_op(x86::Inst::kIdVpbroadcastb, x86::Inst::kIdVpbroadcastw,
					x86::Inst::kIdVpbroadcastd, x86::Inst::kIdVpbroadcastq), s1,
					ins->sew_bytes == 8 ? x86::Gp(x86::rax) : x86::Gp(x86::eax));
				EvexOnly(j);
				j.k(x86::k2).emit(op == Kind::Sbc ? element_op(x86::Inst::kIdVpsubb, x86::Inst::kIdVpsubw,
						x86::Inst::kIdVpsubd, x86::Inst::kIdVpsubq)
					: element_op(x86::Inst::kIdVpaddb, x86::Inst::kIdVpaddw,
						x86::Inst::kIdVpaddd, x86::Inst::kIdVpaddq), s0, s0, s1);
			}
		}
		if (compare) {
			// Add: final_sum < original_a, or equal with carry-in. Sub: a < b,
			// or equal with borrow-in. Unsigned comparisons work at every SEW.
			if (op == Kind::Madc) { EvexOnly(j); j.vmovdqu64(s1, x86::ptr(R_STATE, ins->rs2_offs, bytes)); }
			u32 const cmp = element_op(x86::Inst::kIdVpcmpub, x86::Inst::kIdVpcmpuw,
				x86::Inst::kIdVpcmpud, x86::Inst::kIdVpcmpuq);
			EvexOnly(j); j.emit(cmp, x86::k3, s0, s1, 1);
			EvexOnly(j); j.emit(cmp, x86::k4, s0, s1, 0);
			j.kmovq(x86::rax, x86::k3); j.kmovq(x86::rdx, x86::k4);
			j.and_(x86::rdx, x86::rcx); j.or_(x86::rax, x86::rdx); j.kmovq(x86::k2, x86::rax);
		}
		break;
	}
	case Kind::Merge: {
		// vmerge selects on v0 but writes every body element, including v0=0 lanes.
		u32 const mo = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg) + ins->element_base / 8u;
		j.mov(x86::rax, x86::qword_ptr(R_STATE, mo));
		if (ins->element_base % 8u) j.shr(x86::rax, ins->element_base % 8u);
		j.kmovq(x86::k2, x86::rax);
		EvexOnly(j);
		j.k(x86::k2).emit(element_op(x86::Inst::kIdVpblendmb, x86::Inst::kIdVpblendmw,
					   x86::Inst::kIdVpblendmd, x86::Inst::kIdVpblendmq), s0, s0, s1);
		break;
	}
	case Kind::Eq: case Kind::Ne: case Kind::LtU: case Kind::LtS:
	case Kind::LeU: case Kind::LeS: case Kind::GtU: case Kind::GtS: {
		if (!ins->architectural_mask) Panic("qemit: mask result needs architectural write mask");
		bool const sign = op == Kind::LtS || op == Kind::LeS || op == Kind::GtS;
		u32 const pred = op == Kind::Eq ? 0 : op == Kind::Ne ? 4 :
			(op == Kind::LtU || op == Kind::LtS) ? 1 : (op == Kind::LeU || op == Kind::LeS) ? 2 : 6;
		j.emit(sign ? element_op(x86::Inst::kIdVpcmpb, x86::Inst::kIdVpcmpw,
					 x86::Inst::kIdVpcmpd, x86::Inst::kIdVpcmpq)
			    : element_op(x86::Inst::kIdVpcmpub, x86::Inst::kIdVpcmpuw,
					 x86::Inst::kIdVpcmpud, x86::Inst::kIdVpcmpuq), x86::k2, s0, s1, pred);
		break;
	}
	default: Panic("qemit: vchunkpartialalu with an unsupported opcode");
	}
	if (compare) {
		u32 const bit = ins->element_base % 8u, off = ins->rd_offs + ins->element_base / 8u;
		u32 const bits = bit + bytes / ins->sew_bytes;
		u32 const mask_bytes = bits <= 8 ? 1 : bits <= 16 ? 2 : bits <= 32 ? 4 : 8;
		if (bits > 64 || off + mask_bytes > sizeof(CPUState)) Panic("qemit: mask destination out of state");
		auto store_mask = [&]() {
			if (mask_bytes == 1) {
				j.kmovq(x86::rax, x86::k2); j.mov(x86::byte_ptr(R_STATE, off), x86::al);
			} else if (mask_bytes == 2) j.kmovw(x86::word_ptr(R_STATE, off), x86::k2);
			else if (mask_bytes == 4) j.kmovd(x86::dword_ptr(R_STATE, off), x86::k2);
			else j.kmovq(x86::qword_ptr(R_STATE, off), x86::k2);
		};
		if (overwrite_mask) {
			store_mask();
		} else {
			auto merge = j.newLabel(), done = j.newLabel();
			bool const byte_aligned = bit == 0 && bits == mask_bytes * 8;
			if (byte_aligned) {
				// The runtime mask can prove complete overwrite too, without
				// cloning the arithmetic body or specializing a guest PC.
				if (bits == 32) {
					j.mov(x86::edx, 0xffffffffu); j.cmp(x86::rdi, x86::rdx);
				} else j.cmp(x86::rdi, bits == 64 ? int64_t(-1) : int64_t((u64(1) << bits) - 1));
				j.jne(merge); store_mask(); j.jmp(done); j.bind(merge);
			}
			j.kmovq(x86::rax, x86::k2); j.and_(x86::rax, x86::rdi);
			if (bit) { j.shl(x86::rax, bit); j.shl(x86::rdi, bit); }
			// Preserve prestart, inactive and tail bits, including future v0 inputs.
			if (mask_bytes == 1) j.movzx(x86::edx, x86::byte_ptr(R_STATE, off));
			else if (mask_bytes == 2) j.movzx(x86::edx, x86::word_ptr(R_STATE, off));
			else if (mask_bytes == 4) j.mov(x86::edx, x86::dword_ptr(R_STATE, off));
			else j.mov(x86::rdx, x86::qword_ptr(R_STATE, off));
			j.not_(x86::rdi); j.and_(x86::rdx, x86::rdi); j.or_(x86::rax, x86::rdx);
			if (mask_bytes == 1) j.mov(x86::byte_ptr(R_STATE, off), x86::al);
			else if (mask_bytes == 2) j.mov(x86::word_ptr(R_STATE, off), x86::ax);
			else if (mask_bytes == 4) j.mov(x86::dword_ptr(R_STATE, off), x86::eax);
			else j.mov(x86::qword_ptr(R_STATE, off), x86::rax);
			if (byte_aligned) j.bind(done);
		}
	}
	if (!compare) {
		EvexOnly(j);
		if (widen_bytes) j.k(k).vpmovwb(x86::ptr(R_STATE, (int32_t)ins->rd_offs, bytes), s0);
		else j.k(k).emit(element_op(x86::Inst::kIdVmovdqu8, x86::Inst::kIdVmovdqu16,
			      x86::Inst::kIdVmovdqu32, x86::Inst::kIdVmovdqu64),
		    x86::ptr(R_STATE, (int32_t)ins->rd_offs, bytes), is_mov ? s1 : s0);
	}
	if (finish_instruction)
		j.mov(x86::dword_ptr(R_STATE, offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart)), 0);
}

void QEmit::Emit_vchunkload(qir::InstVChunkLoad *ins)
{
	// Accounted like every other typed body op, so `end`'s shape check covers the whole frame.
	// Outside a group rvv_typed_chunk_open is false and this adds nothing, which is why the
	// unrouted mechanism-test callers are unaffected.
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto vrd = ins->o(0);
	assert_pvpr(vrd);
	// P7N-D: the store's derivation, applied to the load's destination for the same reason -- the
	// width read must be the width of the value it is read into, not a literal. S1 (2026-09-05)
	// admits the narrow vle32.v shapes (RvvVleChunkShape now carries RvvRouteChunkShape), so this
	// is 16/32/64 according to the destination's type, exactly as the store side.
	u32 const load_bytes = qir::VTypeToSize(vrd.GetType()); // VTypeToSize is in BYTES

	if (ins->base_state_offs == qir::InstVChunkLoad::NO_STATE_BASE) {
		auto mem = make_vmem(ins->i(0));
		mem.setSize(load_bytes);
		// Unaligned: a guest address carries no 64-byte alignment guarantee.  See EmitVecMov.
		j.vmovdqu64(make_vpr(vrd), mem);
		return;
	}

	// INDIRECT form (S2.6).  R_SCRATCH is ArchTraits::AX, which GPR_FIXED keeps out of
	// QRegAlloc::AllocPReg's reach for the whole region, so writing it cannot destroy an
	// allocated value and needs no operand -- which is the entire point (see qir.h).  The 32-bit
	// mov zero-extends, so the u32 guest address becomes the host address under zero_membase.
	//
	// CPUState holds the live guest register here because `rvvtypedchunkbegin` carries HAS_CALLS
	// and QRegAlloc::CallOp(true) spilled every global immediately before the guard.  The guard
	// itself only compares vec.vtype/vl/vstart, so nothing between that sync and this read can
	// have made the slot stale.
	//
	// The bound QIR could not apply, because CPUState is guest state and invisible from qir.h --
	// the same division of labour the two InstVStateChunk* emitters below already implement, and
	// the one qir.h says this form is subject to.  QIR checks only that the offset is
	// REPRESENTABLE in the u16 encoding; whether the 4-byte address read it names lies inside
	// CPUState is decidable only here.  Fail closed: reading past the end of CPUState would take
	// the guest ADDRESS from unrelated host memory and then dereference it, which is worse than
	// the plain out-of-bounds read vstatechunkload could produce.
	if (unlikely((size_t)ins->base_state_offs + sizeof(u32) > sizeof(CPUState))) {
		Panic("qemit: vchunkload indirect base lies outside CPUState");
	}
	if (ins->active_sew) {
		u32 const lanes = load_bytes / ins->active_sew;
		EmitRvvFpLaneMask(lanes, (u32)ins->chunk * lanes);
		j.kmovw(x86::k7, x86::edx);
	}
	auto const scratch32 = make_gpr(ArchTraits::AX, qir::VType::I32);
	auto const scratch64 = x86::gpq(ArchTraits::AX);
	j.mov(scratch32, x86::dword_ptr(R_STATE, (int32_t)ins->base_state_offs));
	// Same addressing contract as make_vmem, spelled out here because the base is a scratch
	// register rather than an operand: no R_MEMBASE term under zero_membase, one otherwise.
	auto mem = config::zero_membase ? x86::ptr(scratch64) : x86::ptr(R_MEMBASE, scratch64);
	// A HOST-pointer displacement, deliberately: [base + 64] does not wrap modulo 2^32 and so
	// agrees with rvv_chunked::copy_chunked on the top 64 guest addresses.  See qir.h.
	mem.addOffset((int32_t)ins->disp);
	mem.setSize(load_bytes);
	if (ins->active_sew) {
		EvexOnly(j);
		if (ins->active_sew == 4)
			j.k(x86::k7).z().vmovdqu32(make_vpr(vrd), mem);
		else
			j.k(x86::k7).z().vmovdqu64(make_vpr(vrd), mem);
		return;
	}
	j.vmovdqu64(make_vpr(vrd), mem);
}

// Order item 4: the saturating add/sub node is an LLVM-route shape. QCG lowers this family through
// `vchunkpartialalu`'s SatAdd kinds instead, so nothing on this backend constructs this one.
// Order item 4: the carry/borrow node is an LLVM-route shape; QCG lowers this family through
// `vchunkpartialalu` instead.
void QEmit::Emit_vchunkadc(qir::InstVChunkAdc *)
{
	Panic("qemit: the carry/borrow node is an LLVM-route shape");
}

void QEmit::Emit_vchunksatadd(qir::InstVChunkSatAdd *)
{
	Panic("qemit: the saturating add/sub node is an LLVM-route shape");
}

// Order item 4: the averaging node is an LLVM-route shape; QCG lowers this family through
// `vchunkpartialalu`'s AvgAddU/AvgAddS/AvgSubU/AvgSubS kinds instead.
void QEmit::Emit_vchunkavg(qir::InstVChunkAvg *)
{
	Panic("qemit: the averaging node is an LLVM-route shape");
}

// Order item 4: the fractional-multiply node is an LLVM-route shape; QCG lowers `vsmul` through
// `vchunkpartialalu`'s FracMul kind instead.
void QEmit::Emit_vchunkfracmul(qir::InstVChunkFracMul *)
{
	Panic("qemit: the fractional-multiply node is an LLVM-route shape");
}

// Order item 4: the narrowing-clip node is an LLVM-route shape; QCG lowers `vnclip` through
// `vchunkpartialalu` instead.
void QEmit::Emit_vchunknarrowclip(qir::InstVChunkNarrowClip *)
{
	Panic("qemit: the narrowing-clip node is an LLVM-route shape");
}

void QEmit::Emit_vchunkadd(qir::InstVChunkAdd *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto vrd = ins->o(0);
	auto vs0 = ins->i(0);
	auto vs1 = ins->i(1);
	assert_pvpr(vrd);
	assert_pvpr(vs0);
	assert_pvpr(vs1);

	auto add_id = [&]() -> uint32_t {
		switch (ins->sew_bytes) {
		case 1:
			return x86::Inst::kIdVpaddb; // AVX512_BW
		case 2:
			return x86::Inst::kIdVpaddw; // AVX512_BW
		case 4:
			return x86::Inst::kIdVpaddd; // AVX512_F
		case 8:
			return x86::Inst::kIdVpaddq; // AVX512_F
		default:
			// The diagnostic arm folds every unknown width into vpaddq; a typed op must
			// not, because its SEW comes from a QIR field a later routing pass will fill.
			Panic("qemit: vchunkadd with an unsupported SEW");
		}
	}();

	// EVEX is non-destructive three-operand, so the destination need not alias a source and the
	// constraint table (arch_traits.cpp CT(r_r_r)) declares no ALIAS.
	//
	// M2C: the operand WIDTH comes from the values' shared VType (InstVChunkAdd's constructor has
	// already proved all three agree), so this one line emits vpaddd on xmm, ymm or zmm without a
	// per-width branch here.
	EvexOnly(j);
	j.emit(add_id, make_vpr(vrd), make_vpr(vs0), make_vpr(vs1));
}

void QEmit::Emit_vwideaddssa(qir::InstRVVWideAddSSA *)
{
	Panic("qemit: LLVM-only fair-wide vadd reached the QCG backend");
}

// Packed low-half integer multiply, the vmul.vv counterpart of Emit_vchunkadd above (P3.5a).
//
// Deliberately NOT a width table like the add's. x86 has no packed byte multiply at all, and the
// 16/64-bit forms live in different AVX-512 subsets (vpmullw is AVX512BW, vpmullq is AVX512DQ)
// than the one this route's admission test probes for (AVX512F). Emitting either of those here
// would produce code the admission test never proved the host can retire, so only the admitted
// width is implemented and every other value is a hard failure rather than a substituted
// operation. RvvQcgTypedMulChunkAdmit (rv32_qir.cpp) is the gate that makes this unreachable.
void QEmit::Emit_vchunkmul(qir::InstVChunkMul *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto vrd = ins->o(0);
	auto vs0 = ins->i(0);
	auto vs1 = ins->i(1);
	assert_pvpr(vrd);
	assert_pvpr(vs0);
	assert_pvpr(vs1);

	if (unlikely(ins->sew_bytes != 4)) {
		Panic("qemit: vchunkmul with an unsupported SEW");
	}
	// vpmulld: SEW=32 packed low-half multiply, AVX512F -- the same feature the admission test
	// probes with __builtin_cpu_supports("avx512f").
	// A1: EvexOnly, so the narrow (xmm/ymm) chunk widths this route now admits at VLEN 128/256
	// are EVEX encoded (AVX512VL, probed by the width-correct shape), as the add/xor/or already are.
	EvexOnly(j);
	j.emit(x86::Inst::kIdVpmulld, make_vpr(vrd), make_vpr(vs0), make_vpr(vs1));
}

// Packed integer subtract, the vsub.vv counterpart of Emit_vchunkadd above (S2.1).
//
// A width table like the add's, not a single width like the multiply's, and for the same reason the
// add has one: x86 has vpsubb/w/d/q covering all four widths in exactly the AVX512F+BW pair
// vpaddb/w/d/q live in, so there is no width whose host support would be assumed here. The
// admission test still admits only SEW=4 today, so only the vpsubd row is reachable; an unadmitted
// width is a hard failure rather than a substituted operation, exactly as in the add.
//
// THE ONE THING THIS EMITTER MUST NOT GET WRONG IS OPERAND ORDER. `vpsub<w> d, a, b` computes
// d = a - b, so input 0 (the minuend, the guest's vs2 chunk) must be the SECOND asmjit operand and
// input 1 (the subtrahend, the guest's vs1 chunk) the third. Reversing them would negate every
// lane while leaving the frame's shape, register disjointness, guard and counters all correct, so
// no structural check would notice; the route's tests therefore gate this order directly, from
// independently disassembled bytes and from guest output.
void QEmit::Emit_vchunksub(qir::InstVChunkSub *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto vrd = ins->o(0);
	auto vs0 = ins->i(0); // minuend
	auto vs1 = ins->i(1); // subtrahend
	assert_pvpr(vrd);
	assert_pvpr(vs0);
	assert_pvpr(vs1);

	auto sub_id = [&]() -> uint32_t {
		switch (ins->sew_bytes) {
		case 1:
			return x86::Inst::kIdVpsubb; // AVX512_BW
		case 2:
			return x86::Inst::kIdVpsubw; // AVX512_BW
		case 4:
			return x86::Inst::kIdVpsubd; // AVX512_F
		case 8:
			return x86::Inst::kIdVpsubq; // AVX512_F
		default:
			Panic("qemit: vchunksub with an unsupported SEW");
		}
	}();

	// EVEX is non-destructive three-operand, so the destination need not alias a source and the
	// constraint table (arch_traits.cpp CT(r_r_r)) declares no ALIAS.
	// A1: EvexOnly for the narrow (xmm/ymm) chunk widths, as the add/xor/or already are.
	EvexOnly(j);
	j.emit(sub_id, make_vpr(vrd), make_vpr(vs0), make_vpr(vs1));
}

// Packed bitwise xor, the vxor.vv counterpart of Emit_vchunkadd above (S2.2).
//
// ONE WIDTH, NO TABLE, AND FOR A DIFFERENT REASON THAN THE MULTIPLY'S. vchunkmul has a single row
// because x86 lacks the other widths; this op has a single row because the other widths would be
// the SAME instruction. An unmasked 512-bit xor is lane-width-independent -- there is no byte or
// word EVEX form, and `vpxord` and `vpxorq` differ only in the granularity of a write mask this
// frame never uses -- so a four-row table would be four spellings of one behaviour and would
// falsely imply the op tracks SEW. Instead, SEW=4 is the width the S2.2 admission test admits and
// the only one implemented; every other value is a hard failure rather than a substituted
// operation. RvvQcgTypedXorChunkAdmit (rv32_qir.cpp) is the gate that makes this unreachable, so
// widening the admitted set stays a deliberate change here plus its own evidence.
//
// OPERAND ORDER IS NOT SEMANTIC HERE. xor commutes, so unlike Emit_vchunksub a swapped pair would
// be numerically identical, and this emitter claims nothing from the order it emits. What the
// route's tests do gate is that the emitted mnemonic is `vpxord` and not one of the sibling
// operations -- an AND or an OR emitted here would be structurally perfect and every lane wrong,
// and that is this route's real hazard because vand.vv/vor.vv share vxor.vv's decode family.
void QEmit::Emit_vchunkxor(qir::InstVChunkXor *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto vrd = ins->o(0);
	auto vs0 = ins->i(0);
	auto vs1 = ins->i(1);
	assert_pvpr(vrd);
	assert_pvpr(vs0);
	assert_pvpr(vs1);

	if (unlikely(ins->sew_bytes != 4)) {
		Panic("qemit: vchunkxor with an unsupported SEW");
	}
	// vpxord: EVEX bitwise xor over the whole register, AVX512F at 64 bytes -- the same feature the
	// admission test probes with __builtin_cpu_supports("avx512f").
	// P7N-D: EvexOnly, so the narrow (xmm/ymm) chunk widths this route admits at VLEN 128/256 are
	// EVEX rather than whichever encoding AsmJit finds shortest for the register the allocator
	// happened to hand out. That keeps the emitted bytes a function of the guest instruction, and
	// keeps all 32 registers addressable at every width. It costs nothing at 64 bytes -- zmm has
	// no VEX form -- so no accepted S2.2/S2.3 byte sequence in the tree moves.
	EvexOnly(j);
	j.emit(x86::Inst::kIdVpxord, make_vpr(vrd), make_vpr(vs0), make_vpr(vs1));
}

// Packed bitwise or, the vor.vv counterpart of Emit_vchunkxor directly above (S2.3).
//
// ONE WIDTH, NO TABLE, for exactly the xor's reason and not the multiply's: the other SEWs would be
// the SAME instruction. An unmasked 512-bit or is lane-width-independent -- there is no byte or word
// EVEX form, and `vpord` and `vporq` differ only in the granularity of a write mask this frame never
// uses. SEW=4 is the width the S2.3 admission test admits and the only one implemented; every other
// value is a hard failure rather than a substituted operation. RvvQcgTypedOrChunkAdmit (rv32_qir.cpp)
// is the gate that makes this unreachable.
//
// OPERAND ORDER IS NOT SEMANTIC HERE. Bitwise or commutes, so unlike Emit_vchunksub a swapped pair
// would be identical, and this emitter claims nothing from the order it emits.
//
// THE ONE THING THIS EMITTER MUST NOT GET WRONG IS THE INSTRUCTION ID, and the failure is one line
// away in both directions. `kIdVpxord` is the accepted S2.2 route's id and `kIdVpandd` is the
// remaining sibling's; either would emit a structurally perfect frame -- right count, right
// registers, right windows, right guard, right counters -- with every lane wrong. Nothing in the
// QIR, the allocator or the frame shape can notice, so the route's tests gate the decoded mnemonic
// itself, from independently disassembled bytes and from guest output.
void QEmit::Emit_vchunkor(qir::InstVChunkOr *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto vrd = ins->o(0);
	auto vs0 = ins->i(0);
	auto vs1 = ins->i(1);
	assert_pvpr(vrd);
	assert_pvpr(vs0);
	assert_pvpr(vs1);

	if (unlikely(ins->sew_bytes != 4)) {
		Panic("qemit: vchunkor with an unsupported SEW");
	}
	// vpord: EVEX bitwise or over the whole register, AVX512F at 64 bytes -- the same feature the
	// admission test probes with __builtin_cpu_supports("avx512f").
	// P7N-D: EvexOnly, so the narrow (xmm/ymm) chunk widths this route admits at VLEN 128/256 are
	// EVEX rather than whichever encoding AsmJit finds shortest for the register the allocator
	// happened to hand out. That keeps the emitted bytes a function of the guest instruction, and
	// keeps all 32 registers addressable at every width. It costs nothing at 64 bytes -- zmm has
	// no VEX form -- so no accepted S2.2/S2.3 byte sequence in the tree moves.
	EvexOnly(j);
	j.emit(x86::Inst::kIdVpord, make_vpr(vrd), make_vpr(vs0), make_vpr(vs1));
}

// Packed bitwise and, the vand.vv counterpart of Emit_vchunkor directly above (S2.4), and the last
// of the three EVEX bitwise siblings to be routed.
//
// ONE WIDTH, NO TABLE, for the or's reason and not the multiply's: the other SEWs would be the SAME
// instruction. An unmasked 512-bit and is lane-width-independent -- there is no byte or word EVEX
// form, and `vpandd` and `vpandq` differ only in the granularity of a write mask this frame never
// uses. SEW=4 is the width the S2.4 admission test admits and the only one implemented; every other
// value is a hard failure rather than a substituted operation. RvvQcgTypedAndChunkAdmit
// (rv32_qir.cpp) is the gate that makes this unreachable.
//
// OPERAND ORDER IS NOT SEMANTIC HERE. Bitwise and commutes, so unlike Emit_vchunksub a swapped pair
// would be identical, and this emitter claims nothing from the order it emits.
//
// THE ONE THING THIS EMITTER MUST NOT GET WRONG IS THE INSTRUCTION ID, and this is the worst
// position of the three to be in. `kIdVpord` and `kIdVpxord` are the ids of TWO ALREADY-ACCEPTED
// routes (S2.3 and S2.2), sitting one and two identifiers away in the same encoding class, with the
// same operand shape, the same width and the same feature bit. Either would emit a structurally
// perfect frame -- right count, right registers, right windows, right guard, right counters -- with
// every lane wrong, AND would be byte-indistinguishable from a correct frame of the route it
// impersonates. Nothing in the QIR, the allocator or the frame shape can notice, so the route's
// tests gate the decoded mnemonic itself, from independently disassembled bytes and from guest
// output, and the mutation gate flips this id into both accepted siblings in turn.
void QEmit::Emit_vchunkand(qir::InstVChunkAnd *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto vrd = ins->o(0);
	auto vs0 = ins->i(0);
	auto vs1 = ins->i(1);
	assert_pvpr(vrd);
	assert_pvpr(vs0);
	assert_pvpr(vs1);

	if (unlikely(ins->sew_bytes != 4)) {
		Panic("qemit: vchunkand with an unsupported SEW");
	}
	// vpandd: EVEX bitwise and over the whole 512-bit register, AVX512F -- the same feature the
	// admission test probes with __builtin_cpu_supports("avx512f").
	// A1: EvexOnly for the narrow (xmm/ymm) chunk widths, as the add/xor/or already are.
	EvexOnly(j);
	j.emit(x86::Inst::kIdVpandd, make_vpr(vrd), make_vpr(vs0), make_vpr(vs1));
}

// P7N-B. vchunksll / vchunksrl: the immediate-count logical shifts.
//
// THREE THINGS ARE DELIBERATE HERE.
//
// 1. THE COUNT IS AN IMMEDIATE OPERAND OF THE HOST INSTRUCTION, not a register. EVEX
//    vpslld/vpsrld with an imm8 are two-operand non-destructive forms (`vpslld zmm1, zmm2, imm8`),
//    which is what lets CT(r_r) declare no ALIAS and what keeps the shift amount out of the
//    register allocator entirely.
//
// 2. THE COUNT IS ALREADY REDUCED MODULO SEW, by InstVChunkSll/Srl's constructor. x86 produces
//    ZERO for a count >= the lane width while RVV 1.0 defines the count as the low log2(SEW) bits,
//    so an unreduced count would be a silent wrong answer at any SEW < 32. The assert below is the
//    backstop: the reduction is the constructor's job and this is where the two must agree.
//
// 3. THE SEW SELECTS THE HOST OPCODE, exactly as it does for the add. Only SEW=4 is admitted by
//    this route today and the Panic keeps it that way rather than quietly emitting a d-width shift
//    for a shape no evidence covers -- the same discipline Emit_vchunkxor uses.
void QEmit::Emit_vchunksll(qir::InstVChunkSll *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto vrd = ins->o(0);
	auto vs0 = ins->i(0);
	assert_pvpr(vrd);
	assert_pvpr(vs0);
	if (unlikely(ins->sew_bytes != 4))
		Panic("qemit: vchunksll with an unsupported SEW");
	if (unlikely(ins->shamt >= 8u * ins->sew_bytes))
		Panic("qemit: vchunksll shift amount was not reduced modulo SEW");
	// EvexOnly so the narrow (xmm/ymm) chunk widths this route admits at VLEN 128/256 are EVEX
	// encoded, matching the width-correct shape's AVX512VL probe.
	EvexOnly(j);
	j.emit(x86::Inst::kIdVpslld, make_vpr(vrd), make_vpr(vs0), asmjit::imm(ins->shamt));
}

void QEmit::Emit_vchunksrl(qir::InstVChunkSrl *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto vrd = ins->o(0);
	auto vs0 = ins->i(0);
	assert_pvpr(vrd);
	assert_pvpr(vs0);
	if (unlikely(ins->sew_bytes != 4))
		Panic("qemit: vchunksrl with an unsupported SEW");
	if (unlikely(ins->shamt >= 8u * ins->sew_bytes))
		Panic("qemit: vchunksrl shift amount was not reduced modulo SEW");
	EvexOnly(j);
	j.emit(x86::Inst::kIdVpsrld, make_vpr(vrd), make_vpr(vs0), asmjit::imm(ins->shamt));
}

void QEmit::Emit_vchunkstore(qir::InstVChunkStore *ins)
{
	// Accounted like every other typed body op, so `end`'s shape check covers the whole frame.
	// Outside a group rvv_typed_chunk_open is false and this adds nothing, which is why the
	// direct-form mechanism-test callers are unaffected.
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto vbase = ins->i(0);
	auto vdata = ins->i(1);
	assert_pvpr(vdata);

	// P7N-D: the window written is exactly the DATA value's own width, not a fixed 64 bytes --
	// the same derivation Emit_vstatechunkload/store have used since M2C. A literal 64 here would
	// turn a 16-byte guest store into a 64-byte one the moment a narrow shape is admitted, which
	// on this side is a write over guest memory the instruction was never asked to touch. The
	// narrow forms are AVX512VL (`vmovdqu64` has no VEX encoding, so xmm/ymm are EVEX by
	// construction); the admission predicate probes for it.
	u32 const store_bytes = qir::VTypeToSize(vdata.GetType()); // VTypeToSize is in BYTES

	if (ins->base_state_offs == qir::InstVChunkStore::NO_STATE_BASE) {
		auto mem = make_vmem(vbase);
		mem.setSize(store_bytes);
		j.vmovdqu64(mem, make_vpr(vdata));
		return;
	}

	// INDIRECT form (S2.7), the exact mirror of Emit_vchunkload's.  R_SCRATCH is ArchTraits::AX,
	// which GPR_FIXED keeps out of QRegAlloc::AllocPReg's reach for the whole region, so writing
	// it cannot destroy an allocated value and needs no operand.  The 32-bit mov zero-extends, so
	// the u32 guest address becomes the host address under zero_membase.
	//
	// CPUState holds the live guest register here because `rvvtypedchunkbegin` carries HAS_CALLS
	// and QRegAlloc::CallOp(true) spilled every global immediately before the guard.  The guard
	// itself only compares vec.vtype/vl/vstart, and the only other thing between that sync and
	// this store is this frame's own vstatechunkload -- which reads CPUState and writes a ZMM, so
	// it cannot make the base slot stale.
	//
	// The bound QIR could not apply, for the reason given on Emit_vchunkload above and stated in
	// qir.h: QIR checks only that the offset is REPRESENTABLE in the u16 encoding, and whether the
	// 4-byte address read it names lies inside CPUState is decidable only here.  Fail closed, and
	// on this side the consequence of not doing so is the worst in the tree: an address taken from
	// unrelated host memory past the end of CPUState would then be the DESTINATION of a 64-byte
	// guest-memory write.
	if (unlikely((size_t)ins->base_state_offs + sizeof(u32) > sizeof(CPUState))) {
		Panic("qemit: vchunkstore indirect base lies outside CPUState");
	}
	if (ins->active_sew) {
		u32 const lanes = store_bytes / ins->active_sew;
		EmitRvvFpLaneMask(lanes, (u32)ins->chunk * lanes);
		j.kmovw(x86::k7, x86::edx);
	}
	auto const scratch32 = make_gpr(ArchTraits::AX, qir::VType::I32);
	auto const scratch64 = x86::gpq(ArchTraits::AX);
	j.mov(scratch32, x86::dword_ptr(R_STATE, (int32_t)ins->base_state_offs));
	// Same addressing contract as make_vmem, spelled out here because the base is a scratch
	// register rather than an operand: no R_MEMBASE term under zero_membase, one otherwise.
	auto mem = config::zero_membase ? x86::ptr(scratch64) : x86::ptr(R_MEMBASE, scratch64);
	// A HOST-pointer displacement, deliberately: [base + 64] does not wrap modulo 2^32 and so
	// agrees with rvv_chunked::copy_chunked on the top 64 guest addresses.  See qir.h.
	mem.addOffset((int32_t)ins->disp);
	mem.setSize(store_bytes);
	if (ins->active_sew) {
		EvexOnly(j);
		if (ins->active_sew == 4)
			j.k(x86::k7).vmovdqu32(mem, make_vpr(vdata));
		else
			j.k(x86::k7).vmovdqu64(mem, make_vpr(vdata));
		return;
	}
	j.vmovdqu64(mem, make_vpr(vdata));
}

// vstatechunkload: one instruction, `vmovdqu64 zmm<allocated>, [R_STATE + offs]` with a 64-byte
// operand.  Deliberately NOT make_vmem: that helper exists to translate a GUEST address, and every
// branch of it either adds R_MEMBASE or emits the guest address as an absolute. Neither is right
// here -- the base is the state register, which is fixed, always live, and unreachable from the
// guest address space. R_MEMBASE is not read, and the guest's memory is not touched.
//
// Unaligned, and it has to be: CPUState carries only 16-byte alignment (rv32::VectorState::vreg is
// alignas(16), and the allocation itself makes no stronger promise), and `offs` is an arbitrary
// validated constant, so the 64-byte window is not 64-byte aligned in general. vmovdqa64 would #GP
// on exactly the offsets a real vector-register file uses.
void QEmit::Emit_vstatechunkload(qir::InstVStateChunkLoad *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	auto vrd = ins->o(0);
	assert_pvpr(vrd);

	// M2C: the window read is exactly the destination value's width, not a fixed 64 bytes.
	u32 const bytes = ins->Bytes();

	// The bound QIR could not apply, because CPUState is guest state and invisible from qir.h. Fail
	// closed: reading past the end of CPUState would be an out-of-bounds host access.
	if (unlikely((size_t)ins->offs + bytes > sizeof(CPUState))) {
		Panic("qemit: vstatechunkload window lies outside CPUState");
	}

	auto mem = asmjit::x86::ptr(R_STATE, (int32_t)ins->offs, bytes);
	EvexOnly(j);
	j.vmovdqu64(make_vpr(vrd), mem);
}

// vstatechunkstore: the mirror of the above, `vmovdqu64 [R_STATE + offs], zmm<allocated>`, 64-byte
// operand.  Same two rules and for the same reasons: NOT make_vmem, because that helper translates
// a GUEST address and every branch of it either adds R_MEMBASE or emits an absolute -- neither is
// the emulator's own state; and unaligned, because CPUState carries only 16-byte alignment and
// `offs` is an arbitrary validated constant, so vmovdqa64 would #GP on exactly the offsets a real
// vector-register file uses.
void QEmit::Emit_vstatechunkstore(qir::InstVStateChunkStore *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	auto vrs = ins->i(0);
	assert_pvpr(vrs);

	// M2C: the window written is exactly the source value's width. This is the store side, so an
	// over-wide access would not merely read too much -- it would overwrite guest vector bytes the
	// guest instruction does not define.
	u32 const bytes = ins->Bytes();

	// The bound QIR could not apply, because CPUState is guest state and invisible from qir.h. Fail
	// closed: writing past the end of CPUState would corrupt unrelated host memory, which is worse
	// than the load's out-of-bounds read.
	if (unlikely((size_t)ins->offs + bytes > sizeof(CPUState))) {
		Panic("qemit: vstatechunkstore window lies outside CPUState");
	}

	auto mem = asmjit::x86::ptr(R_STATE, (int32_t)ins->offs, bytes);
	if (ins->active_sew && ins->kmask) {
		// F1 GUARD. The frame's resident active mask for this chunk -- the same EmitRvvFpLaneMask
		// derivation Emit_vchunkmaskset ran once for the frame -- instead of a second derivation
		// here. FpMaskRegs checks the recycled slot AND its current chunk ownership.
		namespace x86 = asmjit::x86;
		auto const [kact, kscr] = FpMaskRegs(ins->kmask, ins->chunk);
		x86::KReg kstore = kact;
		if (ins->masked) {
			u32 const lanes = bytes / ins->active_sew, base = ins->chunk * lanes;
			j.movzx(x86::eax, x86::word_ptr(R_STATE, (int32_t)offsetof(CPUState, vec) +
				(int32_t)offsetof(rv32::VectorState, vreg) + base / 8));
			if (base % 8) j.shr(x86::eax, base % 8);
			j.kmovw(kscr, x86::eax);
			j.kandw(kscr, kact, kscr);
			kstore = kscr;
		}
		EvexOnly(j);
		if (ins->active_sew == 4) j.k(kstore).vmovdqu32(mem, make_vpr(vrs));
		else j.k(kstore).vmovdqu64(mem, make_vpr(vrs));
		return;
	}
	if (ins->active_sew) {
		namespace x86 = asmjit::x86;
		u32 const lanes = bytes / ins->active_sew, base = ins->chunk * lanes;
		// AX/DX are fixed scratch registers. k7 never holds a shared FP mask.
		EmitRvvFpLaneMask(lanes, base);
		if (ins->masked) {
			j.movzx(x86::eax, x86::word_ptr(R_STATE, (int32_t)offsetof(CPUState, vec) +
				(int32_t)offsetof(rv32::VectorState, vreg) + base / 8));
			if (base % 8) j.shr(x86::eax, base % 8);
			j.and_(x86::edx, x86::eax);
		}
		j.kmovw(x86::k7, x86::edx);
		EvexOnly(j);
		if (ins->active_sew == 4) j.k(x86::k7).vmovdqu32(mem, make_vpr(vrs));
		else j.k(x86::k7).vmovdqu64(mem, make_vpr(vrs));
		return;
	}
	EvexOnly(j);
	j.vmovdqu64(mem, make_vpr(vrs));
}

// Native-3. vchunkbroadcast: one instruction, `vpbroadcastd zmm<allocated>, dword [R_STATE + offs]`.
//
// THE SCALAR OPERAND OF AN RVV `.vx` INSTRUCTION, AND NOTHING ELSE. `vmul.vx vd, vs2, rs1` is
// `vd[i] = vs2[i] * x[rs1]`, so every lane multiplies by the same guest integer register. This is
// that replication; the arithmetic is the frame's own body op.
//
// NOT make_vmem, for Emit_vstatechunkload's reason and one that is sharper here: the address is not
// a guest address at all. R_STATE is fixed, always live and unreachable from the guest address
// space, and `offs` is the translation-time offset of a guest GPR slot inside CPUState. R_MEMBASE
// is not read and the guest's memory is not touched.
//
// FOUR BYTES READ, SIXTY-FOUR WRITTEN, and the operand size below says so. `vpbroadcastd` with a
// memory source reads exactly one dword and replicates it -- it does not read a 64-byte window --
// so setting the operand size to anything else would encode a different instruction. The 4-byte
// slot is naturally aligned (a guest GPR is 4-byte aligned inside CPUState and qir.h refuses a
// misaligned offset), so unlike the 64-byte windows above there is no alignment caveat.
//
// THE VALUE IT READS IS LIVE. The enclosing `rvvtypedchunkbegin` carries HAS_CALLS, so
// QRegAlloc::CallOp has synced every guest global back to CPUState before the body starts, and this
// op's SIDEEFF flag keeps that sync in front of it. So the word here is the same `s->gpr[rs1]` the
// rv32_vimul helper on the guard-miss arm would read.
void QEmit::Emit_vchunkbroadcast(qir::InstVChunkBroadcast *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	auto vrd = ins->o(0);
	assert_pvpr(vrd);

	// The bound QIR could not apply, because CPUState is guest state and invisible from qir.h.
	// Fail closed, exactly as the two ops above: reading past the end of CPUState is out of bounds.
	if (unlikely((size_t)ins->offs + qir::InstVChunkBroadcast::SCALAR_BYTES > sizeof(CPUState))) {
		Panic("qemit: vchunkbroadcast scalar lies outside CPUState");
	}
	// SEW=4 -> vpbroadcastd (AVX512F with a zmm destination), the width this route's admission
	// predicate probes for. Every other width is a hard failure rather than a substituted lane
	// width: vpbroadcastb/w are AVX512BW and vpbroadcastq is AVX512F but would splat a different
	// number of lanes, so emitting one here would be a silent miscompile.
	if (unlikely(ins->sew_bytes != 4)) {
		Panic("qemit: vchunkbroadcast with an unsupported SEW");
	}
	if (ins->is_imm) {
		// A6: `mov eax, imm32 ; vpbroadcastd v, eax`. AX is ArchTraits::AX, the fixed scratch
		// GPR_FIXED keeps out of QRegAlloc for the whole region (the indirect vchunkload above
		// already relies on that), so no allocated value can be destroyed and no operand is
		// needed. The GPR-source vpbroadcastd is AVX-512F only (EVEX by definition).
		auto const scratch32 = make_gpr(ArchTraits::AX, qir::VType::I32);
		j.mov(scratch32, (int32_t)ins->imm);
		EvexOnly(j);
		j.vpbroadcastd(make_vpr(vrd), scratch32);
		return;
	}
	auto mem = asmjit::x86::ptr(R_STATE, (int32_t)ins->offs,
				    qir::InstVChunkBroadcast::SCALAR_BYTES);
	// A2: the destination width is the operand's own type (xmm/ymm/zmm); the narrow forms are
	// EVEX (AVX512VL, probed by the width-correct shape), as every other narrow chunk op.
	EvexOnly(j);
	j.vpbroadcastd(make_vpr(vrd), mem);
}

// T7R. Read an RV32 NaN-boxed scalar and splat it without a helper call.
void QEmit::Emit_vchunkfbroadcast(qir::InstVChunkFBroadcast *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto d = ins->o(0);
	assert_pvpr(d);
	if ((size_t)ins->offs + sizeof(u64) > sizeof(CPUState))
		Panic("qemit: vchunkfbroadcast outside CPUState");
	auto emit32 = [&] {
		auto boxed = j.newLabel(), done = j.newLabel();
		j.mov(x86::eax, x86::dword_ptr(R_STATE, (int32_t)ins->offs + 4));
		j.cmp(x86::eax, -1); j.je(boxed);
		j.mov(x86::eax, 0x7fc00000u); j.jmp(done);
		j.bind(boxed); j.mov(x86::eax, x86::dword_ptr(R_STATE, (int32_t)ins->offs));
		j.bind(done); EvexOnly(j); j.vpbroadcastd(make_vpr(d), x86::eax); // A9: EVEX for xmm/ymm
	};
	if (ins->sew_bytes == 8) {
		EvexOnly(j); j.vpbroadcastq(make_vpr(d), x86::qword_ptr(R_STATE, (int32_t)ins->offs)); // A9
		return;
	}
	if (ins->sew_bytes == 4) { emit32(); return; }
	auto fp64 = j.newLabel(), done = j.newLabel();
	j.cmp(x86::dword_ptr(R_STATE, (int32_t)offsetof(CPUState, vec) +
		(int32_t)offsetof(rv32::VectorState, vtype)), 0xd9);
	j.je(fp64); emit32(); j.jmp(done);
	j.bind(fp64); EvexOnly(j); j.vpbroadcastq(make_vpr(d), x86::qword_ptr(R_STATE, (int32_t)ins->offs)); // A9
	j.bind(done);
}

void QEmit::Emit_rvvqcgfpbegin(qir::InstRVVQCGFPBegin *)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto const fpu = (int32_t)offsetof(CPUState, fpu);
	auto const open = fpu + (int32_t)offsetof(rv32::FPUState, fround_run_open);
	auto const saved = fpu + (int32_t)offsetof(rv32::FPUState, fround_run_saved_mxcsr);
	auto const cur = fpu + (int32_t)offsetof(rv32::FPUState, qcg_current_mxcsr);
	auto fresh = j.newLabel();
	j.cmp(x86::byte_ptr(R_STATE, open), 0);
	j.je(fresh);
	// A preceding scalar instruction may have used an explicit rounding mode.
	// Fold its exceptions before replacing the host environment with guest frm.
	EmitCloseRvvFpBracket();
	j.bind(fresh);
	j.stmxcsr(x86::dword_ptr(R_STATE, saved));
	j.mov(x86::eax, x86::dword_ptr(R_STATE, saved));
	// Exceptions clear, gradual underflow, retain exception masks. RVV and MXCSR
	// encode their rounding modes differently: 0,1,2,3 -> 0,3,1,2.
	j.and_(x86::eax, ~(0x3fu | 0x6000u | 0x8040u));
	j.mov(x86::edx, x86::dword_ptr(R_STATE, fpu + (int32_t)offsetof(rv32::FPUState, fcsr)));
	j.shr(x86::edx, 5); j.and_(x86::edx, 7);
	// Guards exclude RMM for rounding-sensitive operations. Exact widening and
	// explicit-rounding conversions can use RNE as a harmless host environment.
	// Never shift guest-only modes into unrelated MXCSR control bits.
	auto host_mode = j.newLabel();
	j.cmp(x86::edx, 4); j.jb(host_mode);
	j.xor_(x86::edx, x86::edx);
	j.bind(host_mode);
	auto mode_ready = j.newLabel(), directed = j.newLabel();
	j.test(x86::edx, x86::edx); j.jz(mode_ready);
	j.cmp(x86::edx, 1); j.jne(directed);
	j.mov(x86::edx, 3); j.jmp(mode_ready);
	j.bind(directed); j.dec(x86::edx);
	j.bind(mode_ready); j.shl(x86::edx, 13); j.or_(x86::eax, x86::edx);
	j.mov(x86::dword_ptr(R_STATE, cur), x86::eax);
	j.mov(x86::dword_ptr(R_STATE, fpu + (int32_t)offsetof(rv32::FPUState, fround_run_rc)), x86::edx);
	j.ldmxcsr(x86::dword_ptr(R_STATE, cur));
	j.mov(x86::byte_ptr(R_STATE, open), 1);
}

// P7L-B1. THE MATCHED DEPENDENCY PROBE. ONE instruction, unconditionally, at every width.
//
//   vpblendmq out, probe, value      ->      out := value, having READ probe
//
// With no writemask VPBLENDMQ is `DEST := SRC2` for every lane and DEST is not a source, so the
// architectural read set is exactly {SRC1, SRC2} = {probe, value} and the written set is {DEST}.
// That is what makes the two ablation arms differ in one register field and in nothing else: the
// arms pass a different `probe`, and this function does not know or care which.
//
// NO MASKING, and that is deliberate rather than an omission. The value is copied whole, so lane
// activity is irrelevant to what this computes -- masking it would make the emitted form depend on
// `vl`, i.e. on run-time state, and the two arms are supposed to differ only in a register index.
// The frame's real lane ops keep their own k1 prologue; this node never touches k1, k2 or MXCSR.
//
// It DOES count as a typed body op: the enclosing group's declared `n_typed` includes the probes
// (RvvEmitVectorRunGroup), so `Emit_rvvtypedchunkend`'s shape assertion still covers every byte
// the guard-miss arm branches over.
void QEmit::Emit_vchunkdep(qir::InstVChunkDep *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto d = ins->o(0), value = ins->i(0), probe = ins->i(1);
	assert_pvpr(d); assert_pvpr(value); assert_pvpr(probe);
	j.vpblendmq(make_vpr(d), make_vpr(probe), make_vpr(value));
}

// A12. (active, scratch) opmask pair for an FP lane op, from the node's declared source, checked
// against what this frame has actually made resident.
std::pair<asmjit::x86::KReg, asmjit::x86::KReg> QEmit::FpMaskRegs(u8 kmask, u8 chunk)
{
	namespace x86 = asmjit::x86;
	if (kmask == 0) {
		if (unlikely(rvv_typed_chunk_fp_masks))
			Panic("qemit: fp lane op recomputes k1/k2 inside a frame holding shared masks");
		return {x86::k1, x86::k2};
	}
	if (unlikely(kmask != 1 + chunk % qir::RVV_FP_SHARED_MASK_MAX_CHUNKS || chunk >= 64))
		Panic("qemit: fp lane op names a mask register outside the shared range");
	if (unlikely(!rvv_typed_chunk_open || !(rvv_typed_chunk_fp_masks & (u64{1} << chunk))))
		Panic("qemit: fp lane op consumes a shared mask this frame never set");
	return {x86::KReg(kmask), x86::KReg(qir::RVV_FP_SCRATCH_KMASK)};
}

// G11-A. Does the arm Emit_vchunkfalu's `switch (funct6)` is about to select write EVERY lane of
// the destination without reading it? That is the only condition under which the `vmovdqu64 out,
// vs2` seed is dead once the lane mask is the constant all-ones, and it is a property of the
// EMITTED SHAPE, not of the guest opcode's meaning:
//
//   vfadd/vfsub/vfmul/vfdiv and the two reversed forms -> ONE masked arithmetic instruction with
//       `out` as destination only; unmasked it writes the whole chunk and never reads `out`.
//   vfmin/vfmax (funct6 4 / 6) -> `out` is written through THREE different partial masks (ORD_Q,
//       EQ_OQ, and the NaN-in-vs2 select); lanes no mask covers must still hold the seeded vs2,
//       which is exactly how "one NaN selects the numeric operand" is implemented.
//   vfsgnj/vfsgnjn/vfsgnjx (funct6 8/9/10) -> `out` is the FIRST VPTERNLOG truth-table input, so
//       the seed is a source operand, not a merge artefact.
//
// `default: return false` keeps a funct6 added later on the safe side: it would keep its seed.
static constexpr bool RvvFaluArmFullyWritesDest(u8 funct6)
{
	switch (funct6) {
	case 0b000000: // vfadd.vv/.vf
	case 0b000010: // vfsub
	case 0b100100: // vfmul
	case 0b100000: // vfdiv
	case 0b100001: // vfrdiv (reversed operands, same single write)
	case 0b100111: // vfrsub (reversed operands, same single write)
		return true;
	default:
		return false;
	}
}

void QEmit::Emit_vchunkfalu(qir::InstVChunkFALU *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto d = ins->o(0), s2 = ins->i(0), s1 = ins->i(1);
	assert_pvpr(d); assert_pvpr(s2); assert_pvpr(s1);
	auto a = make_vpr(s2), b = make_vpr(s1), out = make_vpr(d);
	// A9: the chunk width is the destination value's own width (16/32/64 bytes), so the lane
	// count, the runtime-VL mask and the NaN-fill scratch all follow it; VPR_FIXED 0 is the scratch
	// register in every class.
	u32 const chunk_w = qir::VTypeToSize(d.GetType());
	auto scratch = [&]() -> x86::Vec { return chunk_w == 16 ? x86::Vec(x86::xmm0) : chunk_w == 32 ? x86::Vec(x86::ymm0) : x86::Vec(x86::zmm0); };
	// A12. THE MASK SOURCE IS THE NODE'S, NOT A RESIDUE. kmask == 0: this op derives its own
	// active mask into k1 and uses k2 as the epilogue scratch (pre-A12, unchanged byte for
	// byte). kmask == 1+chunk: the frame's vchunkmaskset left it in k(1+chunk); the prologue is
	// not emitted and the scratch is k7, which no chunk's resident mask can occupy
	// (RVV_FP_SHARED_MASK_MAX_CHUNKS). The bitmap check makes a frame that mixes the two
	// conventions a translation Panic: a self-computing op would clobber k1/k2 = chunks 0/1.
	auto const [kact, kscr] = FpMaskRegs(ins->kmask, ins->chunk);
	// G11-A. The frame's guard proved `vl == VLMAX && vstart == 0`, this member is unmasked, and
	// the frame therefore holds no shared mask (Emit_vchunkmaskset Panics if it does), so every
	// element of the destination group is an active body element: the mask is the constant
	// all-ones, there is no tail to fill, and `kact` is never written. `ka()` below is what makes
	// that a HOST-UNMASKED operation rather than an operation masked by an all-ones register --
	// the two are not the same claim, and only the first is true here.
	bool const full_vl = rvv_typed_chunk_full_vl && !ins->kmask && !ins->masked;
	auto emit_width = [&](u8 sew) {
		if (!ins->kmask && !full_vl) {
			u32 const lanes = chunk_w / sew, base = (u32)ins->chunk * lanes; // A9: lanes from the chunk width
			EmitRvvFpLaneMask(lanes, base);
			j.kmovw(kact, x86::edx);
		}
		// The active-mask applicator: `{kact}` normally, nothing when the predicate is the
		// constant 1. The SCRATCH mask `kscr` is data-dependent (the unordered compare, the
		// min/max selects) and is applied directly everywhere below -- it is never elided.
		auto ka = [&]() -> x86::Assembler & { return full_vl ? j : j.k(kact); };
		if (ins->masked) {
			u32 const base = ins->chunk * (chunk_w / sew);
			j.movzx(x86::eax, x86::word_ptr(R_STATE, (int32_t)offsetof(CPUState, vec) +
				(int32_t)offsetof(rv32::VectorState, vreg) + base / 8));
			if (base % 8) j.shr(x86::eax, base % 8);
			j.kmovw(kscr, x86::eax); j.kandw(kact, kact, kscr);
		}
		// THE DESTINATION SEED. `out` is preloaded with vs2 so the MASKED lane op below can
		// merge, which is also what leaves every lane defined for the epilogue. G11-A drops it
		// only when the arm the switch is about to select writes every lane of `out` without
		// reading it -- decided from the same funct6 the switch decides the shape from, so an
		// arm that reads `out` (sign injection's VPTERNLOG input) or writes it through several
		// partial masks (min/max) cannot lose its seed, and a form added later defaults to
		// keeping it.
		if (!(full_vl && RvvFaluArmFullyWritesDest(ins->funct6)))
			j.vmovdqu64(out, a);
		auto emit = [&](uint32_t ps, uint32_t pd) { ka().emit(sew == 4 ? ps : pd, out, a, b); };
		switch (ins->funct6) {
		case 0b000000: emit(x86::Inst::kIdVaddps, x86::Inst::kIdVaddpd); break;
		case 0b000010: emit(x86::Inst::kIdVsubps, x86::Inst::kIdVsubpd); break;
		case 0b100100: emit(x86::Inst::kIdVmulps, x86::Inst::kIdVmulpd); break;
		case 0b100000: emit(x86::Inst::kIdVdivps, x86::Inst::kIdVdivpd); break;
		case 0b100001: ka().emit(sew == 4 ? x86::Inst::kIdVdivps :
			x86::Inst::kIdVdivpd, out, b, a); break;
		case 0b100111: ka().emit(sew == 4 ? x86::Inst::kIdVsubps :
			x86::Inst::kIdVsubpd, out, b, a); break;
		case 0b000100: case 0b000110: {
			bool const maximum = ins->funct6 == 6;
			auto cmp = [&](u32 predicate) {
				if (sew == 4) ka().vcmpps(kscr, a, b, predicate);
				else ka().vcmppd(kscr, a, b, predicate);
			};
			// Quiet ordered comparison raises NV only for signaling NaNs. Never
			// expose a quiet NaN to x86 MIN/MAX's different exception semantics.
			cmp(7); // ORD_Q
			u32 const opcode = maximum ? (sew == 4 ? x86::Inst::kIdVmaxps : x86::Inst::kIdVmaxpd) :
				(sew == 4 ? x86::Inst::kIdVminps : x86::Inst::kIdVminpd);
			j.k(kscr).emit(opcode, out, a, b);
			// Equal operands have identical bits except signed zero. OR chooses
			// -0 for min; AND chooses +0 for max, independent of operand order.
			cmp(0); // EQ_OQ
			if (sew == 4) {
				if (maximum) j.k(kscr).vpandd(out, a, b); else j.k(kscr).vpord(out, a, b);
				ka().vcmpps(kscr, a, a, 3);
				j.k(kscr).vmovaps(out, b);
			} else {
				if (maximum) j.k(kscr).vpandq(out, a, b); else j.k(kscr).vporq(out, a, b);
				ka().vcmppd(kscr, a, a, 3);
				j.k(kscr).vmovapd(out, b);
			}
			// One NaN selects the numeric operand; two NaNs reach the common
			// canonicalization below. Inactive lanes never set exception flags.
			break;
		}
		case 0b001000: case 0b001001: case 0b001010: {
			// Integer bit selection preserves NaN payloads and never raises FP flags.
			// VPTERNLOG truth-table inputs are (old out=a, b, sign-bit mask).
			u32 const truth = ins->funct6 == 8 ? 0xd8 : ins->funct6 == 9 ? 0x72 : 0x78;
			if (sew == 4) {
				j.mov(x86::eax, 0x80000000u); EvexOnly(j); j.vpbroadcastd(scratch(), x86::eax);
				ka().vpternlogd(out, b, scratch(), truth);
			} else {
				j.mov(x86::rax, 0x8000000000000000ull); EvexOnly(j); j.vpbroadcastq(scratch(), x86::rax);
				ka().vpternlogq(out, b, scratch(), truth);
			}
			break;
		}
		default: Panic("qemit: unsupported direct vfalu funct6");
		}
		bool const sign_injection = ins->funct6 >= 8 && ins->funct6 <= 10;
		if (!sign_injection && sew == 4) {
		// Mask-register destinations do not have the EVEX.z form; kact suppresses inactive-lane
		// comparisons, while stale inactive scratch bits can only write tail-agnostic lanes below.
			ka().vcmpps(kscr, out, out, 3); j.mov(x86::eax, 0x7fc00000u);
			EvexOnly(j); j.vpbroadcastd(scratch(), x86::eax); j.k(kscr).vmovaps(out, scratch());
		} else if (!sign_injection) {
			ka().vcmppd(kscr, out, out, 3);
			j.mov(x86::rax, 0x7ff8000000000000ull); EvexOnly(j); j.vpbroadcastq(scratch(), x86::rax);
			j.k(kscr).vmovapd(out, scratch());
		}
		// A4 (2026-09-05). THE TAIL. `out` was seeded from `a` (vs2) so the masked lane op could
		// merge, which left every INACTIVE lane holding vs2's value -- not a member of RVV 1.0's
		// tail-agnostic set {old vd, all ones} (v-st-ext 3.4.3 / 5.4). The vd-free choice made here
		// is all ones: scratch := ~active and every inactive lane is set to 1s. On the full-vl path
		// the scratch is empty and the write is a no-op; no CPUState read is added. A12: the
		// scratch is k7 when the active mask is shared, so the resident masks survive this write.
		//
		// P2e CORRECTION (2026-09-13). This comment previously asserted two preconditions that the
		// code does NOT enforce, and both were measured false on xbd (P2A_NATIVE_CHUNK_COUNTER_
		// 20260913.md section 6c). They are corrected here; no code token changed.
		//
		//   * "This route admits vta=1 only (RvvQcgTypedFaluAdmit)" -- FALSE. That predicate
		//     contains no vta condition at all, and a vta=0 (tail-undisturbed) vfadd.vv frame is
		//     admitted and built, with the same unit count and the same guard kind.
		//   * "vl == 0 never reaches here (the guard sends it to the helper)" -- FALSE for the
		//     guard kind this route actually gets. Only VTypePartialVlVstartFrmRNE and
		//     VTypeE32OrE64M2PartialVlVstartFrmRNE emit the `vl == 0 -> fallback` compare; the
		//     statically-typed route here carries VTypePartialVlVstartFrmHost, which does not. At
		//     vl == 0 `kact` is empty, so the fill below covers EVERY lane of `out`.
		//
		// WHY THE RESULT IS STILL CORRECT, AND WHERE THAT CORRECTNESS LIVES. It is not this fill
		// and it is not the guard: it is the STORE. Emit_vstatechunkstore writes the chunk back as
		// `vmovdqu32 {k7}` with k7 = the architectural active-lane mask (EmitRvvFpLaneMask of
		// vl/vstart, AND-ed with v0 when masked), so prestart, inactive and tail lanes -- and at
		// vl == 0 every lane -- are simply never stored. Guest state is therefore UNDISTURBED under
		// every policy, which legally implements both the agnostic and the undisturbed choice and
		// satisfies RVV 1.0's rule that vl == 0 updates no destination element.
		//
		// THE PRACTICAL CONSEQUENCE FOR A FUTURE EDIT: this fill is safe ONLY because that store
		// mask exists. Relaxing the store predicate would let the all-ones fill reach guest state.
		// That exact mutation was applied on a throwaway remote copy and the focused test caught it
		// in all four constrained categories (vl == 0, vta = 0 tail, vma = 0 inactive, prestart);
		// see rvv_active_chunk_census_test.cpp section [C].
		//
		// G11-A. That "on the full-vl path the scratch is empty" is now a fact the FRAME has
		// proved rather than one this emitter has to hope for, so the pair is not emitted at
		// all. It is not optional here: with the predicate elided `kact` was never written, so
		// `knotw kscr, kact` would read an undefined opmask.
		if (!full_vl) {
			j.knotw(kscr, kact);
			if (sew == 4)
				j.k(kscr).vpternlogd(out, out, out, 0xff);
			else
				j.k(kscr).vpternlogq(out, out, out, 0xff);
		}
	};
	if (ins->sew_bytes) { emit_width(ins->sew_bytes); return; }
	auto fp64 = j.newLabel(), done = j.newLabel();
	j.cmp(x86::dword_ptr(R_STATE, (int32_t)offsetof(CPUState, vec) +
		(int32_t)offsetof(rv32::VectorState, vtype)), 0xd9);
	j.je(fp64); emit_width(4); j.jmp(done); j.bind(fp64); emit_width(8); j.bind(done);
}

// P7I. The fused three-input lane operation. Structurally Emit_vchunkfalu with one more input and
// an FMA3 opcode in the middle; the lane-mask prologue and the NaN-canonicalisation epilogue are
// deliberately the SAME sequences, because they must keep meaning the same thing.
//
// THE OPCODE MAPPING, WHICH IS THE ONE THING HERE THAT IS NOT COPIED FROM THE FALU EMITTER:
//
//   RVV vfmadd.vf   vd = fma( vd_old, scalar, vs2)   (rv32_vector_lower.h:1634)
//   RVV vfnmsub.vf  vd = fma(-vd_old, scalar, vs2)   (rv32_vector_lower.h:1637)
//
// With `out` pre-loaded with vd_old, x86's 213 form computes `dst = src1*dst (+/-) src2`:
//
//   vfmadd213pd  out, b, a   ->   out =   b*out  + a    == fma( vd_old, scalar, vs2)   MATCH
//   vfnmadd213pd out, b, a   ->   out = -(b*out) + a    == fma(-vd_old, scalar, vs2)   MATCH
//
// *** NAMING TRAP. RVV's `vfnmsub` maps to x86's vfnmADDpd, NOT to the identically-named
// vfnmsub213pd. *** x86's vfnmsub213pd is `-(src1*dst) - src2`, i.e. the ADDEND'S SIGN IS ALSO
// FLIPPED, which RVV's nmsub does not do -- the helper's `std::fma(-d, b, a)` negates only the
// product. Picking the same-spelled opcode would silently produce `-(b*d) - a` and would still
// look right in a chunk-count or node-count test; only a disassembly check or a value differential
// catches it (vfma_typedchunk_route_test.cpp sections [7] and [8]).
//
// There is no vmulpd+vaddpd decomposition anywhere below, and that is a correctness requirement
// rather than an optimisation: a separate multiply and add round TWICE and are a different
// function from the helper's single-rounded std::fma.
void QEmit::Emit_vchunkfma(qir::InstVChunkFMA *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto d = ins->o(0), sdold = ins->i(0), sb = ins->i(1), sa = ins->i(2);
	assert_pvpr(d); assert_pvpr(sdold); assert_pvpr(sb); assert_pvpr(sa);
	auto dold = make_vpr(sdold), b = make_vpr(sb), a = make_vpr(sa), out = make_vpr(d);
	// No sew_bytes == 0 branch, unlike Emit_vchunkfalu: this route refuses an unobserved vtype in
	// admission, so there is no run-time element width to resolve here. A zero would mean the
	// predicate and the node disagreed, and InstVChunkFMA's constructor has already Panicked.
	u8 const sew = ins->sew_bytes;
	if (unlikely(sew != 4 && sew != 8))
		Panic("qemit: vchunkfma with an unsupported SEW");
	// A9: the chunk width is the destination value's own width (16/32/64 bytes), so the lane
	// count, the runtime-VL mask and the NaN-fill scratch all follow it; VPR_FIXED 0 is the scratch
	// register in every class.
	u32 const chunk_w = qir::VTypeToSize(d.GetType());
	auto scratch = [&]() -> x86::Vec { return chunk_w == 16 ? x86::Vec(x86::xmm0) : chunk_w == 32 ? x86::Vec(x86::ymm0) : x86::Vec(x86::zmm0); };
	auto const [kact, kscr] = FpMaskRegs(ins->kmask, ins->chunk); // A12: see Emit_vchunkfalu
	// G11-A: see Emit_vchunkfalu. The frame's guard proved `vl == VLMAX && vstart == 0` and this
	// member is unmasked, so the active predicate is the constant 1 and the lane op is emitted
	// HOST-UNMASKED rather than masked by an all-ones register. The DESTINATION SEED below is
	// kept unconditionally: every 213/231 form reads `out` as the multiplicand or the
	// accumulator, so it is a source operand here and never a merge artefact.
	bool const full_vl = rvv_typed_chunk_full_vl && !ins->kmask && !ins->masked;
	auto ka = [&]() -> x86::Assembler & { return full_vl ? j : j.k(kact); };
	if (!ins->kmask && !full_vl) {
		u32 const lanes = chunk_w / sew, base = (u32)ins->chunk * lanes; // A9: lanes from the chunk width
		EmitRvvFpLaneMask(lanes, base);
		j.kmovw(kact, x86::edx);
	}
	if (ins->masked) {
		u32 const base = ins->chunk * (chunk_w / sew);
		j.movzx(x86::eax, x86::word_ptr(R_STATE, (int32_t)offsetof(CPUState, vec) +
			(int32_t)offsetof(rv32::VectorState, vreg) + base / 8));
		if (base % 8) j.shr(x86::eax, base % 8);
		j.kmovw(kscr, x86::eax); j.kandw(kact, kact, kscr);
	}
	// The destination starts as the OLD vd, for two independent reasons: the 213 form needs it
	// there as the multiplicand, and it is what leaves the inactive lanes holding a defined
	// value (the same role `vmovdqu64 out, a` plays in Emit_vchunkfalu).
	j.vmovdqu64(out, dold);
	// THE EIGHT FORMS, one fused host instruction each. `out` holds vd_old (the helper's `d`),
	// `b` is the helper's `b` (vs1 or the .vf splat) and `a` is vs2. x86 offers the same four sign
	// pairs in two operand orders, and the two RVV operand-role groups need one order each:
	//
	//   213: dst = src1*dst (+/-) src2  -- the PRODUCT uses the destination
	//   231: dst = src1*src2 (+/-) dst  -- the destination is the ADDEND
	//
	//   RVV        helper (rv32_vector_lower.h:1673-1680, :1695-1702)   x86 with out = d
	//   vfmadd     fma( d, b,  a)   =   d*b + a                         vfmadd213    b*out + a
	//   vfnmadd    fma(-d, b, -a)   = -(d*b) - a                        vfnmsub213 -(b*out) - a
	//   vfmsub     fma( d, b, -a)   =   d*b - a                         vfmsub213    b*out - a
	//   vfnmsub    fma(-d, b,  a)   = -(d*b) + a                        vfnmadd213 -(b*out) + a
	//   vfmacc     fma( b, a,  d)   =   b*a + d                         vfmadd231    b*a + out
	//   vfnmacc    fma(-b, a, -d)   = -(b*a) - d                        vfnmsub231 -(b*a) - out
	//   vfmsac     fma( b, a, -d)   =   b*a - d                         vfmsub231    b*a - out
	//   vfnmsac    fma(-b, a,  d)   = -(b*a) + d                        vfnmadd231 -(b*a) + out
	//
	// *** THE NAMING TRAP IS SYSTEMATIC, in BOTH groups: RVV's `n...sub` is x86's `nmadd` and
	// RVV's `n...add` is x86's `nmsub`. RVV's leading `n` negates the PRODUCT only, and the
	// trailing add/sub names the ADDEND's sign; x86 spells those two signs the other way round.
	// Reaching for the identically-spelled opcode flips the addend's sign and still produces a
	// plausible number that no chunk-count or node-count test can see. ***
	//
	// The 231 forms need nothing extra from the frame: `out` was already preloaded with vd_old,
	// which is precisely the accumulator those four read, and under `k(kact)` the inactive lanes
	// keep that same preloaded vd_old in both groups.
	//
	// Still no vmulp?+vaddp? decomposition anywhere: a separate multiply and add round TWICE and
	// are a different function from the helper's single-rounded std::fma / softfp::op_fma.
	switch (ins->funct6) {
	case 0b101000: // VF6_VFMADD   d*b + a
		ka().emit(sew == 4 ? x86::Inst::kIdVfmadd213ps : x86::Inst::kIdVfmadd213pd,
			       out, b, a);
		break;
	case 0b101001: // VF6_VFNMADD  -(d*b) - a  -- vfnmSUB on x86; see the naming trap above.
		ka().emit(sew == 4 ? x86::Inst::kIdVfnmsub213ps : x86::Inst::kIdVfnmsub213pd,
			       out, b, a);
		break;
	case 0b101010: // VF6_VFMSUB   d*b - a
		ka().emit(sew == 4 ? x86::Inst::kIdVfmsub213ps : x86::Inst::kIdVfmsub213pd,
			       out, b, a);
		break;
	case 0b101011: // VF6_VFNMSUB  -(d*b) + a  -- vfnmADD on x86; see the naming trap above.
		ka().emit(sew == 4 ? x86::Inst::kIdVfnmadd213ps : x86::Inst::kIdVfnmadd213pd,
			       out, b, a);
		break;
	case 0b101100: // VF6_VFMACC   b*a + d
		ka().emit(sew == 4 ? x86::Inst::kIdVfmadd231ps : x86::Inst::kIdVfmadd231pd,
			       out, b, a);
		break;
	case 0b101101: // VF6_VFNMACC  -(b*a) - d  -- vfnmSUB on x86.
		ka().emit(sew == 4 ? x86::Inst::kIdVfnmsub231ps : x86::Inst::kIdVfnmsub231pd,
			       out, b, a);
		break;
	case 0b101110: // VF6_VFMSAC   b*a - d
		ka().emit(sew == 4 ? x86::Inst::kIdVfmsub231ps : x86::Inst::kIdVfmsub231pd,
			       out, b, a);
		break;
	case 0b101111: // VF6_VFNMSAC  -(b*a) + d  -- vfnmADD on x86.
		ka().emit(sew == 4 ? x86::Inst::kIdVfnmadd231ps : x86::Inst::kIdVfnmadd231pd,
			       out, b, a);
		break;
	default: Panic("qemit: unsupported direct vfma funct6");
	}
	// Identical to Emit_vchunkfalu's tail, and it must be: the helper canonicalises through
	// vf_write -> f{32,64}_canon, so any NaN this frame produces has to become the same
	// canonical quiet NaN the helper would have written.
	if (sew == 4) {
		ka().vcmpps(kscr, out, out, 3); j.mov(x86::eax, 0x7fc00000u);
		EvexOnly(j); j.vpbroadcastd(scratch(), x86::eax); j.k(kscr).vmovaps(out, scratch());
	} else {
		ka().vcmppd(kscr, out, out, 3);
		j.mov(x86::rax, 0x7ff8000000000000ull); EvexOnly(j); j.vpbroadcastq(scratch(), x86::rax);
		j.k(kscr).vmovapd(out, scratch());
	}
}

// P8. THE ONE-SOURCE FP LANE OP: the correctly-rounded square root.
//
// Structurally Emit_vchunkfalu with one input instead of two and a single opcode in the middle; the
// lane-mask prologue and the NaN-canonicalisation epilogue are deliberately the SAME sequences,
// because they must keep meaning the same thing across the three FP lane emitters.
//
// *** vsqrtps / vsqrtpd AND NOTHING ELSE. *** The reference computes std::sqrt (host-FP path) or
// softfp::op_sqrt (exact path), both of which are the IEEE-754 correctly-rounded square root, and
// x86's vsqrtp{s,d} is that same function under the current rounding mode. The 14-bit estimate
// forms -- vrsqrt14ps, vrcp14ps and a Newton-Raphson refinement -- are a DIFFERENT function: they
// are not correctly rounded, they do not raise the same inexact/invalid flags, and no runtime guard
// could express "close enough". A reciprocal-estimate lowering is not a faster version of this
// node; it is a wrong one, and there is none below.
//
// THE INACTIVE LANES, AND WHY THERE IS NO TAIL FILL HERE. `out` is preloaded with the SOURCE, as
// Emit_vchunkfalu preloads it with `a`, so every lane holds a defined value before the masked op and
// `kact` stops an inactive lane's operand from raising a spurious NV or NX. What those inactive
// lanes end up holding never reaches guest state: the frame that builds this node stores its result
// through the vl-MASKED form of vstatechunkstore, which writes only elements below the live vl and
// leaves the tail bytes of vd untouched. That is why there is no `knotw` + all-ones fill here --
// not because the tail cannot occur, but because the store, not the lane op, is what decides it.
void QEmit::Emit_vchunkfsqrt(qir::InstVChunkFSqrt *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto d = ins->o(0), ssrc = ins->i(0);
	assert_pvpr(d); assert_pvpr(ssrc);
	auto s = make_vpr(ssrc), out = make_vpr(d);
	u8 const sew = ins->sew_bytes;
	if (unlikely(sew != 4 && sew != 8))
		Panic("qemit: vchunkfsqrt with an unsupported SEW");
	u32 const chunk_w = qir::VTypeToSize(d.GetType());
	auto scratch = [&]() -> x86::Vec { return chunk_w == 16 ? x86::Vec(x86::xmm0) : chunk_w == 32 ? x86::Vec(x86::ymm0) : x86::Vec(x86::zmm0); };
	auto const [kact, kscr] = FpMaskRegs(ins->kmask, ins->chunk); // A12: see Emit_vchunkfalu
	if (!ins->kmask) {
		u32 const lanes = chunk_w / sew, base = (u32)ins->chunk * lanes;
		EmitRvvFpLaneMask(lanes, base);
		j.kmovw(kact, x86::edx);
	}
	if (ins->masked) {
		u32 const base = (u32)ins->chunk * (chunk_w / sew);
		j.movzx(x86::eax, x86::word_ptr(R_STATE, offsetof(CPUState, vec) +
			offsetof(rv32::VectorState, vreg) + base / 8));
		if (base % 8) j.shr(x86::eax, base % 8);
		j.kmovw(kscr, x86::eax); j.kandw(kact, kact, kscr);
	}
	j.vmovdqu64(out, s);
	j.k(kact).emit(sew == 4 ? x86::Inst::kIdVsqrtps : x86::Inst::kIdVsqrtpd, out, s);
	// Identical to Emit_vchunkfalu's tail, and it must be: sqrt of a negative operand produces a
	// NaN, and the helper writes it through vf_write -> f{32,64}_canon, so this frame has to
	// produce the same canonical quiet NaN rather than the host's own payload.
	if (sew == 4) {
		j.k(kact).vcmpps(kscr, out, out, 3); j.mov(x86::eax, 0x7fc00000u);
		EvexOnly(j); j.vpbroadcastd(scratch(), x86::eax); j.k(kscr).vmovaps(out, scratch());
	} else {
		j.k(kact).vcmppd(kscr, out, out, 3);
		j.mov(x86::rax, 0x7ff8000000000000ull); EvexOnly(j); j.vpbroadcastq(scratch(), x86::rax);
		j.k(kscr).vmovapd(out, scratch());
	}
}

// P9. THE MASK-PRODUCING FP COMPARE. One chunk in, one or two BYTES of a mask register out.
//
// THE PREDICATES ARE THE WHOLE CORRECTNESS ARGUMENT, because RVV 1.0 13.13 splits this family into
// two NaN behaviours and x86 spells that split in the predicate's suffix:
//
//   RVV       reference (vfcmp_apply)                    x86 imm8
//   vmfeq     quiet: only a signalling NaN raises NV      0  EQ_OQ
//   vmfne     quiet, and TRUE when either operand is NaN  4  NEQ_UQ   (unordered -> true)
//   vmflt     ordered: ANY NaN raises NV                  1  LT_OS
//   vmfle     ordered                                     2  LE_OS
//   vmfgt     ordered (.vf only)                         14  GT_OS
//   vmfge     ordered (.vf only)                         13  GE_OS
//
// The _OQ/_UQ forms are the QUIET comparisons and the _OS forms the SIGNALLING ones, which is
// exactly the reference's `quiet ? snan : nan` rule. Reaching for the more familiar NEQ_OQ or
// LT_OQ would silently stop raising NV where the ISA requires it, and no result bit would change.
//
// THE ACTIVE-LANE MASK IS NOT OPTIONAL EITHER. The compare runs under `kact`, so a lane at or above
// vl -- whose operand is whatever the register happened to hold -- cannot raise a spurious NV. It
// also zeroes those bits in the k destination, which is what lets the deposit below OR them in.
//
// THE DEPOSIT BLENDS. The reference writes bits only for active elements and leaves masked-off and
// tail bits alone, so this does a read-modify-write of the destination byte(s): clear the active
// bits, then OR the computed ones. `edx` already holds the active bit mask from the prologue, so
// the sequence needs no third scratch register: `not edx` makes it the complement, `and` keeps the
// bits this chunk does not own, and `or` sets the ones it does.
void QEmit::Emit_vchunkfcmpstate(qir::InstVChunkFCmpState *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto sa = ins->i(0), sb = ins->i(1);
	assert_pvpr(sa); assert_pvpr(sb);
	auto a = make_vpr(sa), b = make_vpr(sb);
	u8 const sew = ins->sew_bytes;
	if (unlikely(sew != 4 && sew != 8))
		Panic("qemit: vchunkfcmpstate with an unsupported SEW");
	u32 const chunk_w = qir::VTypeToSize(sa.GetType());
	u32 const lanes = chunk_w / sew, base = (u32)ins->chunk * lanes;
	// BIT-GRANULAR DEPOSIT. A chunk owns the `lanes` bits starting at bit `base`, and that span
	// never crosses a byte boundary: `lanes` is a power of two (chunk width / SEW with both
	// powers of two) and `base` is a multiple of `lanes`, so a sub-byte chunk sits entirely
	// inside one byte at bit offset `base % 8`, and a 16-lane chunk is exactly two aligned bytes.
	// The shift below is what lets the narrow shapes -- 4 lanes at VLEN 128 e32, 2 at e64 -- use
	// the same read-modify-write as the byte-aligned ones instead of being refused.
	if (unlikely(lanes == 0u || (lanes & (lanes - 1u)) != 0u))
		Panic("qemit: vchunkfcmpstate lane count is not a power of two");
	u32 const bit_off = base % 8u;
	if (unlikely(bit_off + lanes > 8u && lanes % 8u != 0u))
		Panic("qemit: vchunkfcmpstate bit span crosses a byte boundary");
	u32 const mask_bytes = lanes >= 8u ? lanes / 8u : 1u;
	if (unlikely(mask_bytes > 2u))
		Panic("qemit: vchunkfcmpstate deposit is wider than two bytes");
	auto const kact = asmjit::x86::k1, kres = asmjit::x86::k2;
	// Only active body lanes may write mask bits or raise floating-point flags.
	EmitRvvFpLaneMask(lanes, base);
	// v0.t. The guest mask's bits for this chunk live at the same bit offset in v0 that the result
	// bits occupy in vd, so the same shift lines them up. ANDing them into the active-lane mask is
	// what makes an inactive element contribute NEITHER a result bit NOR an exception -- the
	// compare never sees its operands. eax is free here: the compare has not run yet.
	if (ins->masked) {
		u32 const v0_off = (u32)(offsetof(CPUState, vec) +
					 offsetof(rv32::VectorState, vreg)) + base / 8u;
		if (mask_bytes == 2u)
			j.movzx(x86::eax, x86::word_ptr(R_STATE, (int32_t)v0_off));
		else
			j.movzx(x86::eax, x86::byte_ptr(R_STATE, (int32_t)v0_off));
		if (bit_off)
			j.shr(x86::eax, bit_off);
		j.and_(x86::edx, x86::eax);
	}
	j.kmovw(kact, x86::edx);
	u32 pred;
	switch (ins->funct6) {
	case 0b011000: pred = 0u; break;  // VF6_VMFEQ -> EQ_OQ,  quiet
	case 0b011100: pred = 4u; break;  // VF6_VMFNE -> NEQ_UQ, quiet, unordered is true
	case 0b011011: pred = 1u; break;  // VF6_VMFLT -> LT_OS,  signalling
	case 0b011001: pred = 2u; break;  // VF6_VMFLE -> LE_OS,  signalling
	case 0b011101: pred = 14u; break; // VF6_VMFGT -> GT_OS,  signalling (.vf only)
	case 0b011111: pred = 13u; break; // VF6_VMFGE -> GE_OS,  signalling (.vf only)
	default: Panic("qemit: unsupported direct vfcmp funct6");
	}
	if (sew == 4)
		j.k(kact).vcmpps(kres, a, b, pred);
	else
		j.k(kact).vcmppd(kres, a, b, pred);
	j.kmovw(x86::eax, kres); // active bits only: a masked compare zeroes the rest
	if (bit_off) {           // move both into the byte position this chunk owns
		j.shl(x86::eax, bit_off);
		j.shl(x86::edx, bit_off);
	}
	j.not_(x86::edx);        // edx was the active bit mask; now it is its complement
	auto mem = x86::ptr(R_STATE, (int32_t)ins->offs, mask_bytes);
	if (mask_bytes == 2u) {
		j.and_(mem, x86::dx);
		j.or_(mem, x86::ax);
	} else {
		j.and_(mem, x86::dl);
		j.or_(mem, x86::al);
	}
}

// P10. THE WIDENING CONVERT: one f32 lane per f64 lane, exact.
//
// `vcvtps2pd` reads HALF the destination's width (a 32-byte source for a 64-byte destination) and
// widens each single to a double. The conversion is exact for every finite value, so no rounding
// mode applies to it and the family's single rounding happens in the vchunkfalu that consumes this
// result -- which is precisely the reference's structure.
//
// THE READ IS ALWAYS chunk_w/2 BYTES, WHICH IS NOT ALWAYS THE WHOLE SOURCE REGISTER. At a 16-byte
// destination chunk (VLEN 128) the window is 8 bytes and qir has no 8-byte vector value, so the
// frame hands this node a 16-byte source and `vcvtps2pd xmm, xmm` converts its LOW 2 f32 lanes and
// ignores the rest. That is the node's operand contract (qir.h), re-checked here because getting it
// wrong would silently convert the WRONG lanes rather than fail: an over-wide source with the same
// destination is a legal x86 encoding.
//
// IT IS MASKED, and that is not decoration: an INACTIVE lane may hold any bit pattern, including a
// signalling NaN, and converting it would raise NV for an element the instruction does not touch.
// The destination is zeroed first so the inactive lanes carry a defined value into the arithmetic
// node rather than whatever the allocator's register happened to hold.
void QEmit::Emit_vchunkfwidencvt(qir::InstVChunkFWidenCvt *ins)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	namespace x86 = asmjit::x86;
	auto d = ins->o(0), ssrc = ins->i(0);
	assert_pvpr(d); assert_pvpr(ssrc);
	auto out = make_vpr(d), s = make_vpr(ssrc);
	// The destination holds f64 lanes; its own width gives the lane count and the element index
	// base, so this node and the vchunkfalu that consumes it derive the SAME active mask.
	u32 const chunk_w = qir::VTypeToSize(d.GetType());
	u32 const lanes = chunk_w / 8u, base = (u32)ins->chunk * lanes;
	if (unlikely(lanes == 0u))
		Panic("qemit: vchunkfwidencvt destination is narrower than one f64 lane");
	u32 const half = chunk_w / 2u, want = half < 16u ? 16u : half;
	if (unlikely(qir::VTypeToSize(ssrc.GetType()) != want))
		Panic("qemit: vchunkfwidencvt source is not this destination's f32 window");
	// THE SHARED MASK, not a copy of it: EmitRvvFpLaneMask derives the vl window AND removes the
	// prestart lanes, so this node needs no vstart rule of its own, and the v0 fold below is the
	// same four lines the falu lane op and the masked state store use. Getting this wrong is not a
	// value bug -- it is an EXCEPTION bug: an inactive lane holding a signalling NaN would raise NV
	// for an element the instruction does not touch.
	auto const kact = asmjit::x86::k1;
	EmitRvvFpLaneMask(lanes, base);
	if (ins->masked) {
		j.movzx(x86::eax, x86::word_ptr(R_STATE, (int32_t)offsetof(CPUState, vec) +
			(int32_t)offsetof(rv32::VectorState, vreg) + base / 8u));
		if (base % 8u)
			j.shr(x86::eax, base % 8u);
		j.and_(x86::edx, x86::eax);
	}
	j.kmovw(kact, x86::edx);
	EvexOnly(j);
	j.vpxorq(out, out, out);
	j.k(kact).vcvtps2pd(out, s);
}

void QEmit::Emit_rvvqcgfpend(qir::InstRVVQCGFPEnd *)
{
	rvv_typed_chunk_seen += rvv_typed_chunk_open;
	// S1-1. THE JOIN, AND ITS POSITION IS THE CONTRACT. Every active-VL bound in this frame lands
	// here -- BEFORE the bracket closes, so a body that left early still folds MXCSR's exception
	// bits into fflags, still restores the saved MXCSR, and still clears vec.vstart below. Binding
	// it any later (at rvv_typed_chunk_join, say) would leave the host FP environment open on the
	// early-exit path; binding it at the fallback would re-run the ordered helpers over chunks the
	// body already stored.
	if (rvv_typed_chunk_bound_open) {
		j.bind(rvv_typed_chunk_body_done);
		rvv_typed_chunk_bound_open = false;
	}
	EmitCloseRvvFpBracket();
	j.mov(asmjit::x86::dword_ptr(R_STATE, (int32_t)offsetof(CPUState, vec) +
		(int32_t)offsetof(rv32::VectorState, vstart)), 0);
}

void QEmit::EmitCloseRvvFpBracket()
{
	namespace x86 = asmjit::x86;
	auto const fpu = (int32_t)offsetof(CPUState, fpu);
	auto const saved = fpu + (int32_t)offsetof(rv32::FPUState, fround_run_saved_mxcsr);
	auto const cur = fpu + (int32_t)offsetof(rv32::FPUState, qcg_current_mxcsr);
	auto const fcsr = fpu + (int32_t)offsetof(rv32::FPUState, fcsr);
	auto flag = [&](u32 host, u32 guest) {
		auto skip = j.newLabel();
		j.test(x86::eax, host); j.jz(skip);
		j.or_(x86::dword_ptr(R_STATE, fcsr), guest); j.bind(skip);
	};
	j.stmxcsr(x86::dword_ptr(R_STATE, cur));
	j.mov(x86::eax, x86::dword_ptr(R_STATE, cur));
	flag(1u << 0, 0x10); flag(1u << 2, 0x08); flag(1u << 3, 0x04);
	flag(1u << 4, 0x02); flag(1u << 5, 0x01);
	j.ldmxcsr(x86::dword_ptr(R_STATE, saved));
	j.mov(x86::byte_ptr(R_STATE, fpu + (int32_t)offsetof(rv32::FPUState, fround_run_open)), 0);
}

// T7S direct-QCG vector setup. Ordinary vsetvli and vsetivli forms use this straight-line sequence;
// no helper call or workload-specific constant participates:
//
//     mov   eax, <vlmax>                      ; scratch = VLMAX
//     cmp   <pavl>, eax
//     cmovb eax, <pavl>                       ; UNSIGNED below -> scratch = min(AVL, VLMAX)
//     mov   <prd>, eax                        ; guest rd <- vl
//     mov   dword [r13 + vec.vtype ], <vtype> ; the four architectural fields, in HANDLER order
//     mov   dword [r13 + vec.vl    ], eax
//     mov   dword [r13 + vec.vstart], 0
//     mov   dword [r13 + vec.vlenb ], <vlenb>
//
// EVERY OFFSET IS AN offsetof AND NEVER A NUMBER, exactly as Emit_rvvtypedchunkbegin writes the two
// offsets it compares. That guard reads vec.vtype and vec.vl back; if the two disagreed about where
// those fields live, twelve accepted typed frames would silently become twelve helper fallbacks.
//
// cmovb, NOT cmovl. The compare is unsigned because rv32_interp.cpp's HANDLER(vsetvli) computes
// `avl < vlmax ? avl : vlmax` on u32. The two conditions agree on every AVL below 2^31; on the top
// half of the domain a signed compare would treat 0x80000000..0xffffffff as BELOW VLMAX and return
// them as vl. See qir.h InstRVVSetVL.
//
// NO CONSTANT RESULT. `vlmax` is one input of a min whose other input is a runtime register; it is
// not the answer. The frozen workload's every strip step happens to have AVL >= VLMAX, so a `mov
// <prd>, <vlmax>` with no compare at all would pass every whole-suite arm this chain has -- which is
// exactly why the route's AVL-boundary evidence exists and why this sequence must stay as written.
//
// The rd=x0,rs1=x0 keep-vl form uses a small conditional sequence: retain current VL and install
// the legal vtype when VL <= new VLMAX; otherwise install vill and zero VL/vstart. EAX IS
// ArchTraits::AX, which QMC_FIXED_REGS puts in GPR_FIXED and therefore outside GPR_POOL for
// the whole region, so writing it cannot destroy an allocated value and it needs no operand -- the
// same scratch idiom Emit_vchunkload and Emit_vchunkstore already use. Here it does one more job:
// it is what makes the sequence CORRECT WHEN `prd` AND `pavl` ARE THE SAME HOST REGISTER (the
// rd == rs1 form) without the emitter having to compare register ids. The scratch can alias
// neither, every read of `pavl` happens before the single write of `prd`, and the two Panics below
// are what keep that argument true rather than assumed.
void QEmit::Emit_rvvsetvlreg(qir::InstRVVSetVLReg *ins)
{
	namespace x86 = asmjit::x86;
	if (rvv_typed_chunk_open || rvv_diag_chunk_open)
		Panic("qemit: runtime vsetvl inside vector operation");
	for (auto op : {ins->o(0), ins->i(0), ins->i(1)}) {
		if (!op.IsPGPR() || op.GetType() != qir::VType::I32 || op.GetPGPR() == ArchTraits::AX)
			Panic("qemit: runtime vsetvl requires allocated nonscratch I32 operands");
	}
	auto const dst = make_gpr(ins->o(0));
	auto const avl = make_gpr(ins->i(0));
	auto const vt = make_gpr(ins->i(1));
	auto const scratch = make_gpr(ArchTraits::AX, qir::VType::I32);
	auto const state = (int32_t)offsetof(CPUState, vec);
	auto const vl_off = state + (int32_t)offsetof(rv32::VectorState, vl);
	auto const vt_off = state + (int32_t)offsetof(rv32::VectorState, vtype);
	auto const start_off = state + (int32_t)offsetof(rv32::VectorState, vstart);
	auto const bytes_off = state + (int32_t)offsetof(rv32::VectorState, vlenb);
	auto invalid = j.newLabel(), commit = j.newLabel(), data = j.newLabel(), done = j.newLabel();
	auto const *table = rv32::vlmax_table_for(ins->vlenb * 8);
	if (!table) Panic("qemit: runtime vsetvl unsupported VLEN");
	// Check the entire RV32 value before indexing; masking would silently accept vill
	// or reserved high bits. Embedded data avoids process-local pointers in generated code.
	j.cmp(vt, asmjit::imm(255));
	j.ja(invalid);
	j.lea(scratch.r64(), x86::ptr(data));
	j.movzx(scratch, x86::word_ptr(scratch.r64(), vt.r64(), 1));
	j.test(scratch, scratch);
	j.jz(invalid);
	if (ins->keep_vl) {
		j.cmp(scratch, x86::dword_ptr(R_STATE, vl_off));
		j.jb(invalid);
		j.mov(scratch, x86::dword_ptr(R_STATE, vl_off));
	} else {
		j.cmp(scratch, avl);
		j.cmova(scratch, avl);
	}
	// Consume both source registers before writing dst, including rd==rs2.
	j.mov(x86::dword_ptr(R_STATE, vt_off), vt);
	j.mov(x86::dword_ptr(R_STATE, bytes_off), asmjit::imm(ins->vlenb));
	j.jmp(commit);
	j.bind(invalid);
	j.xor_(scratch, scratch);
	j.mov(x86::dword_ptr(R_STATE, vt_off), asmjit::imm(rv32::VTYPE_VILL_BIT));
	j.bind(commit);
	j.mov(dst, scratch);
	j.mov(x86::dword_ptr(R_STATE, vl_off), scratch);
	j.mov(x86::dword_ptr(R_STATE, start_off), asmjit::imm(0));
	j.jmp(done);
	j.bind(data);
	j.embed(table->vlmax, sizeof(table->vlmax));
	j.bind(done);
}

void QEmit::Emit_rvvsetvl(qir::InstRVVSetVL *ins)
{
	namespace x86 = asmjit::x86;

	// The typed chunk group's invariant, mirrored from Emit_mov. Everything between a group's
	// guard and its fallback label is branched over when the guard fails, so nothing but the
	// group's own typed body ops may be emitted there. This op is never routed inside a group --
	// TRANSLATOR(vsetvli) emits it alone -- and stating that here turns a future routing change
	// into a loud translation failure instead of a silently skipped state write.
	if (unlikely(rvv_typed_chunk_open)) {
		Panic("qemit: rvvsetvl inside a typed chunk group");
	}
	if (unlikely(rvv_diag_chunk_open)) {
		Panic("qemit: rvvsetvl inside a diagnostic chunk group");
	}

	auto vrd = ins->o(0);
	auto vavl = ins->i(0);
	// CT(rvvsetvl, r_r) declares both operands register-only, so QSel has already materialised
	// any constant AVL into a register. Fail closed rather than encode a `cmov` whose source has
	// no immediate form.
	if (unlikely(!vrd.IsPGPR() || vrd.GetType() != qir::VType::I32)) {
		Panic("qemit: rvvsetvl result is not an allocated 32-bit GPR");
	}
	if (unlikely(!vavl.IsPGPR() || vavl.GetType() != qir::VType::I32)) {
		Panic("qemit: rvvsetvl AVL operand is not an allocated 32-bit GPR");
	}
	// The whole rd == rs1 argument rests on the scratch aliasing neither operand. GPR_FIXED
	// makes that true for every allocation QRegAlloc can produce; this is what fails loudly if a
	// future allocator change stopped making it true.
	if (unlikely(vrd.GetPGPR() == ArchTraits::AX || vavl.GetPGPR() == ArchTraits::AX)) {
		Panic("qemit: rvvsetvl operand was allocated the fixed scratch register");
	}

	auto const prd = make_gpr(vrd);
	auto const pavl = make_gpr(vavl);
	auto const scratch = make_gpr(ArchTraits::AX, qir::VType::I32);

	auto const vec_off = (int32_t)offsetof(CPUState, vec);
	auto const vtype_off = vec_off + (int32_t)offsetof(rv32::VectorState, vtype);
	auto const vl_off = vec_off + (int32_t)offsetof(rv32::VectorState, vl);
	auto const vstart_off = vec_off + (int32_t)offsetof(rv32::VectorState, vstart);
	auto const vlenb_off = vec_off + (int32_t)offsetof(rv32::VectorState, vlenb);

	if (ins->keep_vl) {
		// Architectural rd=x0,rs1=x0 rule: retain VL if it fits the new VLMAX. Otherwise the
		// encoding is reserved and produces vill, vl=0, vstart=0 without changing vlenb.
		auto reserved = j.newLabel(), done = j.newLabel();
		j.mov(scratch, x86::dword_ptr(R_STATE, vl_off));
		j.cmp(scratch, asmjit::imm(ins->vlmax));
		j.ja(reserved);
		j.mov(x86::dword_ptr(R_STATE, vtype_off), asmjit::imm(ins->vtype));
		j.mov(x86::dword_ptr(R_STATE, vstart_off), asmjit::imm(0));
		j.mov(x86::dword_ptr(R_STATE, vlenb_off), asmjit::imm(ins->vlenb));
		j.jmp(done);
		j.bind(reserved);
		j.mov(x86::dword_ptr(R_STATE, vtype_off), asmjit::imm(rv32::VTYPE_VILL_BIT));
		j.mov(x86::dword_ptr(R_STATE, vl_off), asmjit::imm(0));
		j.mov(x86::dword_ptr(R_STATE, vstart_off), asmjit::imm(0));
		j.bind(done);
		return;
	}

	j.mov(scratch, asmjit::imm(ins->vlmax));
	j.cmp(pavl, scratch);
	j.cmovb(scratch, pavl);
	j.mov(prd, scratch);
	j.mov(x86::dword_ptr(R_STATE, vtype_off), asmjit::imm(ins->vtype));
	j.mov(x86::dword_ptr(R_STATE, vl_off), scratch);
	j.mov(x86::dword_ptr(R_STATE, vstart_off), asmjit::imm(0));
	if (ins->vlmax)
		j.mov(x86::dword_ptr(R_STATE, vlenb_off), asmjit::imm(ins->vlenb));
}

// P is an LLVM-AOT substrate.  Reaching any typed vector-SSA instruction in
// the scalar-only AsmJit allocator is a routing bug, never an invitation to
// silently re-opaqueify it as a helper call.
#define RVV_SSA_QCG_UNSUPPORTED(name, cls)                                                                   \
	void QEmit::Emit_##name(qir::cls *)                                                                     \
	{                                                                                                      \
		Panic("typed RVV SSA reached the QCG backend");                                                  \
	}
RVV_SSA_QCG_UNSUPPORTED(rvvread, InstRVVRead)
RVV_SSA_QCG_UNSUPPORTED(rvvwrite, InstRVVWrite)
RVV_SSA_QCG_UNSUPPORTED(rvvsplatf, InstRVVSplatF)
RVV_SSA_QCG_UNSUPPORTED(rvvload, InstRVVLoad)
RVV_SSA_QCG_UNSUPPORTED(rvvstore, InstRVVStore)
RVV_SSA_QCG_UNSUPPORTED(rvvfcmp, InstRVVFCmp)
RVV_SSA_QCG_UNSUPPORTED(rvvmerge, InstRVVMerge)
RVV_SSA_QCG_UNSUPPORTED(rvvfalu, InstRVVFALU)
RVV_SSA_QCG_UNSUPPORTED(rvvfma, InstRVVFMA)
RVV_SSA_QCG_UNSUPPORTED(rvvfpbegin, InstRVVFPBegin)
RVV_SSA_QCG_UNSUPPORTED(rvvfpend, InstRVVFPEnd)
#undef RVV_SSA_QCG_UNSUPPORTED

void QEmit::Emit_setcc(qir::InstSetcc *ins)
{
	auto prd = make_gpr(ins->o(0));
	auto vs0 = ins->i(0);
	auto vs1 = ins->i(1);
	auto cc = ins->cc;

	bool dst_aliased = vs0.GetPGPR() == prd.id() || (vs1.IsPGPR() && vs1.GetPGPR() == prd.id());

	if (!dst_aliased) {
		j.xor_(prd, prd);
	}

	j.emit(asmjit::x86::Inst::kIdCmp, make_operand(vs0), make_operand(vs1));
	auto setcc = asmjit::x86::Inst::setccFromCond(make_cc(cc));
	j.emit(setcc, prd.r8());

	if (dst_aliased) {
		j.movzx(prd, prd.r8());
	}
}

// V512 copy / spill / fill.  The vector file has no scalar `mov`; this is vmovdqu64, and it must
// be the UNALIGNED form.  The spill frame is addressed as [R_SP + 8|16 + slot_offs] and the
// trampoline that reserves it guarantees no more than 16-byte alignment (arch_traits.h), so a
// 64-byte slot is not 64-byte aligned at run time and vmovdqa64 would #GP.  EVEX memory operands
// carry no alignment requirement, so the unaligned encoding costs nothing when the address does
// happen to be aligned.
//
// Only three operand pairs are legal, and they are exactly the three the register allocator
// creates (QRegAlloc::EmitSpill / EmitFill / the copy in AllocOpInputV).  Anything else -- an
// immediate, or memory-to-memory -- fails closed instead of being silently mis-encoded.
// M2C. Every copy, spill and fill of a vector value moves EXACTLY that value's width: make_vpr
// picks the register form from the type and make_slot sets the `Mem` size from VTypeToSize, which
// is the same function QRegAlloc::AllocFrameSlot sized the slot with. A V128 therefore spills 16
// bytes into a 16-byte slot and fills 16 back -- the allocator and the emitter cannot disagree
// about a width because neither of them chooses it.
//
// A pair whose two ends disagree about width would be a copy between different types, which is not
// something the allocator can construct (it copies a value to itself elsewhere) and which the
// check below refuses rather than silently encoding at the destination's width.
void QEmit::EmitVecMov(qir::VOperand vrd, qir::VOperand vs0)
{
	if (unlikely(vrd.GetType() != vs0.GetType())) {
		Panic("qemit: vector mov between two different host vector widths");
	}
	if (vrd.IsPVPR() && vs0.IsPVPR()) {
		EvexOnly(j);
		j.vmovdqu64(make_vpr(vrd), make_vpr(vs0));
		return;
	}
	if (vrd.IsPVPR() && vs0.IsSlot()) { // fill
		EvexOnly(j);
		j.vmovdqu64(make_vpr(vrd), make_slot(vs0));
		return;
	}
	if (vrd.IsSlot() && vs0.IsPVPR()) { // spill
		EvexOnly(j);
		j.vmovdqu64(make_slot(vrd), make_vpr(vs0));
		return;
	}
	Panic("qemit: unsupported vector mov operand pair");
}

void QEmit::Emit_mov(qir::InstUnop *ins)
{
	// The typed chunk group's invariant (qir.h InstRVVTypedChunkBegin). Every instruction
	// QRegAlloc inserts -- spill, fill, copy, side-effect global sync -- is a `mov`, and one
	// landing inside the group would be branched over on the fallback path. A skipped global sync
	// loses a guest register write, so this fails translation loudly rather than emitting it.
	if (unlikely(rvv_typed_chunk_open)) {
		Panic("qemit: register-allocator mov inside a typed chunk group");
	}
	auto vrd = ins->o(0);
	auto vs0 = ins->i(0);
	if (qir::IsVectorVType(vrd.GetType()) || qir::IsVectorVType(vs0.GetType())) {
		EmitVecMov(vrd, vs0);
		return;
	}
	// TODO: slowed code by ~3%, try again after bb merging
	if (unlikely(false && vs0.IsConst() && vs0.GetConst() == 0 && vrd.IsPGPR())) {
		auto prd = make_gpr(vrd);
		j.emit(asmjit::x86::Inst::kIdXor, prd, prd);
		return;
	}
	j.emit(asmjit::x86::Inst::kIdMov, make_operand(vrd), make_operand(vs0));
}

template <asmjit::x86::Inst::Id Op>
ALWAYS_INLINE void QEmit::EmitInstBinop(qir::InstBinop *ins)
{
	auto &vrd = ins->o(0);
	[[maybe_unused]] auto vs0 = ins->i(0);
	auto vs1 = ins->i(1);

	assert(vrd.GetPGPR() == vs0.GetPGPR());
	j.emit(Op, make_gpr(vrd), make_operand(vs1));
}

void QEmit::Emit_add(qir::InstBinop *ins)
{
	EmitInstBinop<asmjit::x86::Inst::kIdAdd>(ins);
}

void QEmit::Emit_sub(qir::InstBinop *ins)
{
	EmitInstBinop<asmjit::x86::Inst::kIdSub>(ins);
}

void QEmit::Emit_and(qir::InstBinop *ins)
{
	EmitInstBinop<asmjit::x86::Inst::kIdAnd>(ins);
}

void QEmit::Emit_or(qir::InstBinop *ins)
{
	EmitInstBinop<asmjit::x86::Inst::kIdOr>(ins);
}

void QEmit::Emit_xor(qir::InstBinop *ins)
{
	EmitInstBinop<asmjit::x86::Inst::kIdXor>(ins);
}

void QEmit::Emit_sra(qir::InstBinop *ins)
{
	[[maybe_unused]] auto vs1 = ins->i(1);
	assert(vs1.IsConst() || vs1.GetPGPR() == asmjit::x86::Gp::kIdCx);
	EmitInstBinop<asmjit::x86::Inst::kIdSar>(ins);
}

void QEmit::Emit_srl(qir::InstBinop *ins)
{
	[[maybe_unused]] auto vs1 = ins->i(1);
	assert(vs1.IsConst() || vs1.GetPGPR() == asmjit::x86::Gp::kIdCx);
	EmitInstBinop<asmjit::x86::Inst::kIdShr>(ins);
}

void QEmit::Emit_sll(qir::InstBinop *ins)
{
	[[maybe_unused]] auto vs1 = ins->i(1);
	assert(vs1.IsConst() || vs1.GetPGPR() == asmjit::x86::Gp::kIdCx);
	EmitInstBinop<asmjit::x86::Inst::kIdShl>(ins);
}

// Regular multiplication (lower word)
void QEmit::Emit_mul(qir::InstBinop *ins)
{
	EmitInstBinop<asmjit::x86::Inst::kIdImul>(ins);
}

// Signed high multiplication
void QEmit::Emit_mulh(qir::InstBinop *ins)
{
	// Signed high multiplication - use 64-bit IMUL and arithmetic shift
	// j.emit(asmjit::x86::Inst::kIdImul, make_gpr(ins->o(0)), make_gpr(ins->i(0)), make_gpr(ins->i(1)));

	auto prd = make_gpr(ins->o(0));
    auto prs0 = make_gpr(ins->i(0)); //r
    auto prs1 = make_gpr(ins->i(1)); //bx

	assert(prs1.id() == asmjit::x86::Gp::kIdBx);
	auto eax = asmjit::x86::eax;
	auto edx = asmjit::x86::edx;
	j.mov(eax, prs0);
	j.imul(prs1);
	j.mov(prd, edx);
}

// Mixed signed/unsigned high multiplication
void QEmit::Emit_mulhsu(qir::InstBinop *ins)
{
	auto prd = make_gpr(ins->o(0));
    auto prs0 = make_gpr(ins->i(0)); //r
    auto prs1 = make_gpr(ins->i(1)); //bx

	assert(prs1.id() == asmjit::x86::Gp::kIdBx);
	auto eax = asmjit::x86::eax;
	auto rax = asmjit::x86::rax;
	auto rbx = asmjit::x86::rbx;
	auto edx = asmjit::x86::edx;
	j.mov(prd, edx);
	j.mov(eax, prs0);
	j.movsxd(rax, eax);
	j.mul(rbx);
	j.sar(rax, 32);
	j.mov(edx, prd);
	j.mov(prd, eax);
}
// Unsigned high multiplication
void QEmit::Emit_mulhu(qir::InstBinop *ins)
{
	// j.emit(asmjit::x86::Inst::kIdMul, make_gpr(ins->o(0)), make_gpr(ins->i(0)), make_gpr(ins->i(1)));

	auto prd = make_gpr(ins->o(0));
    auto prs0 = make_gpr(ins->i(0)); //r
    auto prs1 = make_gpr(ins->i(1)); //bx

	assert(prs1.id() == asmjit::x86::Gp::kIdBx);
	auto eax = asmjit::x86::eax;
	auto edx = asmjit::x86::edx;
	j.mov(eax, prs0);
	j.mul(prs1);
	j.mov(prd, edx);
}

// Signed division
void QEmit::Emit_div(qir::InstBinop *ins)
{
    auto prs0 = make_gpr(ins->i(0));
    auto prs1 = make_gpr(ins->i(1));
    auto prd = make_gpr(ins->o(0));
    auto end = j.newLabel();
	auto div = j.newLabel();

    // Check division by zero
	j.mov(prd, asmjit::Imm(0xFFFFFFFF));
	j.test(prs1, prs1);
    j.jz(end);  // If zero, use 0xFFFFFFFF already in prd
    
    // Check INT32_MIN / -1 overflow case
    j.cmp(prs0, INT32_MIN);
    j.jne(div);  // If not INT32_MIN, do normal division
    j.cmp(prs1, -1);
    j.jne(div);  // If not -1, do normal division
    j.mov(prd, INT32_MIN);
    j.jmp(end);

    // Normal division
    j.bind(div);
	j.mov(asmjit::x86::eax, prs0);
	j.cdq();
    j.idiv(prs1);
	j.mov(prd, asmjit::x86::eax);
    
    j.bind(end);
}

// Unsigned division
void QEmit::Emit_divu(qir::InstBinop *ins)
{
    // Check for division by zero
	auto prs0 = make_gpr(ins->i(0));
	auto prs1 = make_gpr(ins->i(1));
	auto prd = make_gpr(ins->o(0));
	j.mov(prd, asmjit::Imm(0xFFFFFFFF));
	j.test(prs1, prs1);
	asmjit::Label zero = j.newLabel();
	j.jz(zero);

	j.xor_(asmjit::x86::edx, asmjit::x86::edx);  // Clear high bits	
	j.mov(asmjit::x86::eax, prs0);
    j.div(prs1);  // Do unsigned division
    j.mov(prd, asmjit::x86::eax);  // Move result
	
	j.bind(zero);
}

// Signed remainder
void QEmit::Emit_rem(qir::InstBinop *ins)
{
	auto prs0 = make_gpr(ins->i(0));
	auto prs1 = make_gpr(ins->i(1));
	auto prd = make_gpr(ins->o(0));
	asmjit::Label end = j.newLabel();
	asmjit::Label rem = j.newLabel();
	j.mov(prd, prs0);
	j.test(prs1, prs1);
	j.jz(end);

	j.cmp(prs0, INT32_MIN);
    j.jne(rem);  // If not INT32_MIN, do normal division
    j.cmp(prs1, -1);
    j.jne(rem);  // If not -1, do normal division
    j.mov(prd, 0);
    j.jmp(end);

	j.bind(rem);
	j.mov(asmjit::x86::eax, prs0);
	j.cdq();
    j.idiv(prs1);  // Do signed division
    j.mov(prd, asmjit::x86::edx);  // Move result
	
	j.bind(end);
}

// Unsigned remainder
void QEmit::Emit_remu(qir::InstBinop *ins)
{
	auto prs0 = make_gpr(ins->i(0));
	auto prs1 = make_gpr(ins->i(1));
	auto prd = make_gpr(ins->o(0));
	j.mov(prd, prs0);
	j.test(prs1, prs1);
	asmjit::Label zero = j.newLabel();
	j.jz(zero);

	j.xor_(asmjit::x86::edx, asmjit::x86::edx);  // Clear high bits	
	j.mov(asmjit::x86::eax, prs0);
    j.div(prs1);  // Do unsigned division
    j.mov(prd, asmjit::x86::edx);  // Move result
	
	j.bind(zero);
}

} // namespace dbt::qcg
