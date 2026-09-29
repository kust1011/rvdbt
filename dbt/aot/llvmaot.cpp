#include "dbt/aot/aot.h"
#include "dbt/aot/loop_region.h"
#include "dbt/qmc/qir_printer.h"
#include "dbt/guest/rv32_analyser.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_insn.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qcg/jitabi.h"
#include "dbt/tcache/objprof.h"
#include "dbt/execute.h"

#include <algorithm>
#include <chrono>
#include <fcntl.h>
#include <fstream>
#include <set>
#include <sstream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Config/llvm-config.h" /* LLVM_VERSION_MAJOR, for the API guards below */
#include "llvm/TargetParser/SubtargetFeature.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <unordered_map>
#include <unordered_set>
#include "llvm/Support/FileSystem.h"
#include "llvm/TargetParser/Host.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#if __has_include("llvm/Target/TargetIntrinsicInfo.h")
// Removed in LLVM 21+. Build-compatibility only: this TU is the LLVM AOT path, which the RVV
// interpreter/JIT execution path does not use, so guarding it cannot change execution semantics.
#include "llvm/Target/TargetIntrinsicInfo.h"
#endif
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/Transforms/IPO/MergeFunctions.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Instrumentation/PGOInstrumentation.h"
#include "llvm/Transforms/Scalar/EarlyCSE.h"
#include "llvm/Transforms/Scalar/Reassociate.h"
#include "llvm/Transforms/Scalar/SimplifyCFG.h"
#include "llvm/Transforms/Scalar.h"

namespace dbt
{
LOG_STREAM(aot)

// LLVM 22 finished the move to debug RECORDS: debug info is no longer carried by intrinsic
// instructions in the instruction list, so Instruction::getNextNonDebugInstruction() was removed
// and getNextNode() performs the identical walk. Build compatibility only -- both spellings visit
// the same instructions on their respective LLVM versions.
static inline llvm::Instruction *NextNonDebugInsn(llvm::Instruction *i)
{
#if LLVM_VERSION_MAJOR >= 22
	return i->getNextNode();
#else
	return i->getNextNonDebugInstruction();
#endif
}

// A-line 2026-07-23 (--aot-edge-move-not-copy): internalized merge targets are MOVED into their
// source's function instead of copied. g_move_fired maps target-region entry ip -> source REGION
// entry ip (function symbol base); g_move_source_regions holds region entry ips that own at least
// one fired merge source (never thunked themselves); g_move_thunks records every emitted thunk for
// the post-translation entry-switch-case verification (abort > wrong artifact).
static std::unordered_map<u32, u32> g_move_fired;
static std::unordered_set<u32> g_move_source_regions;
static std::vector<std::pair<u32, u32>> g_move_thunks; // (tgt, src_region_ip)

struct LLVMAOTCompilerRuntime final : CompilerRuntime {
	LLVMAOTCompilerRuntime() {}

	void *AllocateCode(size_t sz, uint align) override
	{
		unreachable("");
	}

	bool AllowsRelocation() const override
	{
		unreachable("");
	}

	// void *AnnounceRegion(u32 ip, std::span<u8> const &code) override
	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override
	{
		unreachable("");
	}
};

u64 getMaxExecCountInRegion(std::vector<dbt::ModuleGraphNode *> const &region)
{
	u64 mx_cnt = 0;
	ModuleGraphNode *mx_n = nullptr;
	for (auto const &n : region) {
		if (n->flags.exec_count > mx_cnt) {
			mx_cnt = n->flags.exec_count;
			mx_n = n;
		}
	}

	if (mx_n && mx_n->flags.is_critical) {
		// log_dbt("critical region: %08x", region[0]->ip);
		log_dbt("critical region: %08x", mx_n->ip);
	}

	return mx_cnt;
}

// V-next: is `ip` a RETURN target (i.e., call_site+4)? A return lands immediately after a JAL- or
// JALR-with-rd!=0 call. Both encodings are used by the RISC-V toolchain.
// Dispatch-jump targets (jump-table handlers) are NOT preceded by a call. This statically separates indirect-dispatch
// handlers (which the method wants) from incidental returns (which it must NOT over-compile), using only guest code.
static bool IsReturnTarget(u32 ip)
{
	if (ip < 4)
		return false;
	u32 prev = *reinterpret_cast<u32 const *>((uptr)mmu::base + (uptr)(ip - 4));
	// RV32 JAL opcode = 0x6f, JALR opcode = 0x67; rd = bits[11:7].
	u32 opcode = prev & 0x7f;
	return (opcode == 0x6f || opcode == 0x67) && ((prev >> 7) & 0x1f) != 0;
}

// V-next dispatch-aware admission: admit a region if it is hot by the global threshold, OR if it is an
// indirect-dispatch HANDLER -- a brind_target entry (not a return target) that EXECUTED above the dispatch floor.
// Recovers handlers Wendell under-admits because exec_count propagation does not cross indirect edges. A static
// hot-successor refinement was REJECTED (computed-goto/threaded handlers exit via indirect jumps, so they have no
// direct graph edge to the dispatcher -> it killed the wins). Clean source-vs-incidental separation needs the runtime
// indirect-edge profile (source hotness); the return-target exclusion is the static partial filter that exists today.
// Round-15 DIA: lazily-loaded island-admission set (entry ips computed offline from the indirect edge profile).
static const std::unordered_set<u32> &AdmitList()
{
	static std::unordered_set<u32> set = [] {
		std::unordered_set<u32> s;
		if (dbt::config::dispatch_admit_list) {
			FILE *f = fopen(dbt::config::dispatch_admit_list, "r");
			if (f) {
				u32 ip;
				while (fscanf(f, "%x", &ip) == 1)
					s.insert(ip);
				fclose(f);
			}
		}
		return s;
	}();
	return set;
}

// A-line 2026-07-27 fair-budget oracle tooling: the exact complement of AdmitList() above --
// mirrors its loading logic exactly, sourced from dispatch_deny_list instead.
static const std::unordered_set<u32> &DenyList()
{
	static std::unordered_set<u32> set = [] {
		std::unordered_set<u32> s;
		if (dbt::config::dispatch_deny_list) {
			FILE *f = fopen(dbt::config::dispatch_deny_list, "r");
			if (f) {
				u32 ip;
				while (fscanf(f, "%x", &ip) == 1)
					s.insert(ip);
				fclose(f);
			}
		}
		return s;
	}();
	return set;
}

// A-line move-not-copy: replace a fired merge target's standalone body with a 2-instruction thunk
// re-entering the source function's multi-entry state->ip switch. Correct for BOTH entry paths:
// dispatch entries already have state->ip == tgt (the store is idempotent), and direct-branch-slot
// entries do NOT set state->ip -- hence the explicit store. The callsite is NoInline so the O3
// module inliner cannot paste the source body back in (which would recreate the duplication this
// mechanism removes).
static void EmitMoveThunk(qir::LLVMGenCtx *ctx, u32 tgt_ip, u32 src_region_ip)
{
	auto *fn = ctx->cmodule.getFunction(MakeAotSymbol(tgt_ip));
	auto *src_fn = ctx->cmodule.getFunction(MakeAotSymbol(src_region_ip));
	assert(fn && fn->empty() && src_fn);
	auto *bb = llvm::BasicBlock::Create(ctx->cmodule.getContext(), "entry", fn);
	llvm::IRBuilder<> b(bb);
	auto *ipp = b.CreateConstInBoundsGEP1_64(b.getInt8Ty(), fn->getArg(0), offsetof(CPUState, ip));
	b.CreateStore(b.getInt32(tgt_ip), ipp);
	auto *call = b.CreateCall(ctx->qcg_fnty, src_fn, {fn->getArg(0), fn->getArg(1)});
	call->setCallingConv(llvm::CallingConv::GHC);
	call->setTailCall(true);
	call->setTailCallKind(llvm::CallInst::TCK_MustTail);
	call->addFnAttr(llvm::Attribute::NoInline);
	b.CreateRetVoid();
	g_move_thunks.push_back({tgt_ip, src_region_ip});
	fprintf(stderr, "EDGE_MOVE_THUNK tgt=%08x src_fn=%08x\n", tgt_ip, src_region_ip);
}

// Design 8 multi-entry (--aot-link-multientry-merge): `t_ip` is a link-merged return-continuation
// whose actual code now lives inside `primary_ip`'s own function (added to that function's
// merge_entries + entry switch by the caller, BEFORE this runs -- Run() must build the switch
// case for `t_ip` first, since a wrapper calling into a function with no matching switch case
// would silently fall to the default arm with the wrong effective entry). This creates the thin
// EXTERNAL stub at `t_ip`'s own address: set state->ip=t_ip, then GHC-tailcall the primary's own,
// unrenamed, still-normally-callable function. Unlike Round-41's --aot-merge-max (which renames
// the shared body to an internal `_mw_*` symbol and wraps EVERY group member, including the
// primary), the primary keeps its own name/direct-call fast path; only the secondary entries pay
// for a wrapper + the (now-fixed, see fn2seg comment at the --aot-merge-max call site) GHC-cc
// calling GHC-cc transfer.
static void CreateLinkEntryWrapper(qir::LLVMGenCtx *ctx, u32 t_ip, u32 primary_ip, qir::CodeSegment segment,
				   std::vector<AOTSymbol> *aot_symbols)
{
	ctx->AddFunction(t_ip, segment); // no-op if DeclareKnownRegionEntries already declared it
	auto *fn = ctx->cmodule.getFunction(MakeAotSymbol(t_ip));
	auto *primary_fn = ctx->cmodule.getFunction(MakeAotSymbol(primary_ip));
	assert(fn && fn->empty() && primary_fn);
	auto *bb = llvm::BasicBlock::Create(ctx->cmodule.getContext(), "entry", fn);
	llvm::IRBuilder<> b(bb);
	auto *ipp = b.CreateConstInBoundsGEP1_64(b.getInt8Ty(), fn->getArg(0), offsetof(CPUState, ip));
	b.CreateStore(b.getInt32(t_ip), ipp);
	if (dbt::config::aot_link_multientry_trace) {
		auto *cp = b.CreateConstInBoundsGEP1_64(b.getInt8Ty(), fn->getArg(0),
							offsetof(CPUState, dbg_wrapper_calls));
		auto *cpp = b.CreateBitCast(cp, llvm::PointerType::getUnqual(b.getInt64Ty()));
		auto *cv = b.CreateAlignedLoad(b.getInt64Ty(), cpp, llvm::Align(alignof(u64)));
		b.CreateAlignedStore(b.CreateAdd(cv, b.getInt64(1)), cpp, llvm::Align(alignof(u64)));
	}
	auto *call = b.CreateCall(ctx->qcg_fnty, primary_fn, {fn->getArg(0), fn->getArg(1)});
	call->setCallingConv(llvm::CallingConv::GHC);
	call->setTailCall(true);
	call->setTailCallKind(llvm::CallInst::TCK_MustTail);
	call->addFnAttr(llvm::Attribute::NoInline);
	b.CreateRetVoid();
	aot_symbols->push_back({t_ip, 0});
}

// Design 8 alias multi-entry (--aot-link-alias-merge, 2026-07-24, Codex-directed second design):
// zero-wrapper realization of the same idea. `t_ip`'s own symbol becomes an `llvm::GlobalAlias`
// for the SAME address as `primary_ip`'s function -- no separate machine code at all. Relies on
// every call site that can reach a multi-entry function refreshing state->ip to its own actual
// target before the call (dbt/qmc/llvmgen/llvmgen.cpp: CreateQCGGbr's direct path and
// Expand_gbrind's fastpath/guarded-fastpath variants; the slowpath already did this via the
// existing qcgstub_brind runtime stub). If DeclareKnownRegionEntries already pre-declared `t_ip`
// as an empty external function (its own raw exec_count happened to also clear the generic
// admission gate), that declaration is replaced: it can only have real uses if something in the
// program takes a compile-time-KNOWN direct branch/call to this exact address, which the
// candidate's own entry contract (a link-merged return-continuation is, by construction, only
// ever reached via a genuinely computed `jalr`/gbrind from its one call site's callee, never a
// static jal/gbr) rules out. Verified, not assumed: aborts loudly instead of silently
// miscompiling if that contract is ever violated for some future candidate class.
static void CreateLinkEntryAlias(qir::LLVMGenCtx *ctx, u32 t_ip, u32 primary_ip)
{
	auto name = MakeAotSymbol(t_ip);
	auto *primary_fn = ctx->cmodule.getFunction(MakeAotSymbol(primary_ip));
	assert(primary_fn);
	if (auto *existing = ctx->cmodule.getFunction(name)) {
		if (!existing->empty() || !existing->use_empty()) {
			Panic(("CreateLinkEntryAlias: entry contract violated for " + name +
			       " -- pre-existing symbol has a body or real uses").c_str());
		}
		existing->eraseFromParent();
	}
	llvm::GlobalAlias::create(name, primary_fn);
}

// 32nd-cycle P6 (--aot-function-closure, default off): once a guest FUNCTION (from the ELF
// STT_FUNC symbol table) contains >=1 naturally-admitted region, statically discover and
// admit every OTHER basic block inside that function's declared [start,size) byte range --
// even blocks never executed in THIS profiling run (e.g. a different switch/jump-table case
// reached only under a different input). This pre-empts DC-2 cross-input exile entirely at
// BUILD time: zero deployment-invocation cost (the artifact is a normal static .so, not a
// mid-run recompile -- P1's compile-cost barrier does not apply). Static discovery never
// leaves the function's declared byte range (an out-of-range target is simply not expanded),
// so worst case it admits nothing extra; it cannot mis-decode adjacent functions or data.
struct FunctionRange {
	u32 start, end;
};

static std::vector<FunctionRange> const &GuestFunctionRanges()
{
	static std::vector<FunctionRange> ranges = [] {
		std::vector<FunctionRange> out;
		if (!dbt::config::aot_function_closure_elf)
			return out;
		int fd = open(dbt::config::aot_function_closure_elf, O_RDONLY);
		if (fd < 0)
			return out;
		struct stat st{};
		if (fstat(fd, &st) < 0 || st.st_size <= 0) {
			close(fd);
			return out;
		}
		void *map = mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		close(fd);
		if (map == MAP_FAILED)
			return out;
		auto *data = (u8 const *)map;
		auto rd32 = [&](size_t off) -> u32 {
			u32 v;
			memcpy(&v, data + off, 4);
			return v;
		};
		auto rd16 = [&](size_t off) -> u16 {
			u16 v;
			memcpy(&v, data + off, 2);
			return v;
		};
		u32 e_shoff = rd32(0x20);
		u16 e_shentsize = rd16(0x2e), e_shnum = rd16(0x30);
		constexpr u32 SYM_ENTSIZE = 16; // Elf32_Sym
		for (u16 i = 0; i < e_shnum; i++) {
			size_t b = (size_t)e_shoff + (size_t)i * e_shentsize;
			if (b + 40 > (size_t)st.st_size)
				break;
			u32 sh_type = rd32(b + 4), sh_offset = rd32(b + 16), sh_size = rd32(b + 20);
			if (sh_type != 2 /* SHT_SYMTAB */)
				continue;
			for (u32 off = sh_offset; off + SYM_ENTSIZE <= sh_offset + sh_size &&
						  off + SYM_ENTSIZE <= (u32)st.st_size;
			     off += SYM_ENTSIZE) {
				u32 st_value = rd32(off + 4);
				u32 st_size = rd32(off + 8);
				u8 st_info = data[off + 12];
				if ((st_info & 0xf) == 2 /* STT_FUNC */ && st_size > 0)
					out.push_back({st_value & ~1u, (st_value & ~1u) + st_size});
			}
		}
		munmap(map, (size_t)st.st_size);
		std::sort(out.begin(), out.end(), [](FunctionRange const &a, FunctionRange const &b) {
			return a.start < b.start;
		});
		return out;
	}();
	return ranges;
}

static FunctionRange const *FindEnclosingFunction(u32 ip)
{
	auto const &ranges = GuestFunctionRanges();
	auto it = std::upper_bound(ranges.begin(), ranges.end(), ip,
				    [](u32 v, FunctionRange const &r) { return v < r.start; });
	if (it == ranges.begin())
		return nullptr;
	--it;
	return (ip >= it->start && ip < it->end) ? &*it : nullptr;
}

// Guard against pathological compile-cost blowup on huge functions (a sanity bound, not a
// tuned accuracy threshold: it only limits HOW MUCH extra code closure may admit).
static constexpr u32 kClosureMaxFnBytes = 64 * 1024;

static std::unordered_set<u32> g_closure_admitted;

// P7 (--aot-jumptable-closure, default off): P6 (whole-function linear scan) was killed --
// admitting every straight-line block in a function (mostly dead/rare error paths, never hot
// under ANY input) pays a CERTAIN code-size/layout cost for a probabilistic benefit, and the
// stable-input control regressed +3.2%/+8.6% (cycles 22-23 already characterized code-size-
// driven layout/predictor-aliasing variance up to 75%). P7 is a NARROWER admission unit: at
// each `jr`/`jalr` in a closure-triggered function, recover the ACTUAL switch/jump-table this
// toolchain emits (confirmed pattern: `lui hi,X` [+ `addi hi,hi,LO12`] ; `slli idx,idx,2` ;
// `add addr,idx,hi` ; `lw target,0(addr)` ; `jr/jalr target` -- verified by disassembly on
// expat_2doc, e.g. guest ip 0x10dd8) via a BOUNDED backward dataflow scan (not a fixed
// instruction-order template -- register allocation varies), then admits ONLY the table's
// actual entries (typically a handful of case bodies), not the whole function body. This
// targets exactly the cross-input-exile class (unseen switch cases) without the incidental
// dead-code bytes that made P6 pay a layout tax on every input.
struct JumpTableInfo {
	u32 base;   // table start address (guest vaddr)
	u32 nslots; // entries actually usable (bounded by validity, see FindJumpTables)
};

// Backward-scan from a jr/jalr at `jr_ip` for the dataflow: rs1(jr) <- lw 0(rB) <- rB defined
// by add(rX,rY) where ONE of rX/rY was set by lui[+addi] (the table base), the OTHER by slli
// (the scaled index) -- order-independent within a bounded lookback window. Returns the base
// address if found, else 0. `win` bounds the scan (cost + false-positive safety, not tuning).
static u32 RecoverJumpTableBase(uptr vmem, u32 jr_ip, u32 fn_start)
{
	constexpr u32 kWin = 48; // bytes to look back (12 instructions) -- generous but bounded
	u32 lo = (jr_ip > fn_start + kWin) ? jr_ip - kWin : fn_start;
	auto fetch = [&](u32 a) { return *(u32 const *)(vmem + a); };
	u32 jr_insn = fetch(jr_ip);
	if ((jr_insn & 0x7f) != 0x67)
		return 0;
	u8 target_reg = (jr_insn >> 15) & 0x1f; // rs1
	// find the nearest preceding `lw target_reg, 0(rB)` for our target_reg
	for (u32 p = jr_ip; p > lo;) {
		p -= 4;
		u32 in = fetch(p);
		if ((in & 0x7f) == 0x03 && ((in >> 12) & 0x7) == 0x2 /* lw */ &&
		    ((in >> 7) & 0x1f) == target_reg) {
			i32 off = (i32)in >> 20;
			if (off != 0)
				return 0; // not the table-load shape (must be base-indexed, offset 0)
			u8 rb = (in >> 15) & 0x1f;
			// find the nearest preceding `add rb, rX, rY` defining rb
			for (u32 q = p; q > lo;) {
				q -= 4;
				u32 in2 = fetch(q);
				if ((in2 & 0x7f) == 0x33 && ((in2 >> 12) & 0x7) == 0 &&
				    ((in2 >> 25) & 0x7f) == 0 /* ADD, not SUB */ &&
				    ((in2 >> 7) & 0x1f) == rb) {
					u8 rx = (in2 >> 15) & 0x1f, ry = (in2 >> 20) & 0x1f;
					// one of rx/ry should trace to a lui(+addi); try both
					for (u8 cand : {rx, ry}) {
						u32 hi = 0;
						bool have_hi = false;
						i32 lo12 = 0;
						for (u32 r = q; r > lo;) {
							r -= 4;
							u32 in3 = fetch(r);
							if ((in3 & 0x7f) == 0x13 && ((in3 >> 12) & 0x7) == 0 &&
							    ((in3 >> 7) & 0x1f) == cand &&
							    ((in3 >> 15) & 0x1f) == cand) {
								lo12 = (i32)in3 >> 20; // addi cand,cand,lo12
								continue;              // keep scanning for the lui
							}
							if ((in3 & 0x7f) == 0x37 && ((in3 >> 7) & 0x1f) == cand) {
								hi = in3 & 0xfffff000u;
								have_hi = true;
								break;
							}
						}
						if (have_hi)
							return hi + (u32)lo12;
					}
				}
			}
			return 0;
		}
	}
	return 0;
}

// Scan a function for jr/jalr sites and recover each one's jump table (if the pattern matches),
// reading entries until one falls outside [fr->start,fr->end) (bounds the read -- a table is
// guest data, never validated beyond "looks like an in-function code address", same discipline
// used for the earlier static-pointer analysis). Caps entries per table (sanity bound, not a
// tuning threshold: switch tables in this corpus are small; this only prevents runaway reads
// if a non-table value is misidentified as a base).
static void FindJumpTableCandidates(uptr vmem, FunctionRange const &fr, std::set<u32> *out)
{
	constexpr u32 kMaxTableEntries = 256;
	for (u32 ip = fr.start; ip + 4 <= fr.end; ip += 4) {
		u32 insn = *(u32 const *)(vmem + ip);
		if ((insn & 0x7f) != 0x67) // jr/jalr
			continue;
		u32 base = RecoverJumpTableBase(vmem, ip, fr.start);
		if (!base)
			continue;
		for (u32 k = 0; k < kMaxTableEntries; k++) {
			u32 addr = base + 4 * k;
			// the table itself must not overlap the function's own code range
			if (addr >= fr.start && addr < fr.end)
				break;
			u32 tgt = *(u32 const *)(vmem + addr);
			if (tgt < fr.start || tgt >= fr.end)
				break; // first non-in-function value ends the (assumed-contiguous) table
			out->insert(tgt);
		}
	}
}

// Shared tail for both P6 and P7: given a raw `candidates` set for function `fr`, filter to
// genuinely new addresses, RecordEntry+Analyse them into `mg`, and root exactly the ones not
// otherwise reachable (BFS from mg->root -- see the long comment this replaced, preserved
// below at its rationale's original call site history). Correctness invariants (page-scoping,
// two-pass RecordEntry-before-Analyse, unreachable-region Panic avoidance) apply identically
// regardless of how `candidates` was produced.
static void AdmitCandidatesInFunction(dbt::ModuleGraph *mg, uptr vmem, FunctionRange const &fr,
				      std::set<u32> const &candidates)
{
	std::vector<u32> existing;
	for (auto const &e : mg->ip_map)
		existing.push_back(e.first);
	std::sort(existing.begin(), existing.end());
	auto covered = [&](u32 ip) {
		auto it = std::upper_bound(existing.begin(), existing.end(), ip);
		if (it == existing.begin())
			return false;
		--it;
		auto *n = mg->GetNode(*it);
		return n && ip < n->ip_end;
	};
	std::vector<u32> fresh;
	for (u32 c : candidates)
		if (!mg->GetNode(c) && !covered(c))
			fresh.push_back(c);
	if (fresh.empty())
		return;
	for (u32 c : fresh)
		mg->RecordEntry(c);
	std::vector<u32> allpts = fresh;
	for (auto const &e : mg->ip_map)
		if (e.first >= fr.start && e.first < fr.end)
			allpts.push_back(e.first);
	std::sort(allpts.begin(), allpts.end());
	allpts.erase(std::unique(allpts.begin(), allpts.end()), allpts.end());
	for (u32 c : fresh) {
		auto it = std::upper_bound(allpts.begin(), allpts.end(), c);
		u32 boundary = (it == allpts.end()) ? fr.end : *it;
		u64 dummy_ec = 0;
		std::map<u32, u64> dummy_map;
		rv32::RV32Analyser::Analyse(mg, c, boundary, vmem, dummy_ec, dummy_map);
		g_closure_admitted.insert(c);
	}
	// Region-count discipline: mark `region_entry` (a NEW compiled region root) ONLY for fresh
	// blocks not already reachable from mg->root via succs -- a plain fallthrough/branch chain
	// from an earlier-rooted block merges into that root's region naturally via
	// ComputeRegionDomSets, instead of every block being forced into its own singleton region
	// (measured on P6: always-singleton cost 7.5x more offline compile for only -3.1%
	// runtime). A naive "has zero preds" test is UNSOUND: a closure-discovered mini-loop whose
	// only external entry is the indirect dispatch itself has a non-empty preds set (its own
	// back-edge) but is NOT reachable from root -- starves aot_module.cpp's "unreachable
	// regions in modulegraph" Panic (the DC-4 class hazard the 27th-cycle audit flagged).
	// Correct fix: full reachability BFS from root; promote exactly the still-unreached fresh
	// nodes to new roots, expanding reachability as each is added, until none remain.
	std::unordered_set<ModuleGraphNode *> reached;
	std::vector<ModuleGraphNode *> bfsq{mg->root.get()};
	reached.insert(mg->root.get());
	auto expand = [&]() {
		while (!bfsq.empty()) {
			auto *n = bfsq.back();
			bfsq.pop_back();
			for (auto *s : n->succs)
				if (reached.insert(s).second)
					bfsq.push_back(s);
		}
	};
	expand();
	// Jump-table multi-entry pivot (--aot-jumptable-multientry, default off, 2026-07-24): P7's own
	// discovery (RecoverJumpTableBase/FindJumpTableCandidates above) is unconditionally kept;
	// this only changes how an admitted candidate is EXPOSED. Reuses the exact Design 8 wrapper
	// machinery (`link_region_suppressed` + llvmaot.cpp's per-region multi-entry loop, unchanged)
	// instead of forcing a brand-new independent region per handler -- letting handlers small
	// enough to be dominated by the enclosing function share its compiled body, wrapped for
	// external gbrind reachability. Falls back to the original force-own-region behavior for a
	// candidate whose enclosing function's own entry node is not itself reachable (extremely
	// rare/defensive; keeps this change strictly additive).
	auto *enclosing_entry = dbt::config::aot_jumptable_multientry ? mg->GetNode(fr.start) : nullptr;
	for (u32 c : fresh) {
		auto *cn = mg->GetNode(c);
		if (reached.count(cn))
			continue;
		if (enclosing_entry && reached.count(enclosing_entry)) {
			cn->flags.link_region_suppressed = true;
			// Distinct from Design 8's link-merge candidates (aot_module.h's flag comment):
			// this node's coverage guarantee must NOT depend on exec_count -- P7 discovered
			// it independently of the profile, so the wrapper-creation gate below must
			// protect it unconditionally, not just when hot.
			cn->flags.jumptable_region_suppressed = true;
			enclosing_entry->AddSucc(cn);
			reached.insert(cn);
			bfsq.push_back(cn);
			expand();
			continue;
		}
		cn->flags.region_entry = true;
		mg->root->AddSucc(cn);
		reached.insert(cn);
		bfsq.push_back(cn);
		expand();
	}
}

// Common driver for both P6/P7: find functions containing >=1 naturally-admitted region
// (clipped to the current page -- ModuleGraph is PAGE-SCOPED, mg->segment covers only this
// 4KB page; GetNode()/InModule() reject addresses outside it, confirmed by a real crash when
// P6 first tried to record entries past the page edge), then call `gen_candidates` per
// function to produce the raw candidate set, and admit via AdmitCandidatesInFunction.
// `require_hot`: P6 (whole-function scan) must stay hot-gated -- its candidate set (every
// straight-line block) scales with function SIZE, so gating on "executed at all" would
// reproduce the same code-size tax that killed it. P7 (jump-table closure)'s candidate set
// scales with the table's OWN entry count (independent of function size or hotness), so its
// trigger can safely be REACHABILITY (this function ran at least once under the profile,
// `page.executed`, already how BuildModuleGraph populates ip_map -- not a new magic number)
// instead of HOTNESS (`exec_count>=threshold`, Wendell's own named admission constant). This
// closes the gap a same-ELF audit found: a table-driven function that is itself never hot
// under input A (e.g. a hash-randomization routine whose call volume depends on how many
// distinct strings input B hashes) was invisible to hot-gated P7 even though its table is
// 100% statically recoverable and cheap (measured: 70% of the P8-scope exiled mass on
// expat_2doc was already jump-table-recoverable, just gated out this way).
template <typename CandidateGen>
static void ForEachClosureFunction(dbt::ModuleGraph *mg, uptr vmem, u32 page_vaddr, CandidateGen &&gen_candidates,
				   bool require_hot = true)
{
	u32 const page_end = page_vaddr + (u32)mmu::PAGE_SIZE;
	std::set<u32> closure_fn_starts;
	for (auto const &e : mg->ip_map) {
		auto *n = e.second.get();
		if (require_hot && n->flags.exec_count < dbt::config::threshold)
			continue;
		auto const *fr = FindEnclosingFunction(n->ip);
		if (fr && (fr->end - fr->start) <= kClosureMaxFnBytes)
			closure_fn_starts.insert(std::max(fr->start, page_vaddr));
	}
	for (u32 fstart : closure_fn_starts) {
		auto const *raw_fr = FindEnclosingFunction(fstart);
		if (!raw_fr)
			continue;
		FunctionRange fr{std::max(raw_fr->start, page_vaddr), std::min(raw_fr->end, page_end)};
		if (fr.start >= fr.end)
			continue;
		std::set<u32> candidates = gen_candidates(fr);
		AdmitCandidatesInFunction(mg, vmem, fr, candidates);
	}
}

static void ApplyFunctionClosure(dbt::ModuleGraph *mg, uptr vmem, u32 page_vaddr)
{
	if (!dbt::config::aot_function_closure)
		return;
	ForEachClosureFunction(mg, vmem, page_vaddr, [&](FunctionRange const &fr) {
		// P6: single linear 4-byte-step scan over the function's declared byte range,
		// collecting candidate block-start addresses -- every direct-branch/jal target
		// inside bounds, and every address immediately after a terminator instruction
		// (branch/jal/jalr/ecall/ebreak). KILLED (see FINDINGS_32ND_CYCLE_P6.md): admits
		// too much incidental dead-code, paying a code-size/layout tax even on inputs
		// that never exercise the extra code. Kept default-off as a measured reference.
		std::set<u32> candidates{fr.start};
		for (u32 ip = fr.start; ip + 4 <= fr.end; ip += 4) {
			u32 raw = *(u32 const *)(vmem + ip);
			u32 op = raw & 0x7f;
			bool term = (op == 0x63 || op == 0x6f || op == 0x67 || op == 0x73);
			if (!term)
				continue;
			if (op == 0x63) {
				rv32::insn::B b{raw};
				u32 tgt = ip + (u32)b.imm();
				if (tgt >= fr.start && tgt < fr.end)
					candidates.insert(tgt);
			} else if (op == 0x6f) {
				rv32::insn::J j{raw};
				u32 tgt = ip + (u32)j.imm();
				if (tgt >= fr.start && tgt < fr.end)
					candidates.insert(tgt);
			}
			if (ip + 4 < fr.end)
				candidates.insert(ip + 4);
		}
		return candidates;
	});
}

// P9 (--aot-return-closure, default off): admits the CALL-RETURN CONTINUATION address (ip+4)
// of every jal/jalr-with-rd inside a closure-triggered function -- statically EXACT (a return
// unconditionally lands at call_site+4, zero ambiguity, no dataflow/alias reasoning needed at
// all, unlike P8's struct-field candidate set). Derived from the same P8 audit: of expat_2doc's
// total exiled hot mass, brind=1,ret=1 (return continuations) alone was 3.5B of 17.4B (~20%),
// LARGER than the entire non-return-indirect pool P7/P8 target, yet was never itself attacked
// as an ADMISSION-UNIT question in this cycle (only as a DISPATCH-MECHANISM question --
// RAS/PIC/software-prediction -- which the 15th-cycle literature verdict correctly closed as
// saturated; build-time pre-admission of the continuation address is a different question:
// which code gets COMPILED, not how the return is DISPATCHED). Candidate set is bounded by
// construction (one entry per call site in the function, not a table read or backward scan).
static void ApplyReturnClosure(dbt::ModuleGraph *mg, uptr vmem, u32 page_vaddr)
{
	if (!dbt::config::aot_return_closure)
		return;
	ForEachClosureFunction(mg, vmem, page_vaddr, [&](FunctionRange const &fr) {
		std::set<u32> candidates;
		for (u32 ip = fr.start; ip + 4 <= fr.end; ip += 4) {
			u32 raw = *(u32 const *)(vmem + ip);
			u32 op = raw & 0x7f;
			bool has_rd = false;
			if (op == 0x6f) { // jal
				rv32::insn::J j{raw};
				has_rd = j.rd() != 0;
			} else if (op == 0x67) { // jalr
				rv32::insn::I ii{raw};
				has_rd = ii.rd() != 0;
			}
			if (has_rd && ip + 4 < fr.end)
				candidates.insert(ip + 4);
		}
		return candidates;
	});
}

static void ApplyJumpTableClosure(dbt::ModuleGraph *mg, uptr vmem, u32 page_vaddr)
{
	if (!dbt::config::aot_jumptable_closure)
		return;
	// Stays HOT-gated (require_hot defaults true). A reachability-gated variant (trigger on
	// "ran at all under the profile" instead of "hot") was measured and KILLED: despite a
	// same-ELF audit predicting 70% more recoverable mass this way, it REGRESSED (+1.9% vs
	// the hot-gated -1.1%) -- the extra admitted code cost more than it recovered. See
	// FINDINGS_32ND_CYCLE_P8.md.
	ForEachClosureFunction(mg, vmem, page_vaddr, [&](FunctionRange const &fr) {
		std::set<u32> candidates;
		FindJumpTableCandidates(vmem, fr, &candidates);
		return candidates;
	});
}

// A-line Round 59: whole-binary, one-time (memoized) pre-pass computing the AVERAGE execution
// density (dynmass/instr -- "average times each compiled instruction runs", this project's own
// already-named profitability signal, see the REGIONDUMP comment above) among regions the MAIN
// threshold already naturally admits. This is the self-calibrating bar `return_admit_cost_ratio`'s
// consumer uses below -- NOT a fixed magic number: it adapts to whatever this specific compile
// run's own admitted-set density looks like, derived once from data this pass already walks
// (`objprof::GetProfile()` + `BuildModuleGraph`/`ComputeRegions`, the same dry-run machinery
// `DumpApplicabilityFeatures` already uses, no new acquisition).
static double NaturallyAdmittedAvgDensity()
{
	static double cached = -1.0;
	if (cached >= 0.0)
		return cached;
	u64 total_dynmass = 0, total_instr = 0;
	for (auto const &page : objprof::GetProfile()) {
		u64 pmax = 0;
		for (auto c : page.exec_count)
			if (c > pmax)
				pmax = c;
		if (pmax < dbt::config::threshold)
			continue; // this page cannot contain a naturally-admitted region; skip the graph build
		auto mg = BuildModuleGraph(page);
		auto regions = mg.ComputeRegions();
		for (auto const &r : regions) {
			u64 mx = getMaxExecCountInRegion(r);
			if (mx < dbt::config::threshold)
				continue;
			for (auto *n : r) {
				total_instr += n->flags.exec_instr_count;
				total_dynmass += (u64)n->flags.exec_instr_count * n->flags.exec_count;
			}
		}
	}
	cached = total_instr ? (double)total_dynmass / (double)total_instr : 0.0;
	if (getenv("DBT_RETURNADMIT_LOG"))
		fprintf(stderr, "RETURNADMIT_AVG_DENSITY total_dynmass=%lu total_instr=%lu avg_density=%.3f\n",
			(unsigned long)total_dynmass, (unsigned long)total_instr, cached);
	return cached;
}

static bool RegionAdmitted(std::vector<dbt::ModuleGraphNode *> const &region, u64 &mx_out)
{
	u64 mx = getMaxExecCountInRegion(region);
	mx_out = mx;
	// A-line 2026-07-27 fair-budget oracle tooling: checked FIRST, unconditionally -- lets a
	// caller force-exclude a region regardless of how hot it naturally is, without touching
	// dbt::config::threshold (hence without perturbing ComputeRegions()'s own topology/seeding).
	if (dbt::config::dispatch_deny_list && !region.empty() && DenyList().count(region[0]->ip))
		return false;
	if (dbt::config::threshold_max && mx >= dbt::config::threshold_max)
		return false; // banded delta: this region already belongs to a HIGHER band's artifact
	if (mx >= dbt::config::threshold) {
		// Round-46 P6: record naturally-admitted region entry ips (the prof quantity the under-admit gate
		// tests). Populated across the DEFINE passes, which complete before Expand_gbrind reads the set.
		if (dbt::config::aot_edge_underadmit_gate && !region.empty())
			dbt::config::aot_natural_admitted.insert(region[0]->ip);
		return true;
	}
	if (dbt::config::dispatch_admit_list && !region.empty() && AdmitList().count(region[0]->ip))
		return true; // round-16 CDA: the list expresses ANY computed admission set (cost-model output), not only brind targets
	if (dbt::config::dispatch_admit_floor > 0 && !region.empty() && region[0]->flags.is_brind_target &&
	    mx >= dbt::config::dispatch_admit_floor && !IsReturnTarget(region[0]->ip))
		return true;
	// A-line Round 59, cheap A/B control: a raw floor applied ONLY to the previously-categorically
	// -excluded return-continuation case (see config.h's return_admit_floor comment for why this
	// exclusion existed and why it was a scope boundary, not a tested negative result).
	if (dbt::config::return_admit_floor > 0 && !region.empty() && IsReturnTarget(region[0]->ip) &&
	    mx >= dbt::config::return_admit_floor)
		return true;
	// A-line Round 59: cost-model admission for return continuations -- self-calibrating (uses
	// THIS run's own naturally-admitted-set average density, not a fixed constant). Admit a return
	// -continuation region if its OWN execution density exceeds the naturally-admitted average
	// scaled by `return_admit_cost_ratio` (1.0 = "at least as profitable as the average admitted
	// region"; the ratio lets the same self-calibrating bar be made stricter/looser without
	// hand-tuning a raw count).
	if (dbt::config::return_admit_cost_ratio > 0.0 && !region.empty() && IsReturnTarget(region[0]->ip)) {
		u64 instr = 0, dynmass = 0;
		for (auto *n : region) {
			instr += n->flags.exec_instr_count;
			dynmass += (u64)n->flags.exec_instr_count * n->flags.exec_count;
		}
		double density = instr ? (double)dynmass / (double)instr : 0.0;
		double bar = NaturallyAdmittedAvgDensity() * dbt::config::return_admit_cost_ratio;
		if (density >= bar) {
			if (getenv("DBT_RETURNADMIT_LOG"))
				fprintf(stderr, "RETURNADMIT_SITE ip=%08x density=%.3f bar=%.3f exec=%lu instr=%lu\n",
					region[0]->ip, density, bar, (unsigned long)mx, (unsigned long)instr);
			return true;
		}
	}
	if ((dbt::config::aot_function_closure || dbt::config::aot_jumptable_closure ||
	     dbt::config::aot_return_closure) &&
	    !region.empty() && g_closure_admitted.count(region[0]->ip))
		return true; // 32nd-cycle P6/P7/P9: statically-discovered block inside a closure function
	return false;
}

// V-next R4: profile-derived applicability features for the build-time gate (workload-name-INDEPENDENT). Dry-run:
// BuildModuleGraph + ComputeRegions per page (no codegen). Computes the dispatch exec-MASS fraction = sum of
// per-region max exec_count over recovered dispatch HANDLERS / sum over ALL executed regions. This separates
// dispatch-BOTTLENECKED workloads (handlers ARE the hot code -> high fraction) from workloads that merely CONTAIN
// dispatch handlers but spend their hot mass elsewhere (e.g. Xerces-DOM: many handler regions, low handler mass).
static void DumpApplicabilityFeatures()
{
	u64 total_mass = 0, handler_mass = 0, hot_mass = 0;
	u32 recovered = 0, admitted = 0, total_regions = 0;
	for (auto const &page : objprof::GetProfile()) {
		if (dbt::config::dry_page_floor) {
			// ACTIVATION-COST prefilter: a page whose max exec count is below the rung threshold
			// cannot admit any region (region mx <= page max) -- skip graph construction entirely.
			// At T0=262144 this collapses the first dry to the 1-2 genuinely hot pages: the dry's
			// cost becomes proportional to the rung's ambition (ski-shaped by construction).
			u64 pmax = 0;
			for (auto c : page.exec_count)
				if (c > pmax)
					pmax = c;
			if (pmax < dbt::config::threshold)
				continue;
		}
		auto mg = BuildModuleGraph(page);
		auto regions = mg.ComputeRegions();
		for (auto const &r : regions) {
			u64 mx = getMaxExecCountInRegion(r);
			if (mx == 0)
				continue;
			++total_regions;
			total_mass += mx;
			bool hot = mx >= dbt::config::threshold;
			if (dbt::config::dump_regions && !r.empty())
				fprintf(stderr, "DRYREGION ip=%08x mx=%lu hot=%d ibt=%d iconf=%.3f\n", r[0]->ip, (unsigned long)mx,
					(int)hot, (int)r[0]->flags.is_brind_target, r[0]->flags.indirect_confidence);
			bool handler = !r.empty() && r[0]->flags.is_brind_target && !hot &&
				       dbt::config::dispatch_admit_floor > 0 &&
				       mx >= dbt::config::dispatch_admit_floor && !IsReturnTarget(r[0]->ip);
			if (hot)
				hot_mass += mx;
			if (handler) {
				handler_mass += mx;
				++recovered;
			}
			if (hot || handler)
				++admitted;
			if (dbt::config::dump_regions) {
				u64 instr = 0;
				// Round-52: dynmass = sum over region blocks of exec_count*static_insns = total guest
				// instructions DYNAMICALLY executed in the region. This is the AOT BENEFIT proxy (time
				// saved ~ dynmass*dt_per_insn), while `instr` (sum static_insns) is the COST proxy
				// (compile time + artifact ~ static size). Their ratio dynmass/instr = execution density
				// = avg times each compiled instruction runs -> the profitability signal Wendell's pure
				// max-exec threshold ignores. Default-off (only under --dump-regions), no codegen change.
				u64 dynmass = 0;
				for (auto *n : r) {
					instr += n->flags.exec_instr_count;
					dynmass += (u64)n->flags.exec_instr_count * n->flags.exec_count;
				}
				// Round-25: region-graph emission. REGIONNODE maps member blocks to their
				// region entry; REGIONEDGE emits cross-region successor edges with the source
				// block's exec count as the crossing-frequency proxy (upper bound: the block's
				// terminator ran exactly exec_count times; for conditional exits the split is
				// unknown -- stated in the audit doc). Indirect edges are NOT here (no static
				// successors); they come from the brind edge profile when needed.
				{
					std::unordered_set<ModuleGraphNode const *> mine(r.begin(), r.end());
					for (auto *n : r) {
						// Round-pivot: emit per-node static instr (exec_instr_count) too, so the
						// cold-block compile-fraction (block-level trimming upper bound) is measurable.
						fprintf(stderr, "REGIONNODE region=%08x node=%08x exec=%lu instr=%u\n",
							r[0]->ip, n->ip, (unsigned long)n->flags.exec_count,
							(unsigned)n->flags.exec_instr_count);
						for (auto *sn : n->succs) {
							if (!mine.count(sn))
								fprintf(stderr, "REGIONEDGE src=%08x dstnode=%08x w=%lu kind=br\n",
									r[0]->ip, sn->ip, (unsigned long)n->flags.exec_count);
							else if (dbt::config::dump_regions_internal_edges)
								// A-line 2026-07-27: --dump-regions never logged INTERNAL
								// successor edges (sn IS a member of this same region) --
								// only cross-region exits. Reachability/dominator analysis of
								// a region's own body was therefore structurally impossible
								// from --dump-regions output alone. Gated behind its own flag
								// (default off, only meaningful combined with --dump-regions)
								// so the existing REGIONEDGE semantics (external exits only)
								// stay byte-identical for every other consumer. Uses the REAL
								// originating node's own ip as src (n->ip), unlike the
								// external-edge lines above which report the region's entry
								// ip for src -- needed to reconstruct actual internal
								// topology, not just "some edge leaves this region".
								fprintf(stderr, "REGIONEDGE src=%08x dstnode=%08x w=%lu kind=internal\n",
									n->ip, sn->ip, (unsigned long)n->flags.exec_count);
						}
						for (u32 cip : n->cross_succs)
							fprintf(stderr, "REGIONEDGE src=%08x dstnode=%08x w=%lu kind=cross\n",
								r[0]->ip, cip, (unsigned long)n->flags.exec_count);
					}
				}
				// fprintf, not log_dbt: log streams are compiled out in NDEBUG builds and this
				// dump is the data product of the --dump-applicability dry run.
				fprintf(stderr, "REGIONDUMP ip=%08x exec=%lu instr=%lu dynmass=%lu nodes=%zu brind=%d ret=%d hot=%d handler=%d\n",
					r[0]->ip, (unsigned long)mx, (unsigned long)instr, (unsigned long)dynmass, r.size(),
					(int)r[0]->flags.is_brind_target, (int)IsReturnTarget(r[0]->ip), (int)hot, (int)handler);
			}
		}
	}
	double frac = total_mass ? (double)handler_mass / (double)total_mass : 0.0;
	fprintf(stderr, "APPLICABILITY total_mass=%lu handler_mass=%lu hot_mass=%lu dispatch_frac=%.4f recovered=%u admitted=%u total_regions=%u\n",
		(unsigned long)total_mass, (unsigned long)handler_mass, (unsigned long)hot_mass, frac, recovered,
		admitted, total_regions);
}

// Layout ceiling oracle (--aot-region-order-file) rank table, shared between DeclareKnownRegionEntries
// (below) and LLVMAOTTranslatePage's post-ComputeRegions() region sort (further down). Root-cause fix
// (2026-07-27): this table used to be built TWICE, once per call site, but only the copy inside
// LLVMAOTTranslatePage was ever consulted where it mattered -- DeclareKnownRegionEntries runs for
// EVERY page, entirely BEFORE any page is defined (see the two separate top-level loops in
// TranslateAOT), and declares an llvm::Function (in raw ascending-IP order, ignoring the order file)
// for every brind_target/segment_entry entry that passes admission. Since region_entry is seeded
// EXACTLY from is_brind_target/is_segment_entry (aot_module.cpp, ApplyFDRE), that is essentially the
// entire admitted set. LLVMGenCtx::AddFunction is idempotent (a no-op if the function already exists
// in the module), so by the time LLVMAOTTranslatePage's sorted `regions` loop calls AddFunction again,
// the function was already created -- in address order -- and the reorder is silently discarded.
// Empirically this made --aot-region-order-file a no-op: 3 independent tests (move-to-last,
// full-reverse, force-to-rank-0) never changed a single compiled address (see
// experiments/2026-07-27-0827-aline-profile-guided-region-algorithm/
// CYCLE31_PROBE5_LAYOUT_ISOLATION_BLOCKED_BY_TOOLING.md). Fix: apply the SAME rank table to
// DeclareKnownRegionEntries's declaration order too, since that is what actually assigns add-order
// for this set. The later regions-level sort is kept (not dead code): it still governs add-order for
// the minority of region entries that exist ONLY via IDF-propagation (idf_fused), which
// DeclareKnownRegionEntries's brind_target/segment_entry filter does not see.
static std::unordered_map<u32, unsigned> const &RegionOrderRanks()
{
	static std::unordered_map<u32, unsigned> m = [] {
		std::unordered_map<u32, unsigned> out;
		FILE *f = fopen(dbt::config::aot_region_order_file, "r");
		if (f) {
			u32 ip;
			unsigned rank = 0;
			while (fscanf(f, "%x", &ip) == 1)
				out[ip] = rank++;
			fclose(f);
		}
		return out;
	}();
	return m;
}

static void DeclareKnownRegionEntries(qir::LLVMGenCtx *ctx, objprof::PageData const &page)
{
	u32 const page_vaddr = page.pageno << mmu::PAGE_BITS;
	qir::CodeSegment segment(page_vaddr, mmu::PAGE_SIZE);

	std::vector<u32> ips;
	for (u32 idx = 0; idx < page.executed.size(); ++idx) {
		if (!page.executed[idx])
			continue;
		u32 ip = page_vaddr + objprof::PageData::idx2po(idx);
		// Round-24: unified admission -- declare an entry if it passes the threshold OR is in the
		// admit-list (the list expresses ANY computed admission set; default empty = old behavior).
		bool pass = page.exec_count[idx] >= dbt::config::threshold ||
			    (dbt::config::dispatch_admit_list && AdmitList().count(ip));
		if (!pass)
			continue;
		if (page.brind_target[idx] || page.segment_entry[idx])
			ips.push_back(ip);
	}
	// Layout ceiling oracle: this is the loop that actually assigns LLVM function ADD order for
	// this set (see RegionOrderRanks() comment above) -- apply the order file HERE, not just on
	// the `regions` vector further down, or it has no observable effect.
	if (dbt::config::aot_region_order_file) {
		auto const &order_rank = RegionOrderRanks();
		std::stable_sort(ips.begin(), ips.end(), [&](u32 a, u32 b) {
			auto ia = order_rank.find(a), ib = order_rank.find(b);
			bool ha = ia != order_rank.end(), hb = ib != order_rank.end();
			if (ha != hb)
				return ha; // listed entries sort before unlisted ones
			if (ha && hb)
				return ia->second < ib->second;
			return false; // both unlisted: preserve relative order (stable_sort)
		});
	}
	for (u32 ip : ips)
		ctx->AddFunction(ip, segment);
}

// V-next Phase 2B: global admitted-region index, incremented per admitted region in the DEFINE loop, used to assign
// each admitted region to a shard (index % aot_shard_mod). Persists across per-page calls within one elfaot process.
static unsigned g_shard_admitted_idx = 0;

using GlobalRegionRanges = std::unordered_map<u32, qir::CompilerJob::IpRangesSet>;

// A-line round 22 Gate 1 Row 1 (oracle-only, default-off): loads (source,target,count) triples
// into a plain map, cached once per process. Deliberately NOT touching ModuleGraph::succs or any
// region/merge/lowering/layout consumer -- see ModuleGraphNode::indirect_succs's comment.
static std::unordered_map<u32, std::vector<u32>> const &LoadIndirectSuccsOracle()
{
	static std::unordered_map<u32, std::vector<u32>> m = [] {
		std::unordered_map<u32, std::vector<u32>> out;
		if (dbt::config::aot_indirect_succs_file) {
			std::ifstream f(dbt::config::aot_indirect_succs_file);
			std::string line;
			while (std::getline(f, line)) {
				if (line.empty())
					continue;
				std::istringstream ls(line);
				unsigned long s, t, c = 1;
				ls >> std::hex >> s >> t;
				ls >> std::dec >> c;
				out[(u32)s].push_back((u32)t);
			}
		}
		return out;
	}();
	return m;
}

static void LLVMAOTTranslatePage(qir::LLVMGenCtx *ctx, std::vector<AOTSymbol> *aot_symbols,
				 objprof::PageData const &page, GlobalRegionRanges const *global_region_ranges)
{
	auto mg = BuildModuleGraph(page);
	// A-line round 22 Gate 1 Row 1: populate the typed, isolated indirect_succs relation BEFORE
	// any region/merge/closure pass runs, from the SAME edge data used elsewhere this round --
	// but this relation has no reader except DumpIndirectSuccs below (added this round). Proves
	// (or disproves) "does the graph merely containing this information change anything" in
	// total isolation from every existing consumer.
	if (dbt::config::aot_indirect_succs_file) {
		auto const &oracle = LoadIndirectSuccsOracle();
		unsigned matched_nodes = 0, matched_edges = 0;
		for (auto &[ip, node] : mg.ip_map) {
			auto it = oracle.find(ip);
			if (it != oracle.end()) {
				node->indirect_succs = it->second;
				matched_nodes++;
				matched_edges += (unsigned)it->second.size();
			}
		}
		if (dbt::config::aot_dump_indirect_succs)
			fprintf(stderr, "INDIRECT_SUCCS_ORACLE page=%x matched_nodes=%u matched_edges=%u\n",
				page.pageno << mmu::PAGE_BITS, matched_nodes, matched_edges);
	}
	// A-line round 25 Track C free-oracle test, step 1 (default off, diagnostic only): static
	// in-degree of every gbrind SOURCE block, straight from ModuleGraphNode::preds -- already-
	// built data, zero new collection. Determines whether this corpus even has a shared-dispatch
	// hub (in-degree > 1) before touching any entropy/replication machinery.
	if (dbt::config::aot_dump_gbrind_indegree) {
		for (auto &[ip, node] : mg.ip_map) {
			if (node->flags.is_brind_source)
				fprintf(stderr, "GBRIND_INDEGREE ip=%08x preds=%zu\n", ip, node->preds.size());
		}
	}
	ApplyFunctionClosure(&mg, (uptr)mmu::base, page.pageno << mmu::PAGE_BITS);
	ApplyJumpTableClosure(&mg, (uptr)mmu::base, page.pageno << mmu::PAGE_BITS);
	ApplyReturnClosure(&mg, (uptr)mmu::base, page.pageno << mmu::PAGE_BITS);
	auto regions = mg.ComputeRegions();

	// Layout/co-location ceiling oracle (--aot-region-order-file, measurement-only, default-off):
	// reorder the region list BEFORE any codegen/emission loop uses it. Stable sort so regions not
	// listed in the file keep their original relative order, placed after all listed ones -- lets
	// a partial ordering (e.g. just the hot dispatch source/target set) be tested without having to
	// enumerate every region on the page. Only affects LLVMGenCtx function-add order for entries NOT
	// already declared by DeclareKnownRegionEntries (i.e. IDF-fused-only region entries; see
	// RegionOrderRanks()'s comment for why DeclareKnownRegionEntries must ALSO apply this order for
	// the (majority) brind_target/segment_entry set). Does not touch region_gsize (computed from a
	// separately address-sorted copy above/below) or any codegen content.
	if (dbt::config::aot_region_order_file) {
		auto const &order_rank = RegionOrderRanks();
		std::stable_sort(regions.begin(), regions.end(),
				  [&](std::vector<ModuleGraphNode *> const &a, std::vector<ModuleGraphNode *> const &b) {
					  auto ia = a.empty() ? order_rank.end() : order_rank.find(a[0]->ip);
					  auto ib = b.empty() ? order_rank.end() : order_rank.find(b[0]->ip);
					  bool ha = ia != order_rank.end(), hb = ib != order_rank.end();
					  if (ha != hb)
						  return ha; // listed entries sort before unlisted ones
					  if (ha && hb)
						  return ia->second < ib->second;
					  return false; // both unlisted: preserve relative order (stable_sort)
				  });
	}

	// AARS gsize: each region's guest byte-extent = distance to the NEXT region entry (regions partition the page's
	// executed code) -> the region's true size, recorded in the aottab so the cross-program reuse byte-identity gate
	// compares EXACTLY this region (no over-reach into adjacent/excluded regions, no magic window). (ip_end is unused.)
	std::vector<u32> region_entries;
	for (auto const &rr : regions)
		if (!rr.empty())
			region_entries.push_back(rr[0]->ip);
	std::sort(region_entries.begin(), region_entries.end());
	auto region_gsize = [&](u32 ip) -> u32 {
		auto it = std::upper_bound(region_entries.begin(), region_entries.end(), ip);
		u32 nxt = (it == region_entries.end()) ? roundup(ip + 1, mmu::PAGE_SIZE) : *it;
		return nxt > ip ? nxt - ip : 4;
	};

	// Round-41 region-merge (RESEARCH PROBE -- NON-FUNCTIONAL, demonstrates the GHC-cc merge-wall;
	// raw/PHASE2_MERGE_FAILURE.txt). Groups admitted regions into one O3 worker with an entry switch on
	// state->ip; non-primary entries get GHC wrappers that set state->ip then tail-call the worker.
	// BLOCKED: a GHC-cc fn calling another GHC-cc fn segfaults LLVM's GHC backend (~560ms into codegen),
	// and the wrappers would re-pay the per-function overhead anyway. Kept default-off (aot_merge_max<=1
	// == stock, byte-identical) as the reproducible artifact of the negative result.
	if (dbt::config::aot_merge_max > 1) {
		std::vector<std::vector<dbt::ModuleGraphNode *> const *> adm;
		for (auto const &r : regions) {
			u64 mx;
			if (RegionAdmitted(r, mx))
				adm.push_back(&r);
		}
		unsigned G = dbt::config::aot_merge_max;
		for (size_t gi = 0; gi < adm.size(); gi += G) {
			size_t ge = std::min(adm.size(), gi + (size_t)G);
			u32 primary_ip = (*adm[gi])[0]->ip;
			ctx->AddFunction(primary_ip, mg.segment);
			qir::CompilerJob::IpRangesSet ipranges;
			std::vector<u32> entries;
			for (size_t k = gi; k < ge; ++k) {
				auto const &r = *adm[k];
				entries.push_back(r[0]->ip);
				for (auto n : r)
					ipranges.push_back({n->ip, n->ip_end});
			}
			auto aotrt = LLVMAOTCompilerRuntime{};
			qir::CompilerJob job(&aotrt, (uptr)mmu::base, mg.segment, std::move(ipranges));
			auto arena = MemArena(1_MB);
			auto *region = qir::CompilerGenRegionIR(&arena, job);
			qir::QIRToLLVM llvm_gen(*ctx, &mg.segment, region, primary_ip);
			llvm_gen.merge_entries = entries;
			llvm_gen.Run();
			// The worker (named after the primary) becomes an INTERNAL multi-entry function; every group
			// member gets a thin GHC wrapper that SETS state->ip = its entry (direct gbr entries do NOT set
			// it -- only brind does) then musttail-calls the worker, whose switch routes by state->ip.
			auto *worker = ctx->cmodule.getFunction(MakeAotSymbol(primary_ip));
			worker->setName(std::string("_mw_") + std::to_string(primary_ip));
			worker->setLinkage(llvm::GlobalValue::InternalLinkage);
			// EXPERIMENT (2026-07-24): the rename above left fn2seg keyed under the PRE-rename
			// name (MakeAotSymbol(primary_ip)); IntrinsicExpansionPass later looks up fn2seg by
			// the function's CURRENT name and unconditionally dereferences find()'s result with
			// no missing-key check -- testing whether this (not the GHC-cc backend) was the real
			// crash cause.
			ctx->fn2seg.insert({worker->getName().str(), mg.segment});
			auto &lctx = ctx->cmodule.getContext();
			for (size_t k = gi; k < ge; ++k) {
				u32 e = (*adm[k])[0]->ip;
				ctx->AddFunction(e, mg.segment);
				auto *wf = ctx->cmodule.getFunction(MakeAotSymbol(e));
				llvm::IRBuilder<> wb(llvm::BasicBlock::Create(lctx, "entry", wf));
				auto *ipp = wb.CreateBitCast(
				    wb.CreateConstInBoundsGEP1_32(wb.getInt8Ty(), wf->getArg(0), offsetof(CPUState, ip)),
				    wb.getInt32Ty()->getPointerTo());
				wb.CreateStore(wb.getInt32(e), ipp);
				auto *call = wb.CreateCall(ctx->qcg_fnty, worker, {wf->getArg(0), wf->getArg(1)});
				call->setCallingConv(llvm::CallingConv::GHC);
				call->setTailCallKind(llvm::CallInst::TCK_MustTail); // GHC->GHC segfaults backend (the wall)
				wb.CreateRetVoid();
				aot_symbols->push_back({e, 0});
			}
		}
		return;
	}

	for (auto const &r : regions) {
		u64 mx;
		if (!RegionAdmitted(r, mx))
			continue;
		// log_dbt("Adding function: %x", r[0]->ip);
		ctx->AddFunction(r[0]->ip, mg.segment);
		// P10 (--aot-closure-cold-section, default off): place a closure-admitted (P6/P7/P9)
		// function in a SEPARATE object-file section, away from naturally-hot code, instead
		// of letting the linker interleave it with the hot artifact's layout. Derived from the
		// convergent P6/P7/P9 negative: every closure variant tried so far modifies the SAME
		// .text region the hot code lives in, and every one paid a cost that met or exceeded
		// its benefit -- this tests whether the cost is specifically LAYOUT INTERFERENCE
		// (cycles 22-23's BTB/indirect-predictor aliasing) rather than an inherent property of
		// admitting more code. If cold-section placement removes the tax, closure becomes
		// viable; if not, it rules out layout and the entire build-time-admission family is a
		// dead end regardless of placement.
		if (dbt::config::aot_closure_cold_section &&
		    (dbt::config::aot_function_closure || dbt::config::aot_jumptable_closure ||
		     dbt::config::aot_return_closure) &&
		    g_closure_admitted.count(r[0]->ip)) {
			// NOTE: a name matching the `.text.*` glob (e.g. ".text.closure_cold") gets
			// merged back into `.text` by the default `ld -shared` linker script's
			// orphan-section handling for text-like names -- defeats the whole point.
			// ".dbtcold" matches no default-script pattern, so the linker places it as
			// a genuine separate orphan output section (verified: readelf shows it
			// distinct from .text in the final .so, unlike the .text.* attempt).
			if (auto *fn = ctx->cmodule.getFunction(MakeAotSymbol(r[0]->ip)))
				fn->setSection(".dbtcold");
		}
	}

	for (auto const &r : regions) {
		assert(r[0]->flags.region_entry);
		u64 mx;
		if (!RegionAdmitted(r, mx))
			continue;
		// V-next R3: SHARD-LINK aggregation mode -- record EVERY admitted gip for the full _aot_tab, define NO function
		// (functions come from the shard .o). This builds the single aottab object that is linked with all shard .o.
		if (dbt::config::aot_shard_link > 0) {
			aot_symbols->push_back({r[0]->ip, 0, region_gsize(r[0]->ip)});
			continue;
		}
		// V-next Phase 2B: sharded parallel compile -- DEFINE only this shard's admitted regions. The function is
		// still DECLARED (loop above + DeclareKnownRegionEntries), so cross-shard direct calls stay external symbols.
		// The global index advances for EVERY admitted region (identical order across shards) -> disjoint partition.
		if (dbt::config::aot_shard_mod > 1) {
			unsigned this_idx = g_shard_admitted_idx++;
			if ((int)(this_idx % (unsigned)dbt::config::aot_shard_mod) != dbt::config::aot_shard_idx)
				continue;
		}
		// A-line move-not-copy: this admitted region is a fired merge target -- its body already
		// lives inside the source's function (spliced there by the merge below when the source
		// region was/will be emitted); emit only the entry thunk instead of a second full copy.
		if (dbt::config::aot_edge_move_not_copy && !g_move_fired.empty()) {
			auto fit = g_move_fired.find(r[0]->ip);
			if (fit != g_move_fired.end() && !g_move_source_regions.count(r[0]->ip)) {
				EmitMoveThunk(ctx, r[0]->ip, fit->second);
				aot_symbols->push_back({r[0]->ip, 0, region_gsize(r[0]->ip)});
				continue;
			}
		}
		if (dbt::config::dispatch_admit_floor > 0 && mx < dbt::config::threshold)
			log_dbt("dispatch-admit recovered brind region %08x (exec=%lu < thr=%lu)", r[0]->ip, mx,
				(unsigned long)dbt::config::threshold);
		qir::CompilerJob::IpRangesSet ipranges;
		for (auto n : r) {
			// log_dbt("Adding ip range: %x-%x", n->ip, n->ip_end);
			ipranges.push_back({n->ip, n->ip_end});
		}
		// Oracle-only edge-directed co-visibility: if THIS region owns a profiled merge source, append
		// the target regions' ranges as INTERNAL code. The registry is built before code generation,
		// so targets may live on another guest page. This is behind the existing default-off flag: it
		// tests whether page-local optimization hides useful flow, not a deployable selection policy.
		std::vector<u32> merge_internal;
		if (dbt::config::aot_edge_region_merge && global_region_ranges &&
		    !dbt::config::aot_region_merge_map.empty()) {
			std::set<std::pair<u32, u32>> included_ranges;
			for (auto n : r)
				included_ranges.emplace(n->ip, n->ip_end);
			for (auto const &[msrc, mtgts] : dbt::config::aot_region_merge_map) {
				bool owns_source = std::any_of(r.begin(), r.end(),
					[&](auto *n) { return n->ip == msrc; });
				if (!owns_source)
					continue;
				for (u32 tgt : mtgts) {
					auto tr = global_region_ranges->find(tgt);
					if (tr == global_region_ranges->end()) {
						log_dbt("edge-region-merge: no region for target %08x", tgt);
						continue;
					}
					for (auto const &range : tr->second)
						if (included_ranges.insert(range).second)
							ipranges.push_back(range);
					merge_internal.push_back(tgt);
				}
				if (!merge_internal.empty())
					fprintf(stderr, "EDGE_REGION_MERGE applied src_region=%08x source=%08x internal=%zu\n",
						r[0]->ip, msrc, merge_internal.size());
			}
		}

		auto aotrt = LLVMAOTCompilerRuntime{};

		qir::CompilerJob job(&aotrt, (uptr)mmu::base, mg.segment, std::move(ipranges));

		auto arena = MemArena(1_MB);
		auto *region = qir::CompilerGenRegionIR(&arena, job);

		auto entry_ip = r[0]->ip;
		qir::QIRToLLVM llvm_gen(*ctx, &mg.segment, region, entry_ip);
		llvm_gen.internal_dispatch_targets = merge_internal;
		// Design 8 multi-entry (--aot-link-multientry-merge): members of this region other than
		// r[0] that ApplyLinkAwareRegionMerge swept in (link_region_suppressed) get a real,
		// externally-reachable secondary entry instead of silently losing their _aot_tab slot.
		// Passing r[0]->ip alongside them is safe and adds no switch case for it: Run()'s switch
		// builder skips any merge_entries member whose block == first_bb (r[0]->ip always is).
		std::vector<u32> link_secondary_entries;
		if (dbt::config::aot_link_multientry_merge || dbt::config::aot_jumptable_multientry) {
			// Cost-model gate (not a new magic constant): a wrapper is a real top-level
			// GHC-cc function, which pays a genuine fixed per-function compile-time+size
			// tax (confirmed by measurement: unconditionally wrapping every suppressed node
			// made total compile time and .aot.so size WORSE than plain baseline, despite
			// deploy time returning to baseline). Only pay that tax for a merged node whose
			// OWN exec_count would have independently cleared Wendell's EXISTING admission
			// threshold -- i.e. only where silently absorbing it (single-entry) would incur
			// a QCG-fallback tax large enough to plausibly matter; cold merged nodes stay
			// silently absorbed (single-entry behavior, only a rare/cheap fallback risk).
			// MEASURED (2026-07-24): a stricter ratio gate (also requiring T >= the region's
			// OWN primary exec_count) was tried and made libyaml's net economics WORSE, not
			// better -- it excludes MORE hot targets from getting a protective wrapper, and
			// those un-wrapped hot targets are STILL merged (silently absorbed) by
			// ApplyLinkAwareRegionMerge whenever --aot-link-multientry-merge is on, so they
			// pay the FULL QCG-fallback tax with no protection at all. Reverted to the plain
			// absolute-threshold gate: every hot merged target gets a wrapper, so none of them
			// are exposed to the fallback tax this mechanism exists to avoid.
			//
			// CEILING-TEST FIX (2026-07-25): the exec_count gate above is Design-8-specific
			// logic (a real, already-observed return continuation -- cold means genuinely
			// rare). A P7-discovered handler (`jumptable_region_suppressed`) has NO exec_count
			// signal to gate on in the first place -- P7's whole purpose is covering handlers
			// the CURRENT profile never observed at all (exec_count==0 by construction for an
			// unseen-in-this-run handler). Applying the same hotness gate to both silently
			// dropped _aot_tab protection for every never-profiled P7 handler, making
			// --aot-jumptable-multientry byte-identical to not running P7 at all on a held-out
			// input that exercises one (see the source-vs-held-out ceiling test,
			// DESIGN8_ALIAS_MULTIENTRY_ROOT_CAUSE_3.md's sibling doc) -- defeating the exact
			// cross-input robustness P7 exists for. A P7-discovered handler is unconditionally
			// wrapped, matching P7-alone's own unconditional (profile-independent) admission
			// discipline; only Design 8's own candidates stay hotness-gated.
			for (auto n : r)
				if (n != r[0] && n->flags.link_region_suppressed &&
				    (n->flags.jumptable_region_suppressed ||
				     n->flags.exec_count >= dbt::config::threshold))
					link_secondary_entries.push_back(n->ip);
		} else if (dbt::config::aot_link_alias_merge) {
			// Alias variant (2026-07-24, second design): no wrapper-function fixed cost to
			// gate against, so every link-merged member of this region is exposed -- entry
			// selection follows the reachability/entry-contract structural invariant (this IS
			// a link-merged return-continuation) rather than a hotness threshold.
			for (auto n : r)
				if (n != r[0] && n->flags.link_region_suppressed)
					link_secondary_entries.push_back(n->ip);
		}
		// T5c-0 late-enterable loop entries (--aot-loop-entry). Same exposure mechanism as the two
		// blocks above and a deliberately separate list, because the ALIAS variant must never be
		// used for these. An alias makes `_x<header>` resolve to the primary's own address without
		// setting state->ip, which is safe only for a candidate that can be reached exclusively by
		// a computed jalr (Design 8's entry contract). A loop header is reached by a DIRECT branch
		// whose QCG slot self-patches straight to the resolved address and never touches state->ip
		// -- exactly the misroute qemit.cpp's Emit_gbr comment documents. The wrapper stores
		// state->ip itself before tail-calling the primary, so it is correct for a direct-branch
		// entry; these therefore always take the wrapper path below.
		std::vector<u32> loop_entries;
		if (dbt::config::aot_loop_entry) {
			for (auto n : r) {
				if (n == r[0] || !n->flags.loop_entry_exposed)
					continue;
				if (std::find(link_secondary_entries.begin(), link_secondary_entries.end(),
					      n->ip) != link_secondary_entries.end())
					continue; // already exposed by Design 8/P7; one symbol per ip
				loop_entries.push_back(n->ip);
			}
		}
		if (!link_secondary_entries.empty() || !loop_entries.empty()) {
			llvm_gen.merge_entries.push_back(entry_ip);
			for (u32 t : link_secondary_entries)
				llvm_gen.merge_entries.push_back(t);
			for (u32 t : loop_entries)
				llvm_gen.merge_entries.push_back(t);
		}
		auto *fn = llvm_gen.Run();
		// FAIL CLOSED. A wrapper is only correct if Run() really added a switch case for its ip:
		// the wrapper stores state->ip and tail-calls the primary, so a missing case would take the
		// switch's DEFAULT arm into the region's own root block carrying a foreign state->ip. Run()
		// records the cases it actually created, and an ip without one simply gets no symbol -- so
		// nothing relinks to it and behaviour falls back to exactly what it is today.
		if (!loop_entries.empty()) {
			auto const &added = ctx->fn2merge_cases[std::string(fn->getName())];
			for (u32 t : loop_entries) {
				if (added.count(t) == 0) {
					if (getenv("LOOPENTRY_DEBUG"))
						fprintf(stderr, "LOOPENTRY_SKIP header=%08x (no switch case)\n", t);
					continue;
				}
				CreateLinkEntryWrapper(ctx, t, entry_ip, mg.segment, aot_symbols);
				if (getenv("LOOPENTRY_DEBUG"))
					fprintf(stderr, "LOOPENTRY_WRAPPER primary=%08x header=%08x\n", entry_ip, t);
			}
		}
		if (!link_secondary_entries.empty()) {
			for (u32 t : link_secondary_entries) {
				if (dbt::config::aot_link_alias_merge) {
					CreateLinkEntryAlias(ctx, t, entry_ip);
					aot_symbols->push_back({t, 0});
				} else {
					CreateLinkEntryWrapper(ctx, t, entry_ip, mg.segment, aot_symbols);
				}
			}
			if (getenv("LINKMERGE_DEBUG"))
				fprintf(stderr, "LINKMERGE_MULTIENTRY primary=%08x secondary=%zu alias=%d\n", entry_ip,
					link_secondary_entries.size(), (int)dbt::config::aot_link_alias_merge);
		}
		// V-next: compile dispatch-admitted handlers (sub-threshold) at O0 (optnone) so the O3 module pipeline skips
		// them -> cheap compile; hot regions (>=threshold) keep O3. CAVEAT (measured): optnone INHERENTLY regresses
		// dispatch loops whose handlers do real compute (interpreter_bench -3.3%, small FP-arith handlers benefit from
		// O3) -- a size gate does NOT separate these (the difference is content, not size). So optnone is not a clean
		// general fix; the clean path is region-merge (keep O3, cut #functions). This flag is kept for the analysis.
		if (dbt::config::dispatch_handler_optnone && fn && mx < dbt::config::threshold) {
			fn->addFnAttr(llvm::Attribute::OptimizeNone);
			fn->addFnAttr(llvm::Attribute::NoInline);
		}
		// A-line Round 59 cheap test: does the SAME "cheapen sub-threshold admission with optnone"
		// idea (already tried for dispatch_admit_floor's handlers, found to regress compute-heavy
		// ones) also apply to return_admit_floor/-cost-model's newly-admitted return continuations?
		// Different candidate set than the existing dispatch_handler_optnone gate above (which never
		// touches IsReturnTarget regions at all) -- testing whether O0 rescues THIS mechanism's
		// compile-cost economics specifically, not assuming the prior finding transfers.
		if (dbt::config::return_admit_optnone && fn && mx < dbt::config::threshold && IsReturnTarget(entry_ip)) {
			fn->addFnAttr(llvm::Attribute::OptimizeNone);
			fn->addFnAttr(llvm::Attribute::NoInline);
		}
		// Round-40 Route E: cheapen the COLD TAIL of the admitted set (mx < hot_floor) to optnone while HOT
		// regions keep O3. Coverage preserved (region still compiled). Reduces L_full on compile-bound workloads.
		if (dbt::config::aot_hot_floor > 0 && fn && mx < dbt::config::aot_hot_floor) {
			fn->addFnAttr(llvm::Attribute::OptimizeNone);
			fn->addFnAttr(llvm::Attribute::NoInline);
		}
		// CPB (2026-07-20, Candidate 2): gate optnone on PREDICTABILITY (indirect_confidence < 0.5, the
		// majority/Bayesian break-even), not size/hotness -- orthogonal axis to Route E above, testing
		// whether the content-vs-size confound documented there (interpreter_bench regression) also applies
		// here, or whether predictability is a cleaner separator. Coverage preserved.
		if (dbt::config::aot_cpb_optnone && fn && !r.empty() && r[0]->flags.indirect_confidence < 0.5) {
			fn->addFnAttr(llvm::Attribute::OptimizeNone);
			fn->addFnAttr(llvm::Attribute::NoInline);
		}
		aot_symbols->push_back({entry_ip, 0, region_gsize(entry_ip)});
	}
}

// ===========================================================================================
// T5d1b: compile T5d1a's SELECTED hot natural loops as header-rooted LLVM functions.
//
// WHAT THIS PATH IS. One function per selected candidate, whose EXTERNAL ENTRY IS THE LOOP HEADER
// and whose body is exactly the candidate's canonical `body_ips`. It replaces the per-page
// `ComputeRegions()` + `RegionAdmitted()` emission loop; every phase after emission (splice,
// optimize, intrinsic expansion, object, link) is the same code, untouched.
//
// HOW THE HEADER BECOMES THE ENTRY, with no wrapper. `LoopCandidateIpRanges` puts the header first;
// `RV32Translator::Translate` takes `ipranges[0].first` as the region entry and creates blocks in
// that order; `QIRToLLVM::Run` takes block id 0 as `first_bb` and, with `merge_entries` and
// `internal_dispatch_targets` both empty, emits a plain `br first_bb`. There is no entry switch, no
// `CreateLinkEntryWrapper`, no `GlobalAlias`, and `loop_entry_exposed` is never read -- the T5c
// exposure machinery exists to give an INTERIOR block an entry, and here the block that needs one is
// the root.
//
// HOW EXITS STAY EXPLICIT, with no new mechanism. The translator's `ip2bb` holds exactly the body's
// blocks, so any branch target outside the body -- taken, fall-through, or an address the profile
// never executed -- misses the lookup and becomes a `gbr` carrying that target ip. `CreateQCGGbr`
// then either tail-calls another compiled region or emits the generic lazy-link `BranchSlot`, which
// is where the target guest PC lives. This is the SAME contract every existing region exit uses; no
// target is invented anywhere, and an unresolved edge is simply one that finds no function to call.
//
// WHAT IT DOES NOT DO. It calls none of the A/B-line machinery: no `ApplyFunctionClosure`,
// `ApplyJumpTableClosure`, `ApplyReturnClosure`, `ComputeRegions`, `RegionAdmitted`, `AdmitList`,
// `dispatch_admit_*`, edge-merge, move-not-copy, multi-entry wrapper or alias. It adds no admission
// rule of its own: the candidate set is exactly `SelectHotNaturalLoopCandidates()`, i.e. T5d1a's
// `header_exec_freq >= config::threshold`. It performs no promotion and no OSR.
//
// NESTED CANDIDATES STAY DISTINCT and therefore DUPLICATE code -- an inner loop's blocks are
// compiled both in its own function and inside its enclosing loop's. That is a real cost and it is
// counted and printed (`LOOPREGION_SUMMARY ... duplicated_blocks=`) rather than resolved here by a
// new heuristic, which is what T5d1a's "preserve nested candidates as distinct" requires.
static void LLVMAOTCompileLoopRegions(qir::LLVMGenCtx *ctx, std::vector<AOTSymbol> *aot_symbols)
{
	auto mg = BuildWholeProfileGraph();
	if (mg.ip_map.size() + 1 > std::numeric_limits<u16>::max())
		Panic("whole-profile graph exceeds ComputeDomTree's u16 node numbering");
	mg.ComputeDomTree();
	auto cands = mg.SelectHotNaturalLoopCandidates();

	fprintf(stderr, "LOOPREGION_SCOPE nodes=%zu candidates=%zu threshold=%llu vaddr_lo=%08x vaddr_hi=%08x\n",
		mg.ip_map.size(), cands.size(), (unsigned long long)dbt::config::threshold,
		mg.segment.gip_base, mg.segment.gip_base + mg.segment.size);

	auto arena = MemArena(16_MB);
	auto results = EmitLoopRegions(ctx, mg, &arena, cands, (uptr)mmu::base);

	// --aot-loop-regions-qir-out: the QIR of every region, as the translator built it, before any
	// LLVM pass. Default off (null path); nothing above depends on it.
	if (dbt::config::aot_loop_regions_qir_out) {
		std::ofstream qir_out(dbt::config::aot_loop_regions_qir_out);
		for (size_t i = 0; i < results.size(); ++i) {
			qir_out << "; ---- region rooted at " << std::hex << results[i].header_ip << std::dec
				<< " ranges:";
			for (auto const &rg : results[i].ranges)
				qir_out << " " << std::hex << rg.first << "-" << rg.second << std::dec;
			qir_out << "\n" << qir::PrinterPass::run(results[i].region) << "\n";
		}
	}

	std::set<u32> distinct_blocks;
	unsigned long long total_blocks = 0;
	for (size_t i = 0; i < results.size(); ++i) {
		auto const &r = results[i];
		auto const &c = cands[i];
		std::set<u32> pages;
		for (u32 ip : c.body_ips) {
			pages.insert(ip >> mmu::PAGE_BITS);
			distinct_blocks.insert(ip);
		}
		total_blocks += c.body_ips.size();
		size_t n_taken = 0, n_fall = 0, n_unres = 0;
		for (auto const &e : r.exits)
			switch (e.kind) {
			case ModuleGraph::LoopExit::Kind::TAKEN:
				n_taken++;
				break;
			case ModuleGraph::LoopExit::Kind::FALLTHROUGH:
				n_fall++;
				break;
			case ModuleGraph::LoopExit::Kind::UNRESOLVED:
				n_unres++;
				break;
			}

		fprintf(stderr,
			"LOOPREGION header=%08x symbol=%s exec_freq=%llu nbody=%zu nlatch=%zu pages=%zu "
			"qir_blocks=%u insns=%u exits=%zu taken=%zu fallthrough=%zu unresolved=%zu\n",
			c.header_ip, r.fn ? r.fn->getName().str().c_str() : "<none>",
			(unsigned long long)c.header_exec_freq, c.body_ips.size(), c.latch_ips.size(),
			pages.size(), r.qir_blocks, r.region->num_insns, r.exits.size(), n_taken, n_fall,
			n_unres);
		fprintf(stderr, "LOOPREGION_BODY header=%08x body=", c.header_ip);
		for (size_t k = 0; k < c.body_ips.size(); ++k)
			fprintf(stderr, "%s%08x", k ? "," : "", c.body_ips[k]);
		fprintf(stderr, "\n");
		for (auto const &e : r.exits) {
			char const *kind = e.kind == ModuleGraph::LoopExit::Kind::TAKEN	      ? "TAKEN"
					   : e.kind == ModuleGraph::LoopExit::Kind::FALLTHROUGH ? "FALLTHROUGH"
											       : "UNRESOLVED";
			// Whether this exit found a compiled callee is a fact about the module, read
			// back from it rather than predicted.
			bool direct = ctx->cmodule.getFunction(MakeAotSymbol(e.tgt_ip)) != nullptr;
			fprintf(stderr, "LOOPREGION_EXIT header=%08x src=%08x tgt=%08x kind=%s direct_call=%d\n",
				c.header_ip, e.src_ip, e.tgt_ip, kind, (int)direct);
		}

		// gsize 0: this checkpoint makes no cross-program byte-identity reuse claim (AARS), and a
		// loop body is not a contiguous guest extent anyway, so the honest window is none.
		aot_symbols->push_back({c.header_ip, 0, 0});
		dbt::config::g_loopregion_functions++;
	}
	dbt::config::g_loopregion_body_blocks = total_blocks;
	dbt::config::g_loopregion_distinct_blocks = distinct_blocks.size();
	fprintf(stderr,
		"LOOPREGION_SUMMARY functions=%llu body_blocks=%llu distinct_blocks=%llu duplicated_blocks=%llu\n",
		dbt::config::g_loopregion_functions, dbt::config::g_loopregion_body_blocks,
		dbt::config::g_loopregion_distinct_blocks,
		dbt::config::g_loopregion_body_blocks - dbt::config::g_loopregion_distinct_blocks);
}

static void AddAOTTabSection(llvm::Module &cmodule, std::vector<AOTSymbol> &aot_symbols)
{
	size_t aottab_size = sizeof(AOTTabHeader) + sizeof(aot_symbols[0]) * aot_symbols.size();
	auto type = llvm::ArrayType::get(llvm::Type::getInt8Ty(cmodule.getContext()), aottab_size);
	auto zeroinit = llvm::ConstantAggregateZero::get(type);
	auto aottab = new llvm::GlobalVariable(cmodule, type, true, llvm::GlobalVariable::ExternalLinkage,
					       zeroinit, AOT_SYM_AOTTAB);

	aottab->setAlignment(llvm::Align(alignof(AOTTabHeader)));
	aottab->setSection(".aottab");

	// CPUState layout signature. The artifact bakes CPUState field offsets into its machine
	// code, and the cache path is keyed only by the guest ELF checksum, so the loader has no
	// other way to tell that an artifact was built against a different layout. Emitted as an
	// initialised global so aot_boot can dlsym and compare it. See dbt/guest/rv32_cpu.h.
	auto abity = llvm::Type::getInt64Ty(cmodule.getContext());
	auto abi = new llvm::GlobalVariable(cmodule, abity, true, llvm::GlobalVariable::ExternalLinkage,
					    llvm::ConstantInt::get(abity, rv32::CPUStateAbiSignature()),
					    AOT_SYM_ABI);
	abi->setAlignment(llvm::Align(alignof(u64)));

	// X4g2: the RVV VLEN this artifact is specialized for. Emitted beside the ABI signature and
	// checked by the same loader gate. This is the LLVM producer; AOTCompileELF() (the non-LLVM
	// QCG producer, aot_file.cpp) emits neither this nor AOT_SYM_ABI, so its artifacts are already
	// refused at every load entry -- adding the VLEN check does not newly reject anything there.
	// If that producer is ever given AOT_SYM_ABI, it must gain this symbol in the same change, or
	// the VLEN gate silently becomes a hard refusal for the whole QCG-AOT path; the source audit
	// in scripts/vlen_propagation_audit.py enforces exactly that pairing (gate G5).
	auto vlenty = llvm::Type::getInt64Ty(cmodule.getContext());
	auto vlen = new llvm::GlobalVariable(cmodule, vlenty, true, llvm::GlobalVariable::ExternalLinkage,
					     llvm::ConstantInt::get(vlenty, config::vlen_bits),
					     AOT_SYM_VLEN);
	vlen->setAlignment(llvm::Align(alignof(u64)));
}

static llvm::TargetMachine *GetAOTTargetMachine()
{
	static auto machine = ([]() {
		auto ttriple = llvm::sys::getProcessTriple();
		llvm::InitializeNativeTarget();
		llvm::InitializeNativeTargetAsmPrinter();
		llvm::InitializeNativeTargetAsmParser();
		std::string error;
		auto target = llvm::TargetRegistry::lookupTarget(ttriple, error);
		if (!target) {
			Panic(error);
		}

		llvm::SubtargetFeatures features;
		{
			for (const auto &[Feature, Enabled] : llvm::sys::getHostCPUFeatures())
				features.AddFeature(Feature, Enabled);
		}

		llvm::TargetOptions opt;
		auto RM = llvm::Reloc::Model(llvm::Reloc::PIC_);
		auto host_cpu = llvm::sys::getHostCPUName();
		int cgo = dbt::config::aot_codegen_optlevel;
		auto cgol = cgo < 0	 ? llvm::CodeGenOptLevel::Aggressive
			    : cgo == 0	 ? llvm::CodeGenOptLevel::None
			    : cgo == 1	 ? llvm::CodeGenOptLevel::Less
			    : cgo == 2	 ? llvm::CodeGenOptLevel::Default
					 : llvm::CodeGenOptLevel::Aggressive;
		// LLVM 21+ takes a parsed Triple here instead of a string.
#if LLVM_VERSION_MAJOR >= 21
		return target->createTargetMachine(llvm::Triple(ttriple), host_cpu,
						   features.getString(), opt, RM, {}, cgol);
#else
		return target->createTargetMachine(ttriple, host_cpu, features.getString(), opt, RM, {}, cgol);
#endif
	})();

	return machine;
}

static void GenerateObjectFile(llvm::Module *cmodule, std::string const &filename)
{
	auto tmachine = GetAOTTargetMachine();
	cmodule->setDataLayout(tmachine->createDataLayout());
	// Module::setTargetTriple also takes a Triple from LLVM 21 on; same value either way.
#if LLVM_VERSION_MAJOR >= 21
	cmodule->setTargetTriple(tmachine->getTargetTriple());
#else
	cmodule->setTargetTriple(tmachine->getTargetTriple().str());
#endif
	cmodule->setPICLevel(llvm::PICLevel::SmallPIC);

	std::error_code errc;
	llvm::raw_fd_ostream dest(filename, errc, llvm::sys::fs::OF_None);

	if (errc) {
		llvm::errs() << "can't open file: " << errc.message();
		Panic();
	}

	llvm::legacy::PassManager pass;
	auto FileType = llvm::CodeGenFileType::ObjectFile;

	log_aot("adding passes to emit file");
	if (tmachine->addPassesToEmitFile(pass, dest, nullptr, FileType)) {
		llvm::errs() << "emit objfile failed";
		Panic();
	}

	log_aot("running passes");
	// cmodule->print(llvm::errs(), nullptr);
	// pass.add(llvm::createEarlyCSEPass());
	pass.run(*cmodule);
	// log_aot("flushing file");
	dest.flush();
}

// Design 8 alias multi-entry cross-page safety (see dbt/config.h's g_direct_branch_targets
// comment): a raw, single-pass scan of every executed instruction across ALL pages, recording
// every jal/branch immediate target. Cheap (linear, same cost class as FindJumpTableCandidates'
// existing per-function scans) and computed ONCE regardless of how many pages exist.
static void BuildGlobalDirectBranchTargets()
{
	if (dbt::config::g_direct_branch_targets_built)
		return;
	dbt::config::g_direct_branch_targets_built = true;
	for (auto const &page : objprof::GetProfile()) {
		u32 page_vaddr = page.pageno << mmu::PAGE_BITS;
		for (u32 idx = 0; idx < page.executed.size(); ++idx) {
			if (!page.executed[idx])
				continue;
			u32 ip = page_vaddr + objprof::PageData::idx2po(idx);
			u32 raw = *(u32 const *)((uptr)mmu::base + ip);
			u32 op = raw & 0x7f;
			if (op == 0x6f) { // jal
				rv32::insn::J j{raw};
				dbt::config::g_direct_branch_targets.insert(ip + (u32)j.imm());
			} else if (op == 0x63) { // branch (beq/bne/blt/...)
				rv32::insn::B b{raw};
				dbt::config::g_direct_branch_targets.insert(ip + (u32)b.imm());
			}
		}
	}
}

void LLVMAOTCompileELF()
{
	// V-next R4: applicability gate dry-run -- print profile-derived features and exit (no codegen/link).
	if (dbt::config::dump_applicability) {
		DumpApplicabilityFeatures();
		return;
	}
	if (dbt::config::aot_link_alias_merge)
		BuildGlobalDirectBranchTargets();

	auto cmodule = llvm::Module("qcg_module", qir::g_llvm_ctx);
	qir::LLVMGenCtx ctx(&cmodule);

	std::vector<AOTSymbol> aot_symbols;
	aot_symbols.reserve(64_KB);
	// 2026-06-23: with --aot-skip-nonelf, skip profile pages outside the ELF's PF_X ranges. A generated-code
	// workload's profile contains runtime gen-code pages (mmap'd, not in the static ELF); reading their
	// unmapped guest addresses SIGSEGVs the AOT. Skipping them compiles only the static .text (no-op when
	// every exec page is ELF-backed). Enables AOT-static + JIT/NGR-gencode in one run.
	auto is_elf_exec = [](objprof::PageData const &page) -> bool {
		if (!config::aot_skip_nonelf)
			return true;
		uint32_t pv = page.pageno << mmu::PAGE_BITS;
		for (auto const &r : config::g_elf_exec_ranges)
			if (pv >= r.first && pv < r.second)
				return true;
		return false;
	};
	// T5d1b: the loop-rooted mode replaces everything from here to the end of the per-page translate
	// loop -- declaration, region formation and emission -- and nothing else. Every phase after it
	// (the alwaysinline splice, the optimize/expand iterations, object emission and link) is the
	// same code on both paths. With the flag off not one line of it runs, which is what makes the
	// flag-off artifact byte-identical rather than merely expected to be.
	bool const loop_regions = dbt::config::aot_loop_regions;
	if (!loop_regions) {
	for (auto const &page : objprof::GetProfile()) {
		if (!is_elf_exec(page))
			continue;
		DeclareKnownRegionEntries(&ctx, page);
	}
	}
	GlobalRegionRanges global_region_ranges;
	if (dbt::config::aot_edge_region_merge && !loop_regions) {
		for (auto const &page : objprof::GetProfile()) {
			if (!is_elf_exec(page))
				continue;
			auto mg = BuildModuleGraph(page);
			auto regions = mg.ComputeRegions();
			for (auto const &r : regions) {
				if (r.empty())
					continue;
				auto &ranges = global_region_ranges[r[0]->ip];
				for (auto n : r)
					ranges.push_back({n->ip, n->ip_end});
			}
		}
	}
	// A-line move-not-copy pass A: decide which merge targets fire, BEFORE any page is emitted
	// (the source and its targets can be on different pages). Mirrors the emission-time merge
	// conditions (admitted source region owning msrc, target has a global range) plus one
	// CONSERVATIVE precondition: every target range must be FRESH w.r.t. the source region's own
	// ranges and previously-processed targets -- a deduped-away range means the target entry may
	// not exist as a distinct block, so such targets keep the safe copy semantics.
	g_move_fired.clear();
	g_move_source_regions.clear();
	g_move_thunks.clear();
	if (dbt::config::aot_edge_move_not_copy && dbt::config::aot_edge_region_merge &&
	    !dbt::config::aot_region_merge_map.empty() && !loop_regions) {
		for (auto const &page : objprof::GetProfile()) {
			if (!is_elf_exec(page))
				continue;
			auto mg = BuildModuleGraph(page);
			auto regions = mg.ComputeRegions();
			for (auto const &r : regions) {
				if (r.empty())
					continue;
				u64 mx;
				if (!RegionAdmitted(r, mx))
					continue;
				std::set<std::pair<u32, u32>> included;
				for (auto n : r)
					included.emplace(n->ip, n->ip_end);
				for (auto const &[msrc, mtgts] : dbt::config::aot_region_merge_map) {
					bool owns = std::any_of(r.begin(), r.end(),
								[&](auto *n) { return n->ip == msrc; });
					if (!owns)
						continue;
					g_move_source_regions.insert(r[0]->ip);
					for (u32 tgt : mtgts) {
						auto tr = global_region_ranges.find(tgt);
						if (tr == global_region_ranges.end())
							continue;
						bool fresh = true;
						for (auto const &range : tr->second)
							if (included.count(range)) {
								fresh = false;
								break;
							}
						for (auto const &range : tr->second)
							included.insert(range);
						if (fresh)
							g_move_fired.emplace(tgt, r[0]->ip);
					}
				}
			}
		}
	}
	// A-line round 23 Gate 3 pivot (--aot-log-phase-timing, default off): Gate 1/2 repeatedly
	// found evidence+compile jointly dominate full-single-run totals (65-78% on real corpus,
	// n=10) while never having measured WHERE inside compile_wall the time actually goes --
	// coarse wall-clock brackets around the three largest phases (per-page region/QIR/LLVM-IR
	// construction; the n_expands optimize+intrinsic-expand loop; final object emission+link).
	auto t_phase0 = std::chrono::steady_clock::now();
	if (loop_regions) {
		LLVMAOTCompileLoopRegions(&ctx, &aot_symbols);
	} else {
	for (auto const &page : objprof::GetProfile()) {
		if (!is_elf_exec(page))
			continue;
		LLVMAOTTranslatePage(&ctx, &aot_symbols, page,
			dbt::config::aot_edge_region_merge ? &global_region_ranges : nullptr);
	}
	}
	auto t_phase1 = std::chrono::steady_clock::now();
	// A-line Round 51: directly, deterministically splice every eagerly-constructed
	// --aot-static-table-alwaysinline call site now that every region function across the WHOLE ELF
	// has a real body. A call recorded during Emit_gbrind may be a forward reference to a not-yet-
	// Run() region (possibly on another page) -- DeclareKnownRegionEntries (above) already gave
	// every admitted region a real llvm::Function* DECLARATION before any page was translated, but
	// only NOW, after the translate loop above, do all of them have real BODIES to inline. Uses
	// llvm::InlineFunction directly -- no reliance on any heuristic pass's ordering or attribute-
	// matching semantics (Round 50's llvm::Attribute::AlwaysInline approach was falsified: see
	// CreateInlinableQCGFnCall's comment in llvmgen.cpp for the precise root cause).
	//
	// CORRECTNESS (fixed same round, before any economics claim, per a live IR-dump audit): neither
	// "splice succeeded" nor "splice failed" is safe to leave as-is without a follow-up check --
	// (a) a FAILED splice leaves the original call exactly as CreateInlinableQCGFnCall built it
	//     (TCK_Tail hint + ret void) -- a plain tail HINT is not a guarantee; upgraded here to
	//     TCK_MustTail, exactly reproducing CreateQCGFnCall's own shape, so a failed-to-inline site
	//     is byte-for-byte as safe as if this mechanism had never touched it.
	// (b) a SUCCEEDED splice can still leave the CALLEE's own onward dispatch calls (whatever this
	//     specific target itself tail-calls into) in a non-tail shape if LLVM's inliner did not
	//     recognize/propagate the tail position for some reason not yet fully characterized --
	//     confirmed as a REAL failure mode this round via a live IR dump on pcre2_super (ordinary,
	//     non-tail `call ghccc void @intr_gbr(...)` instructions appeared post-splice). Every
	//     touched caller function is scanned below for exactly this shape; a genuinely-still-tail-
	//     positioned-but-untagged dispatch call (the last real instruction before a compatible
	//     `ret`) is repaired the same way (upgraded to TCK_MustTail) -- a sound, structural
	//     transform (mirroring what LLVM's own tail-call-elimination pass does), not a guess. Any
	//     dispatch call that is NOT structurally in tail position after splicing is an
	//     unrecoverable violation of this architecture's core unbounded-tail-dispatch invariant --
	//     this compile is ABORTED rather than silently emitting a broken artifact.
	if (!ctx.pending_alwaysinline_splices.empty()) {
		unsigned n_ok = 0, n_failed = 0;
		std::set<llvm::Function *> touched_callers;
		bool dump_ir = getenv("DBT_ALWAYSINLINE_DUMP_IR") != nullptr;
		for (llvm::CallInst *call : ctx.pending_alwaysinline_splices) {
			touched_callers.insert(call->getParent()->getParent());
			llvm::InlineFunctionInfo ifi;
			auto result = llvm::InlineFunction(*call, ifi);
			if (result.isSuccess()) {
				n_ok++;
			} else {
				n_failed++;
				if (getenv("DBT_ALWAYSINLINE_LOG"))
					fprintf(stderr, "ALWAYSINLINE_SPLICE_FAILED reason=%s\n",
						result.getFailureReason());
				// (a) above: restore the strict musttail guarantee for this untouched call.
				call->setTailCallKind(llvm::CallInst::TCK_MustTail);
			}
		}
		if (dump_ir) {
			std::error_code ec;
			llvm::raw_fd_ostream os("/tmp/dbt_alwaysinline_ir_dump.ll", ec);
			for (auto *fn : touched_callers) {
				fn->print(os);
				os << "\n";
			}
			fprintf(stderr, "ALWAYSINLINE_IR_DUMP functions=%zu path=/tmp/dbt_alwaysinline_ir_dump.ll\n",
				touched_callers.size());
		}
		// (b) above: repair-or-abort scan over every function this mechanism touched.
		unsigned n_repaired = 0;
		for (llvm::Function *fn : touched_callers) {
			for (auto &bb : *fn) {
				for (auto &insn : bb) {
					auto *ci = llvm::dyn_cast<llvm::CallInst>(&insn);
					if (!ci)
						continue;
					if (ci->getCallingConv() != llvm::CallingConv::GHC)
						continue;
					if (!ci->getType()->isVoidTy())
						continue; // every dispatch primitive in this codebase returns void
					// Deferred intrinsic stand-ins (intr_gbr/intr_gbrind) are DELIBERATELY left in
					// "tail call ... ; unreachable" shape until IntrinsicExpansionPass (a
					// ModuleToFunctionPassAdaptor -- runs over EVERY function in the module,
					// regardless of which one now holds the call after inlining) properly expands
					// them into a real, final musttail dispatch, exactly the same way it already
					// does for every non-inlined function in this codebase. Inlining only moved
					// these calls to a different function; it did not change this pass's ability to
					// find and correctly finish them. Not this scan's responsibility -- verified by
					// grep: their construction sites (llvmgen.cpp CreateQCGGbr/Emit_gbrind) never
					// use TCK_MustTail or `ret void` either, by design.
					if (auto *callee = ci->getCalledFunction();
					    callee && (callee->getName() == "intr_gbr" || callee->getName() == "intr_gbrind"))
						continue;
					auto kind = ci->getTailCallKind();
					if (kind == llvm::CallInst::TCK_MustTail)
						continue; // already the hard guarantee -- nothing to do
					// CORRECTNESS FIX (same round, caught via disassembly, not assumed): a bare
					// `tail` kind (unlike `musttail`) is only an OPTIMIZATION HINT -- LLVM's own
					// InlineFunction demotes a spliced-in musttail call down to plain `tail` when
					// the call site it replaced was itself only `tail` (not `musttail`, since
					// musttail can never be an inline call site) -- confirmed via a live
					// disassembly+IR-dump audit on pcre2_super: a call that read `tail call ghccc
					// void @_x2a0e0(...)` in the post-splice IR (this exact case, previously
					// treated as "already fine" and skipped) compiled down to an ORDINARY,
					// non-tail `call` instruction in the final object -- LLVM's backend is free to
					// skip real sibling-call codegen for a mere hint. TCK_Tail is therefore treated
					// exactly like TCK_None below: it must be verified structurally and upgraded to
					// TCK_MustTail (the hard guarantee), or the compile is aborted.
					// Structural check: is this call the last REAL instruction before a `ret
					// void` in the SAME block? That is exactly tail position, regardless of
					// whether the inliner happened to tag it as such. "Real" skips debug
					// intrinsics (getNextNonDebugInstruction already does that) AND
					// llvm.lifetime.end markers -- InlineFunction inserts these after a spliced
					// callee's own final call to mark its now-inlined allocas' lifetime as over;
					// they are pure optimizer metadata (no runtime effect, no control-flow/stack
					// impact) and do not change whether the preceding call is genuinely in tail
					// position -- confirmed via a live IR-dump audit on pcre2_super, where exactly
					// this shape (`tail call ... @_x27910(...); call void @llvm.lifetime.end...
					// (x7); ret void`) was the false-positive this check needs to see through.
					llvm::SmallVector<llvm::CallInst *, 8> lifetime_ends;
					llvm::Instruction *next = NextNonDebugInsn(ci);
					while (auto *lc = llvm::dyn_cast_or_null<llvm::CallInst>(next)) {
						auto *intr = lc->getCalledFunction();
						if (!intr || intr->getIntrinsicID() != llvm::Intrinsic::lifetime_end)
							break;
						lifetime_ends.push_back(lc);
						next = NextNonDebugInsn(lc);
					}
					// Inlining commonly unifies a callee's several original exit paths into one
					// shared "<callee>.exit" block via an unconditional branch (a standard LLVM
					// inlining artifact, not something specific to this codebase) -- follow ONE
					// such hop if the target block is trivially just `ret void` and nothing else
					// (bounded: this is a single, structural check, not an open-ended CFG walk).
					// Confirmed via the same pcre2_super audit: `tail call ...@_x2a0e0(...); (7x
					// lifetime.end); br label %_x27780.exit`, where `_x27780.exit:` contains only
					// `ret void` (and has a SECOND, unrelated predecessor -- removing just this
					// one edge by returning directly instead of branching there is still fully
					// safe: a void return has no PHI to break, and the other predecessor's own
					// edge to that block is untouched).
					llvm::BranchInst *redirect_br = nullptr;
					if (auto *br = llvm::dyn_cast_or_null<llvm::BranchInst>(next);
					    br && br->isUnconditional()) {
						auto *target = br->getSuccessor(0);
						if (target->size() == 1 && llvm::isa<llvm::ReturnInst>(target->front()) &&
						    !llvm::cast<llvm::ReturnInst>(target->front()).getReturnValue()) {
							redirect_br = br;
						}
					}
					auto *ret = redirect_br ? nullptr : llvm::dyn_cast_or_null<llvm::ReturnInst>(next);
					if (redirect_br || (ret && !ret->getReturnValue())) {
						// The verifier requires a musttail call be LITERALLY adjacent to its
						// ret (skipping only an optional bitcast) -- erase the (dead-at-this-
						// point, no-op) lifetime.end markers physically so the IR satisfies
						// that requirement, not just "structurally equivalent".
						for (auto *lc : lifetime_ends)
							lc->eraseFromParent();
						if (redirect_br) {
							// Replace "br label %exit" with a real "ret void" in THIS block --
							// behaviorally identical (the target block did nothing but return),
							// and now the call is LITERALLY adjacent to a ret, satisfying the
							// verifier directly instead of relying on a cross-block equivalence.
							llvm::ReturnInst::Create(fn->getContext(), nullptr, redirect_br->getParent());
							redirect_br->eraseFromParent();
						}
						ci->setTailCall(true);
						ci->setTailCallKind(llvm::CallInst::TCK_MustTail);
						n_repaired++;
					} else {
						fprintf(stderr,
							"ALWAYSINLINE_UNSAFE_RESIDUAL_CALL fn=%s callee=%s -- not in tail "
							"position after splicing; aborting compile rather than emit a "
							"stack-unsafe artifact\n",
							fn->getName().str().c_str(),
							ci->getCalledFunction() ? ci->getCalledFunction()->getName().str().c_str()
										 : "<indirect>");
						abort();
					}
				}
			}
		}
		fprintf(stderr, "ALWAYSINLINE_SPLICE ok=%u failed=%u repaired=%u\n", n_ok, n_failed, n_repaired);
	}
	// A-line move-not-copy verification: every emitted thunk's target MUST have a real entry-switch
	// case in its source function (recorded at Run()-time in fn2switch_cases). A missing case would
	// make the thunk fall through to the source's own entry block with a wrong state->ip -- abort
	// the compile loudly rather than ever produce a wrong artifact.
	if (!g_move_thunks.empty()) {
		for (auto const &[tgt, src] : g_move_thunks) {
			auto it = ctx.fn2switch_cases.find(MakeAotSymbol(src));
			if (it == ctx.fn2switch_cases.end() || !it->second.count(tgt)) {
				fprintf(stderr,
					"EDGE_MOVE_VERIFY_FAIL tgt=%08x src_fn=%08x entry-switch case missing -- aborting\n",
					tgt, src);
				abort();
			}
		}
		fprintf(stderr, "EDGE_MOVE_SUMMARY thunks=%zu verified=OK\n", g_move_thunks.size());
	}
	assert(!verifyModule(cmodule, &llvm::errs()));

	// OPAQUE_BOUNDARY mechanism ladder (2026-08-21, default off, DIAGNOSTIC ONLY): same matcher
	// as llvmgen.cpp's DiagNameInList (duplicated locally rather than shared across TUs -- both
	// are a few lines and this keeps the diagnostic self-contained per file).
	auto diag_name_in_list = [](char const *spec, std::string_view name) {
		if (!spec)
			return false;
		std::string_view sv(spec);
		size_t pos = 0;
		while (pos <= sv.size()) {
			size_t next = sv.find(':', pos);
			auto piece =
			    sv.substr(pos, next == std::string_view::npos ? std::string_view::npos : next - pos);
			if (piece == name)
				return true;
			if (next == std::string_view::npos)
				break;
			pos = next + 1;
		}
		return false;
	};

	// OPAQUE_BOUNDARY diagnostic (2026-08-21, default off, DIAGNOSTIC ONLY): if a helper bitcode
	// module is supplied, link it into cmodule now, BEFORE the optimization pipeline below runs,
	// so LLVM's own CGSCC/inliner passes see real function bodies at hcall sites instead of bare
	// external declarations. This is generic across whatever functions the supplied bitcode
	// defines and whatever call sites reference them by name -- it is not specific to any
	// workload or opcode, and it adds no new codegen logic of its own; every optimization
	// decision after linking is made by LLVM's stock passes.
	if (dbt::config::aot_diag_link_bitcode) {
		unsigned n_targets_before = 0;
		std::vector<std::string> target_names;
		for (auto &fn : cmodule) {
			// Filter to qcgstub_* declarations specifically (not every declaration in the
			// module -- LLVM intrinsics etc. are external declarations too and are neither
			// meant to be linked from this bitcode nor meaningful in this count).
			if (fn.isDeclaration() && fn.getName().starts_with("qcgstub_")) {
				n_targets_before++;
				target_names.push_back(fn.getName().str());
			}
		}
		llvm::SMDiagnostic diag;
		std::unique_ptr<llvm::Module> helperModule =
		    llvm::parseIRFile(dbt::config::aot_diag_link_bitcode, diag, qir::g_llvm_ctx);
		if (!helperModule) {
			fprintf(stderr, "OPAQUE_BOUNDARY_DIAG: failed to parse %s: %s\n",
				dbt::config::aot_diag_link_bitcode, diag.getMessage().str().c_str());
			abort();
		}
		llvm::Linker linker(cmodule);
		if (linker.linkInModule(std::move(helperModule), llvm::Linker::Flags::LinkOnlyNeeded)) {
			fprintf(stderr, "OPAQUE_BOUNDARY_DIAG: linkInModule failed for %s\n",
				dbt::config::aot_diag_link_bitcode);
			abort();
		}
		unsigned n_resolved = 0;
		for (auto const &name : target_names) {
			auto *fn = cmodule.getFunction(name);
			if (fn && !fn->isDeclaration())
				n_resolved++;
		}
		fprintf(stderr,
			"OPAQUE_BOUNDARY_DIAG linked=%s decl_targets_before=%u resolved_to_definitions=%u\n",
			dbt::config::aot_diag_link_bitcode, n_targets_before, n_resolved);

		// Split every now-defined function named in aot_diag_direct_funcs into two groups:
		// those ALSO named in aot_diag_inline_funcs get alwaysinline (A3, the visibility
		// arm); everything else that got a body linked in is explicitly marked noinline (A2,
		// linkage/build effects present, call boundary deliberately preserved) rather than
		// left to the standard pipeline's own size/cost heuristic, so A2 is a controlled,
		// well-defined arm rather than "probably still a call, un-audited".
		auto diag_list_split = [&](char const *spec, char const *inline_spec) {
			if (!spec)
				return;
			std::string s = spec;
			size_t pos = 0;
			unsigned n_inlined = 0, n_noinline = 0;
			while (pos <= s.size()) {
				size_t next = s.find(':', pos);
				std::string name = s.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
				if (!name.empty()) {
					// spec entries are bare stub names (e.g. "rv32_vfma"); the linked
					// LLVM symbol is qcgstub_##name -- see Emit_hcall's matching
					// comment in llvmgen.cpp for why the two names differ.
					if (auto *fn = cmodule.getFunction("qcgstub_" + name);
					    fn && !fn->isDeclaration()) {
						bool force_inline =
						    inline_spec && diag_name_in_list(inline_spec, name);
						if (force_inline) {
							fn->removeFnAttr(llvm::Attribute::NoInline);
							fn->addFnAttr(llvm::Attribute::AlwaysInline);
							n_inlined++;
						} else {
							fn->removeFnAttr(llvm::Attribute::AlwaysInline);
							fn->addFnAttr(llvm::Attribute::NoInline);
							n_noinline++;
						}
					}
				}
				if (next == std::string::npos)
					break;
				pos = next + 1;
			}
			fprintf(stderr, "OPAQUE_BOUNDARY_DIAG alwaysinline_marked=%u noinline_marked=%u\n",
				n_inlined, n_noinline);
		};
		diag_list_split(dbt::config::aot_diag_direct_funcs, dbt::config::aot_diag_inline_funcs);
		assert(!verifyModule(cmodule, &llvm::errs()));
	}
	if (dbt::config::aot_dump_llvm_ir_preopt) {
		std::error_code ec;
		llvm::raw_fd_ostream ir_out(dbt::config::aot_dump_llvm_ir_preopt, ec,
					    llvm::sys::fs::OF_Text);
		if (ec) {
			fprintf(stderr, "cannot open %s for pre-optimization IR dump: %s\n",
				dbt::config::aot_dump_llvm_ir_preopt, ec.message().c_str());
		} else {
			cmodule.print(ir_out, nullptr);
			fprintf(stderr, "wrote pre-optimization LLVM IR to %s\n",
				dbt::config::aot_dump_llvm_ir_preopt);
		}
	}

	llvm::LoopAnalysisManager lam;
	llvm::FunctionAnalysisManager fam;
	llvm::CGSCCAnalysisManager cgam;
	llvm::ModuleAnalysisManager mam;

	llvm::PassBuilder pb;
	pb.registerModuleAnalyses(mam);
	pb.registerCGSCCAnalyses(cgam);
	pb.registerFunctionAnalyses(fam);
	pb.registerLoopAnalyses(lam);
	pb.crossRegisterProxies(lam, fam, cgam, mam);

	auto optlevel = dbt::config::aot_optlevel <= 0 ? llvm::OptimizationLevel::O0
			: dbt::config::aot_optlevel == 1 ? llvm::OptimizationLevel::O1
			: dbt::config::aot_optlevel == 2 ? llvm::OptimizationLevel::O2
							 : llvm::OptimizationLevel::O3;

	llvm::ModulePassManager mpm_final_expand;
	mpm_final_expand.addPass(
	    llvm::createModuleToFunctionPassAdaptor(qir::IntrinsicExpansionPass(ctx, true)));
	// A-line round 23 Gate 1 Row 5 (oracle-only): the gbrind intrinsic is only fully expanded into
	// its real musttail-indirect-call form by IntrinsicExpansionPass above -- ICP must run
	// immediately after, in this SAME pass manager, before any subsequent iteration's default
	// pipeline (which never includes ICP -- PassBuilder pb is built with no PGOOptions) has a
	// chance to inline/CSE the call away first.
	if (dbt::config::aot_gbrind_vp_metadata)
		mpm_final_expand.addPass(llvm::PGOIndirectCallPromotion());
	if constexpr (config::debug) {
		mpm_final_expand.addPass(llvm::VerifierPass());
	}

	pb.registerOptimizerEarlyEPCallback([&](
		llvm::ModulePassManager &mpm, llvm::OptimizationLevel optl
		, llvm::ThinOrFullLTOPhase phase // this line is for llvm 20, for 19 or below, plz comment this parameter
		) {
		mpm.addPass(llvm::createModuleToFunctionPassAdaptor(qir::IntrinsicExpansionPass(ctx, false)));

		if constexpr (config::debug) {
			mpm.addPass(llvm::VerifierPass());
		}
	});

	static constexpr uint n_expands = 4;
	// Round-54: the final (bulk) intrinsic expansion runs at this iteration (default = last). Moving it earlier
	// tests the expand-first/single-phase schedule.
	int final_iter = dbt::config::aot_final_expand_at < 0 ? (int)n_expands - 1
			 : std::min(dbt::config::aot_final_expand_at, (int)n_expands - 1);

	for (int i = 0; i < n_expands; ++i) {
		if (dbt::config::aot_log_expand)
			dbt::config::intrin_expand_count = 0; // Round-44: reset per-iteration expansion counter
		if (i == final_iter) {
			log_aot("Run final expansion pipeline");
			mpm_final_expand.run(cmodule, mam);
			if (dbt::config::aot_log_icp) {
				// A-line round 23 Gate 1 Row 5 reachability evidence: LLVM's ICP pass
				// (llvm/lib/Transforms/Instrumentation/IndirectCallPromotion.cpp) hard-codes
				// "if.true.direct_targ" as the promoted-call block name prefix (confirmed
				// against an isolated opt -passes=pgo-icall-prom witness run this round) --
				// counting them is an unambiguous "did ICP actually fire" signal independent
				// of any diagnostic-handler plumbing.
				unsigned long n_promoted_blocks = 0, n_vp_calls_remaining = 0;
				for (auto &fn : cmodule) {
					for (auto &bb : fn) {
						if (bb.getName().starts_with("if.true.direct_targ"))
							n_promoted_blocks++;
						for (auto &insn : bb) {
							if (auto *ci = llvm::dyn_cast<llvm::CallBase>(&insn))
								if (ci->getMetadata(llvm::LLVMContext::MD_prof))
									n_vp_calls_remaining++;
						}
					}
				}
				fprintf(stderr,
					"ICP_REACHABILITY promoted_blocks=%lu vp_tagged_calls_remaining=%lu\n",
					n_promoted_blocks, n_vp_calls_remaining);
			}
		}
		log_aot("Run optimize+expand pipeline");
		// TODO: something breaks, invalidating all analyses dont help, create pipeline again
		// llvm::ModulePassManager mpm = pb.buildPerModuleDefaultPipeline(optlevel);
		llvm::ModulePassManager mpm;
		// Round-42: aot_heavy_final -> only the final expand iteration runs heavy O3; iterations 0..n-2
		// do expand (manual, since the default pipeline's EarlyEP won't fire here) + light cleanup. Cuts
		// the per-function O3 setup paid ~n_expands times down to ~once, keeping ~O3 quality (heavy opt
		// runs on the fully-expanded code).
		// Round-42 frontier: heavy O3 on the last hn expand iterations; the rest do expand+light.
		unsigned hn = dbt::config::aot_heavy_last_n ? dbt::config::aot_heavy_last_n
							    : (dbt::config::aot_heavy_final ? 1u : n_expands);
		// Round-42 region-count-aware: small modules (few admitted regions) keep >=2 heavy iterations,
		// where the early heavy opt contributes real quality to a tight hot loop.
		if (dbt::config::aot_heavy_min_regions > 0 && aot_symbols.size() < dbt::config::aot_heavy_min_regions)
			hn = std::max(hn, 2u);
		bool heavy = (i >= (int)n_expands - (int)hn);
		if (!heavy) {
			mpm.addPass(llvm::createModuleToFunctionPassAdaptor(qir::IntrinsicExpansionPass(ctx, false)));
			llvm::FunctionPassManager fpm;
			fpm.addPass(llvm::InstCombinePass());
			fpm.addPass(llvm::SimplifyCFGPass());
			mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(fpm)));
		} else if (dbt::config::aot_pipeline && dbt::config::aot_pipeline[0]) {
			// Route A custom reduced pipeline (heavy iteration). Manually expand first, then the parsed
			// passes. On parse error, consume + fall back to the default O3 pipeline.
			mpm.addPass(llvm::createModuleToFunctionPassAdaptor(qir::IntrinsicExpansionPass(ctx, false)));
			if (auto err = pb.parsePassPipeline(mpm, dbt::config::aot_pipeline)) {
				llvm::consumeError(std::move(err));
				log_aot("bad --aot-pipeline; falling back to default O-level");
				mpm.addPass(pb.buildPerModuleDefaultPipeline(optlevel));
			}
		} else if (dbt::config::llvmopt) {
			// Round-54: Phase-1 heavy iterations (before the final expansion) may use a cheaper opt level
			// (test whether optimizing the opaque-intrinsic surroundings needs full O3 or less).
			auto iter_optlevel = optlevel;
			if (i < final_iter && dbt::config::aot_phase1_optlevel >= 0) {
				iter_optlevel = dbt::config::aot_phase1_optlevel <= 0 ? llvm::OptimizationLevel::O0
					: dbt::config::aot_phase1_optlevel == 1 ? llvm::OptimizationLevel::O1
					: dbt::config::aot_phase1_optlevel == 2 ? llvm::OptimizationLevel::O2
										: llvm::OptimizationLevel::O3;
			}
			// First add default O3 pipeline
			llvm::ModulePassManager defaultPM = pb.buildPerModuleDefaultPipeline(iter_optlevel);
			mpm.addPass(std::move(defaultPM));

			// Then add early-cse and instcombine in order, like rv32emu
			llvm::FunctionPassManager fpm;
			bool UseMemSSA = true;
			fpm.addPass(llvm::EarlyCSEPass(UseMemSSA));
			fpm.addPass(llvm::InstCombinePass());
			mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(fpm)));
		} else {
			// If no llvmopt, just use default pipeline
			mpm = pb.buildPerModuleDefaultPipeline(optlevel);
		}
		mpm.run(cmodule, mam);
		if (dbt::config::aot_log_expand)
			fprintf(stderr, "EXPAND_ITER %d expansions=%lu heavy=%d\n", i,
				dbt::config::intrin_expand_count, heavy ? 1 : 0);
		if (dbt::config::aot_log_irsize) {
			// Round-54-fix: module instruction count = the IR-delta convergence signal for the K detector.
			unsigned long ninsn = 0;
			for (auto &fn : cmodule)
				for (auto &bb : fn)
					ninsn += bb.size();
			fprintf(stderr, "IRSIZE_ITER %d insns=%lu heavy=%d\n", i, ninsn, heavy ? 1 : 0);
		}
	}
	// P2E (2026-09-04) -- DEFAULT-OFF STATIC DIAGNOSTIC PROBE. Not a method, not a tuning knob.
	//
	// With --aot-reassoc-probe, append exactly ONE llvm::ReassociatePass over the module's functions
	// here: AFTER every optimize/expand iteration above has completed, and BEFORE codegen. It exists
	// only so that reassociation can be varied as a SINGLE factor against an otherwise identical
	// pipeline, which --aot-pipeline structurally cannot do (it REPLACES the default pipeline; see
	// P2D). Deliberately: the default O3 pipeline is untouched, no existing pass is reordered or
	// removed, and no InstCombine cleanup is added -- so any downstream difference is attributable to
	// this one pass rather than to a re-tuned schedule.
	//
	// With the flag off NOTHING here runs and no pass manager is even constructed, so the emitted
	// object is byte-identical to a build without this code (asserted in P2E section 3).
	if (dbt::config::aot_reassoc_probe) {
		llvm::ModulePassManager reassoc_mpm;
		llvm::FunctionPassManager reassoc_fpm;
		reassoc_fpm.addPass(llvm::ReassociatePass());
		reassoc_mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(reassoc_fpm)));
		reassoc_mpm.run(cmodule, mam);
		fprintf(stderr, "AOT_REASSOC_PROBE applied=1 scope=post_expand_pre_codegen passes=reassociate\n");
	}
	if (dbt::config::aot_log_gbrind_constfold)
		fprintf(stderr, "GBRIND_CONSTFOLD_COUNT=%lu GBRIND_TOTAL_EXPAND_COUNT=%lu\n",
			dbt::config::gbrind_constfold_count, dbt::config::gbrind_total_expand_count);
	if (dbt::config::aot_gbrind_context_replicate)
		fprintf(stderr, "GBRIND_CONTEXT_REPLICATE_SITES=%lu GBRIND_CONTEXT_REPLICATE_CLONES=%lu\n",
			dbt::config::gbrind_context_replicate_sites, dbt::config::gbrind_context_replicate_clones);
	// A-line round 26 Part A (default off, diagnostic only): count SURVIVING dbt_gbrind_site_id
	// tags in the fully-optimized module (after every optimize+expand iteration has run, not just
	// the forced final expansion) -- ground truth is g_gbrind_site_id_next (every logical gbrind
	// site that reached Emit_gbrind's tagging code); a tagged CallInst count LOWER than that
	// ground truth is direct proof that LLVM's own optimizer collapsed multiple logical guest
	// gbrind sites onto fewer final host dispatch instructions. Duplicate ids (same tag appearing
	// >1 time) would indicate cloning, the opposite direction -- reported too, not assumed absent.
	if (dbt::config::aot_log_gbrind_site_identity) {
		std::unordered_map<u32, unsigned> id_counts;
		unsigned long n_tagged_instrs = 0;
		for (auto &fn : cmodule) {
			for (auto &bb : fn) {
				for (auto &insn : bb) {
					auto *ci = llvm::dyn_cast<llvm::CallBase>(&insn);
					if (!ci)
						continue;
					auto *tag = ci->getMetadata("dbt_gbrind_site_id");
					if (!tag)
						continue;
					n_tagged_instrs++;
					auto *cv = llvm::cast<llvm::ConstantAsMetadata>(tag->getOperand(0))->getValue();
					u32 id = (u32)llvm::cast<llvm::ConstantInt>(cv)->getZExtValue();
					id_counts[id]++;
				}
			}
		}
		unsigned long n_distinct_ids = id_counts.size();
		unsigned long n_duplicated_ids = 0;
		for (auto const &[id, cnt] : id_counts)
			if (cnt > 1)
				n_duplicated_ids++;
		fprintf(stderr,
			"GBRIND_SITE_IDENTITY ground_truth_sites=%u tagged_instrs=%lu distinct_surviving_ids=%lu "
			"duplicated_ids=%lu\n",
			dbt::config::g_gbrind_site_id_next, n_tagged_instrs, n_distinct_ids, n_duplicated_ids);
	}
	assert(dbt::config::avoid_ips.empty());
	auto t_phase2 = std::chrono::steady_clock::now();

	// cmodule.print(llvm::errs(), nullptr);
	if (dbt::config::aot_dump_llvm_ir) {
		std::error_code ec;
		llvm::raw_fd_ostream ir_out(dbt::config::aot_dump_llvm_ir, ec, llvm::sys::fs::OF_Text);
		if (ec) {
			fprintf(stderr, "OPAQUE_BOUNDARY_DIAG: cannot open %s for IR dump: %s\n",
				dbt::config::aot_dump_llvm_ir, ec.message().c_str());
		} else {
			cmodule.print(ir_out, nullptr);
			fprintf(stderr, "OPAQUE_BOUNDARY_DIAG: wrote final LLVM IR to %s\n",
				dbt::config::aot_dump_llvm_ir);
		}
	}
	auto obj_path = objprof::GetCachePath(AOT_O_EXTENSION);

	// V-next R3: SHARD-LINK aggregation mode -- this module has NO function bodies (link mode skipped codegen) but the
	// FULL _aot_tab (all admitted gips). Emit the aottab object, then link it with the N shard function-.o into ONE
	// runnable .aot.so (LinkAOTObject appends the shard .o to the ld command when aot_shard_link>0) and write the
	// resolved aottab (each gip's _aot_<gip> resolves to its definition in some shard .o).
	if (dbt::config::aot_shard_link > 0) {
		AddAOTTabSection(cmodule, aot_symbols);
		GenerateObjectFile(&cmodule, obj_path);
		log_aot("Shard-link: aottab object with %zu syms -> %s; linking %d shard .o into .aot.so",
			aot_symbols.size(), obj_path.c_str(), dbt::config::aot_shard_link);
		LinkAOTObject(aot_symbols);
		return;
	}

	// V-next Phase 2B: SHARD-COMPILE mode -- functions-only .o (NO aottab, to avoid duplicate _aot_tab at link),
	// shard-suffixed, no link. The aottab + link happen in the separate --aot-shard-link aggregation invocation.
	if (dbt::config::aot_shard_mod > 1) {
		obj_path += "." + std::to_string(dbt::config::aot_shard_idx) + "of" +
			    std::to_string(dbt::config::aot_shard_mod);
		log_aot("Sharded compile shard %d/%d: %zu defined funcs -> %s (functions-only, no aottab, no link)",
			dbt::config::aot_shard_idx, dbt::config::aot_shard_mod, aot_symbols.size(), obj_path.c_str());
		GenerateObjectFile(&cmodule, obj_path);
		return;
	}

	// SERIAL (default): aottab + functions in one module/.o, link to .so.
	AddAOTTabSection(cmodule, aot_symbols);
	// log_aot("Generating object file: %s", obj_path.c_str());
	GenerateObjectFile(&cmodule, obj_path);
	// ProcessLLVMStackmaps(aot_symbols);
	log_aot("Number of symbols: %zu", aot_symbols.size());
	LinkAOTObject(aot_symbols);
	if (dbt::config::aot_log_phase_timing) {
		auto t_phase3 = std::chrono::steady_clock::now();
		auto ms = [](auto a, auto b) {
			return std::chrono::duration<double, std::milli>(b - a).count();
		};
		fprintf(stderr,
			"AOT_PHASE_TIMING region_qir_llvmir_ms=%.3f optimize_expand_ms=%.3f "
			"objemit_link_ms=%.3f\n",
			ms(t_phase0, t_phase1), ms(t_phase1, t_phase2), ms(t_phase2, t_phase3));
	}
}

} // namespace dbt
