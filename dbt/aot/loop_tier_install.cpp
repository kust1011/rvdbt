// T5d2b2: INSTALL the loop tier's own validated artifact, at the EXACT header this run built for.
//
// THE WHOLE OF THIS CHECKPOINT, and its boundary, in one sentence: the parent turns the ONE table
// entry naming its own spawn header into an AOT `TBlock` and replaces that exact guest ip in the
// translation cache, and then stops -- entering it is `Execute()`'s existing direct-edge arm, which
// is not modified and is not called from here.
//
// WHY THIS IS ITS OWN TRANSLATION UNIT, for the same reason `loop_tier_load.cpp` is. `BootAOTFile`
// and `BootOneArtifact` promote WHOLE ARTIFACTS -- every symbol the table carries -- so "install
// exactly ONE header" cannot be expressed by calling either of them with a flag. Keeping it in a
// file of its own makes the difference checkable by reading one file's symbols: audit gate T12 fails
// if this TU names `CacheBr`, `CacheBrind`, `CacheExecCountOnly`, `RelinkTo`, `RevokeTarget`,
// `ICUnpatchTarget`, `trampoline_to_jit`, either L1 dispatch array, or any `Boot*` entry point, and
// it fails if the entry it installs is chosen by anything other than an exact comparison against the
// view's own `spawn_gip`. What differs between this file and the whole-artifact promoters is WHICH
// ips are promoted -- one, by exact match -- and nothing else.
//
// ================================================================================================
// C5d: WHY THE PROMOTION IS THE SHARED ONE, AND WHAT THAT REPLACES.
//
// T5d2b2 shipped this installer with `tcache::InsertOrReplace` and deliberately nothing else, on an
// argument written here in full and repeated in the option's own help text: the escape that
// delivered the service carries its own `BranchSlot *` to `Execute()`, so the fresh lookup a few
// instructions later returns the block installed here and the ordinary link path enters the
// artifact -- and a global relink "would make it impossible to say WHICH mechanism produced the
// entry", which was that checkpoint's only claim. Stale direct links into the old QCG code were
// accepted as "correct, and merely lower-tier".
//
// THAT ARGUMENT IS TRUE ABOUT THE FIRST ENTRY AND FALSE ABOUT EVERY LATER ONE, and the difference is
// measured rather than argued:
//
//   * T5g, 40 trials: in 35 of them the installed artifact was entered EXACTLY ONCE. The one edge
//     `Execute()` happened to be holding was linked; every other predecessor kept its pre-promotion
//     target, so the loop went back to QCG and stayed there.
//   * C5C, on the integer dependency chain at both widths: at the instant of the install the
//     header's `link_map` fan-in was non-empty and its single slot pointed at the pre-promotion QCG
//     code (`link_slots=1 link_to_old_qcg=1`, agreed by an independent code-pool classifier).
//
// So this file now performs the SAME promotion `BootOneArtifact` has performed since Round-18,
// through the SAME function -- `tcache::PromoteTarget` -- applied to one guest ip instead of to a
// whole table. There is no second copy of the wiring to drift, and no configuration in which this
// installer does a partial promotion.
//
// WHAT IS GIVEN UP, stated rather than glossed: T5d2b2's attribution property. With the direct
// edges migrated at the install, "which mechanism produced the entry" is no longer readable off a
// later run, because the answer is now "the promotion did". The published T5e/T5f/T5g/T5h campaigns
// keep their meaning -- they are pinned to their own commits, and their evidence is preserved -- but
// a NEW run of this tier cannot reproduce that particular attribution. That is the deliberate
// trade: the attribution was the T5d2b2 checkpoint's claim, and the bypass it left behind is the
// C5 blocker the checklist now names.
//
// WHAT IS DELIBERATELY NOT COPIED FROM THE HISTORICAL IN-RUN TIER. No timer, no poll cadence, no
// artifact sequence or rung index, no escalation, no skip-ahead, no mtime bookkeeping, no second
// hotness notion, no workload-specific policy, and no admission decision of any kind. The path is
// exactly:
//
//     builder exit -> exact reap -> PUBLISHED -> load+validate -> LOADED -> this installer
//                  -> INSTALLED -> Execute()'s own lookup and link
//
// entered only from the T5d2b1 host-stack in-run disposition, never from a signal handler, never
// from generated code, and never from the child.

#include "dbt/aot/aot.h"
#include "dbt/aot/loop_tier.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/tcache/tcache.h"

namespace dbt::looptier
{

// The one installed block, and the only way out of this file. Filled exactly once by a successful
// `InstallLoadedArtifact`; `InstalledBlock` returns nullptr until then, so no caller can observe a
// half-established install.
static TBlock *g_block = nullptr;
static bool g_installed = false;

TBlock const *InstalledBlock()
{
	return g_installed ? g_block : nullptr;
}

void ReleaseInstalledBlock()
{
	g_block = nullptr;
	g_installed = false;
}

// THE INSTALL, and every step of it is a runtime refusal with its own stable reason. There is no
// assert here and nothing is taken on the loader's word: the view is const and validated, but
// "validated" is a property established by another translation unit, and the two facts this one
// depends on -- that the spawn header really is in the table, and that its host address is usable --
// are cheap enough to re-establish that assuming them would be a choice rather than a saving.
//
// `*why` always receives one of the reason strings below, including on success ("ok").
bool InstallLoadedArtifact(char const **why)
{
	char const *sink = "";
	if (!why)
		why = &sink;
	*why = "ok";

	// 1. THE MODE. Default off means the process behaves exactly as T5d2b1's did, and the first
	//    statement is what makes that true rather than the call site's discipline.
	if (!config::loop_tier_install) {
		*why = "install_disabled";
		return false;
	}
	// 2. ONE INSTALL. Not a convention: the tier's state machine has no path back to LOADED, but
	//    "installed once" is a property of THIS primitive and is stated here so a second call is
	//    refused by the code rather than by the caller's structure.
	if (g_installed) {
		*why = "already_installed";
		return false;
	}
	// 3. LOADED, AND NOTHING ELSE. PUBLISHED means a file exists; ARMED, BUILDING, FAILED and
	//    ABSTAINED have no artifact at all. Only LOADED means this process mapped one and proved it
	//    is the one it meant, which is the only state in which `base + aot_vaddr` is a host address
	//    this run may hand to the trampoline.
	if (config::loop_tier_state != (int)State::LOADED) {
		*why = "not_loaded";
		return false;
	}
	// 4. AND THE VIEW IS REALLY THERE. The state and the view are two facts; a state moved by hand
	//    would otherwise let a null view through.
	auto const *view = LoadedArtifactView();
	if (!view || !view->tab || !view->base) {
		*why = "no_validated_view";
		return false;
	}

	// 5. THE EXACT ENTRY, FOUND BY AN EXACT COMPARISON. `spawn_gip` is the header this run's own
	//    notification named and its own child compiled; the artifact may legitimately carry others,
	//    and none of them is installed. Table ORDER decides nothing here -- the entry is selected by
	//    its gip, and the loader has already refused any artifact with a duplicate one.
	AOTSymbol const *sym = nullptr;
	for (u64 k = 0; k < view->n_sym; ++k) {
		if (view->tab->sym[k].gip == view->spawn_gip) {
			sym = &view->tab->sym[k];
			break;
		}
	}
	if (!sym) {
		// Unreachable through the loader, which refuses `spawn_header_absent` before it establishes
		// a view. Kept because this function's precondition is the VIEW, and a precondition that is
		// only true because of another file's internals is not one this file has checked.
		*why = "spawn_entry_absent";
		return false;
	}
	if (sym->aot_vaddr == 0) {
		*why = "no_host_entry";
		return false;
	}

	// 6. THE PROMOTION BOUNDARY, READ BEFORE THE MUTATION.
	//
	// `region_entry_hits` is written ONLY by LLVM-compiled artifact code (llvmgen.cpp, under
	// --aot-region-hit-count), so its value at this instant is the before-picture and must be zero
	// in a run whose only artifact is the one being installed now. The QCG census is read here too,
	// and here rather than at exit, because at exit the block installed below would be in it: what
	// this records is what the run had achieved on QCG alone, up to the instruction before the
	// install. Both are READS -- `TierCensus` walks the map and sums, and mutates nothing.
	{
		unsigned long census[4] = {0, 0, 0, 0};
		tcache::TierCensus(census);
		config::loop_tier_install_qcg_tbs = census[0];
		config::loop_tier_install_qcg_mass = census[2];
		unsigned long long hits = 0;
		if (auto *st = CPUState::Current()) {
			for (unsigned i = 0; i < CPUState::REGION_HIT_SLOTS; ++i)
				hits += st->region_entry_hits[i];
			config::loop_tier_install_at_ip = st->ip;
		}
		config::loop_tier_install_aot_hits = hits;
	}

	// C5c PROMOTION-ROUTE CENSUS, HERE AND NOT ONE LINE LATER. This is the last instant at which
	// the header's pre-promotion routing is still observable: the next statement replaces the map
	// entry, and from then on the block this census is describing is unreachable from any index.
	// It is a pure read (see dbt/aot/loop_tier_route_census.cpp) and it returns on its first
	// statement unless `--loop-tier-route-census` was asked for, so the default path through this
	// function is unchanged. It is placed after the reads above and before the mutation below, in
	// the block whose whole purpose is already "read before the mutation".
	RouteCensusEmit("pre_install", view->spawn_gip);

	// 7. THE INSTALL ITSELF: one block, one ip, one replace.
	//
	// `tcode.size == 0` is what makes this an AOT block everywhere in the process that asks -- the
	// tier census, the code-size census and the escape classifier all read it, and an announce-created
	// block is exactly this shape (`BootAOTFile`, `BootOneArtifact`). The code lives in the artifact,
	// not in this process's code pool, so there are no bytes to own here.
	auto *tb = tcache::AllocateTBlock();
	if (tb == nullptr) {
		*why = "no_tblock";
		return false;
	}
	tb->ip = view->spawn_gip;
	tb->tcode = TBlock::TCode{(void *)(view->base + sym->aot_vaddr), 0};
	// PROMOTE, NOT MERELY REPLACE -- ONE IP, THROUGH THE ONE SHARED PRIMITIVE.
	//
	// `tcache::PromoteTarget` is the wiring `BootOneArtifact` has performed since Round-18, and it
	// is called here rather than re-spelled: the map and L1 block cache (so a fresh lookup resolves
	// here), the exec-count cache, the indirect-dispatch L1 (a RAW pointer the generated fast path
	// jumps to without consulting any TBlock), every already-self-patched direct slot naming this
	// ip, and every inline-cache blob patched at it. Each of those is a way control can still reach
	// the pre-promotion code; leaving any of them is the bypass T5g measured.
	//
	// SCOPE IS STILL EXACTLY ONE GUEST IP. `PromoteTarget` takes a block, not a table, and this file
	// hands it the one block built from the one entry whose gip equals `view->spawn_gip`. The other
	// symbols the artifact may carry are untouched, which is the property gate T12 checks by reading
	// the table walk above rather than by trusting this sentence.
	//
	// THIS IS THE LAST STATEMENT THAT CAN FAIL-CLOSED. Every refusal above returns before any
	// structure is touched; from here the promotion is a sequence of unconditional writes with the
	// guest paused, so there is no half-installed state for a caller to observe.
	auto const promoted = tcache::PromoteTarget(tb);
	config::loop_tier_install_relinked = promoted.relinked;
	config::loop_tier_install_ic_unpatched = promoted.ic_unpatched;
	config::loop_tier_install_brind_was_target = promoted.brind_was_target;

	// 2026-09-17 diagnostic capture (free when --dump-fault-state is off, because nothing reads
	// it): the guest register file AT THE INSTALL INSTANT, so a later fault dump can show what
	// changed across the AOT entry instead of offering one snapshot with nothing to compare to.
	if (auto *st = CPUState::Current()) {
		for (unsigned i = 0; i < CPUState::gpr_num; ++i)
			config::loop_tier_install_gpr[i] = st->gpr[i];
		config::loop_tier_install_ip_at_capture = st->ip;
		config::loop_tier_install_gpr_valid = true;
	}

	g_block = tb;
	g_installed = true;
	config::loop_tier_installed_gip = tb->ip;
	config::loop_tier_install_host = (unsigned long long)(uptr)tb->tcode.ptr;
	return true;
}

} // namespace dbt::looptier
