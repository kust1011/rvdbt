#pragma once

// T5d2a: the loop tier -- build T5d1b's loop-rooted artifact during the run that earned it.
//
// Everything in this header is either a PURE FUNCTION of its arguments or a host-stack action with
// an explicit precondition. That split is deliberate: the state machine, the admission comparison,
// the child's argument vector, the artifact gate and the publish step are each testable without a
// guest, a compiler, a clock or a second CPU, so `loop_tier_test.cpp` drives exactly the code the
// run drives instead of a re-implementation of it.
//
// See dbt/config.h's T5d2a block for what this path deliberately does NOT share with the existing
// single-run/BCT tier.

#include "dbt/aot/aot.h"
#include "dbt/util/common.h"

#include <cstddef>
#include <string>
#include <vector>

extern "C" {
#include <sched.h>
#include <sys/types.h>
}

namespace dbt
{
struct TBlock; // T5d2b2: the installed block is reported by pointer; its layout is tcache.h's
} // namespace dbt

namespace dbt::looptier
{

// The build's life. There is no path back into ARMED from any terminal state, which is what "one
// allowed build" means mechanically rather than by convention -- and, since T5d2a2, what the
// EMITTED notification tests before it stores anything: a tier that is not ARMED is silent in the
// generated code as well as in this file.
enum class State : int {
	OFF = 0,	// the mode was never armed
	ARMED = 1,	// waiting for evidence; the one-shot is intact
	BUILDING = 2,	// the child exists; the one-shot is spent
	PUBLISHED = 3,	// the child published an artifact carrying >=1 selected loop header
	FAILED = 4,	// the child exited without publishing (bad rc, missing or empty artifact)
	ABSTAINED = 5,	// no distinct allowed CPU: reported, and no build attempted
	// T5d2b1. A SEPARATE STATE, and the distinction is the checkpoint. PUBLISHED means a FILE
	// exists at the published path -- the parent stat'ed it and read its size. LOADED means this
	// process dlopen'd that exact file, passed the shared CPUState-ABI and RVV-VLEN gate, and
	// validated the table it carries down to the entry that names the header this run spent its
	// build on. Neither means anything was installed, relinked or entered: no TBlock exists for a
	// LOADED artifact and no branch points at it. That is the next checkpoint.
	LOADED = 6,
	// T5d2b2. AGAIN A SEPARATE STATE, for the same reason LOADED is separate from PUBLISHED.
	// INSTALLED means the ONE table entry naming this run's own spawn header has been turned into
	// an AOT TBlock and has REPLACED that exact guest ip in the translation cache -- so the next
	// `tcache::Lookup` of that header resolves into the artifact. It does not by itself mean the
	// artifact ran: entering it is the ordinary business of `Execute()`'s own direct-edge arm, and
	// the evidence for it is the artifact's own region-entry counter, not this state.
	INSTALLED = 7,
	// 2026-09-17. The builder was still running at guest exit and this run cancelled it, because an
	// artifact that lands after the guest has stopped can never be installed (installs are in-run
	// only) and waiting for it charges cold elapsed for nothing. CANCELED is deliberately NOT
	// FAILED: nothing about the compilation was wrong, and it is deliberately NOT PUBLISHED even
	// when the child managed to rename the artifact first -- see loop_tier_stale_publication.
	CANCELED = 8,
};

// What a single notification should do. Note what is NOT a parameter: a time, a tick index, a
// cadence, or how many notifications have already arrived.
enum class Action : int {
	NOTHING, // the mode is off, or the state is terminal
	REJECT,	 // the target is not a selected hot loop header -- the BUILD is NOT spent
	SPAWN,	 // it is -- take the one allowed build
	REAP,	 // a child exists; collect its disposition
};

// THE DECISION, in full. `target_is_selected_header` is the answer T5d1a's own selector gave for
// the guest block whose counter raised the notification; nothing else is consulted, and there is no
// second notion of hotness here to disagree with it.
Action Decide(State st, bool enabled, bool target_is_selected_header);

// The evidence half of the emitted notification, as a function, so what the run tests and what the
// test tests are the same rule. `count` is the counter's value AFTER the increment.
//
// REACHED OR PASSED, not "equals" (T5d2a2). `exec_count` is shared with every other incoming path,
// so an exact equality can be consumed by an arrival the backward edge never runs on, and the edge
// then never sees the value at all. The one-shot that equality provided is provided instead by
// `notified` below, which is a fact about the guest TARGET.
bool CrossedBar(u64 count, u64 bar);

// THE WHOLE EMITTED PREDICATE, as one function: the conjunction the generated code implements with
// four compares. Stating it here is what lets the rule be driven directly by a test at every
// interesting point (below/at/above the bar, each tier state, mailbox free/occupied, notified or
// not) while the emitted-byte test proves the generated form is this conjunction and not another.
//
//   count   -- the target's exec_count after the increment this edge just performed
//   bar     -- config::sr_chunk_threshold, the compiler's own admission number
//   state   -- config::loop_tier_state; only ARMED can still use a notification
//   mailbox -- config::loop_tier_event_ip; 0 means free
//   notified-- this guest target's durable one-shot byte
bool ShouldNotify(u64 count, u64 bar, int state, u32 mailbox, unsigned char notified);

// A CPU from `allowed` that is not `guest_cpu`, or -1 if there is none. Split out of the
// getaffinity call so the "mask contains only the guest's CPU" case can be constructed in a test
// instead of waited for on a machine that happens to have one core free.
int SelectDistinctCpu(cpu_set_t const *allowed, int guest_cpu);

// This process's answer to the same question. -1 also when sched_getaffinity itself fails: an
// asynchronous builder that cannot be placed must not be started.
int PickBuilderCpu();

// Every selected loop header the artifact actually carries: `.aottab`'s gips, each confirmed to
// have a defined `_x<gip>` symbol at the address the table records. Reads a whole .so image out of
// memory and ALLOCATES NOTHING, so the same function serves the forked child (which must not touch
// the malloc arena it inherited) and the test (which builds its input by hand).
//
// Returns how many gips were written to `out`, which may be 0 for a real artifact that selected
// nothing, or -1 for an image that could not be parsed, that does not fit `max`, or whose table
// names a header the artifact does not define. Zero and -1 are both unpublishable, and they are
// kept distinct so a corrupt artifact is not reported as an empty selection.
long ArtifactLoopHeaders(void const *buf, size_t n, u32 *out, size_t max);

// The same walk, projecting the WHOLE `AOTSymbol` rather than just the gip. T5d2b1's loader compares
// the mapped `_aot_tab` against the validated file bytes field by field: an entry that names the
// same guest ip at a different host address is a different artifact, and comparing gips alone would
// admit it. Allocation-free, like every other reader here, so the same code can serve the forked
// publish gate.
long ArtifactLoopSymbols(void const *buf, size_t n, AOTSymbol *out, size_t max);

// One executable PT_LOAD segment's virtual-address range.
struct ExecRange {
	u64 vaddr;
	u64 memsz;
};

// The artifact's executable PT_LOAD ranges, read from its own program header table. Returns how many
// were written, or -1 for a malformed/oversized table; 0 means the object declares no executable
// segment at all, which makes every non-zero entry address refusable. A virtual address is bounded
// by these, NOT by the file's byte length -- the two are unrelated, and using the latter was simply
// the wrong test.
long ArtifactExecRanges(void const *buf, size_t n, ExecRange *out, size_t max);

// The name `QIRToLLVM` gives a region rooted at `ip` -- MakeAotSymbol's spelling, produced without
// a std::stringstream so it is usable after a fork. The test pins the two against each other.
void AotSymbolName(u32 ip, char *out, size_t n);

// Run the EXACT T5d1a selector -- whole-profile stitched graph, real dominator tree, natural loops
// by dominance -- over the live profile at `bar`, and report the selected hot loop-header set.
//
// `bar` is installed into `config::threshold` for the duration of the call and restored, because
// that is the field `ComputeNaturalLoopCandidates` reads when it decides `hot`. Passing the loop
// tier's own bar there is what makes this the same admission the child will apply, rather than a
// second, private one.
//
// Returns false, having touched nothing, if the graph cannot support a dominator tree (too large,
// or not fully reachable). That is a refusal and not a Panic: this runs inside a live guest, and
// killing a correct run to report an analysis limit is not an option. Fail-closed either way -- a
// refusal yields no headers, and no headers means no build.
bool SelectedLoopHeaders(u64 bar, std::vector<u32> *headers, u64 *header_freq_of, u32 target);

// The publish gate, fail-closed on both inputs: a failed compile and an artifact with no selected
// loop header are the same answer.
bool MayPublish(int build_rc, size_t n_headers);

// rename(2) `src` onto `dst`. Both must live in the same directory, which is what makes the step
// atomic: an observer polling `dst` sees either nothing or the complete artifact, never the
// partially-written file the compiler was producing.
bool PublishAtomically(char const *src, char const *dst);

// Byte-identical host-stack snapshot of a stopped regular-file profile. Preserve sparse extents
// where the filesystem reports them; otherwise retain the dense-copy correctness fallback.
bool CopyProfileSnapshot(char const *src, char const *dst);

// Fork the builder: pin it to `cpu`, run `elfaot` over the profile already staged in `stage`, and
// publish `<stage>/<publish>` -- atomically, and only if that compile succeeded and produced an
// artifact carrying at least one selected loop header. Returns the child's pid, or -1.
//
// `cpu` is the CALLER's decision, because refusing to build at all when there is no distinct CPU is
// a decision about the run and not about the child; `Service` makes it and abstains, and the child
// then fails closed if the pin it was handed cannot be applied.
//
// The parent's live `--vlen` and the whole rendered RVV route contract are assembled at the execv
// site inside this function, before the fork, and written to `<stage>/loop_tier_build.cmd` from the
// same array execv receives -- so the argument vector is constructed exactly once and the run's own
// evidence records it. scripts/vlen_propagation_audit.py reads that site.
pid_t SpawnBuilder(int cpu, char const *loop_tier_elfaot, char const *elf, char const *stage,
		   char const *artifact, char const *publish, u64 bar);

// ---------------------------------------------------------------------------------------------
// The host-stack actions. Preconditions, not conventions: `Service` walks the profile, copies a
// file and may fork, none of which is safe in a signal handler.

// Consume one service opportunity. Called ONLY from Execute()'s loop.
void Service();

// Arm the tier. Returns false, having said why on stderr, when the configuration cannot support
// it; the caller must then refuse to run rather than proceed with a tier that can never fire.
bool Arm();

// Report the final disposition after the guest has stopped. Collects a still-running child, which
// is legal here for the same reason: the guest has already finished, so nothing it waits for can
// be charged to guest execution.
void ReportAtExit();

// ---------------------------------------------------------------------------------------------
// T5d2b0. The child-completion notification, exposed so `loop_tier_test` can drive the REAL install,
// the REAL handler (through a REAL child's termination) and the REAL restore, rather than a copy.
//
// `InstallCompletionNotification` returns false when SIGCHLD is already owned by another consumer;
// `Arm()` turns that into a refusal. `RestoreCompletionNotification` puts the saved disposition
// back and is a no-op when nothing was installed. Neither reaps, decides or logs: the completion is
// consumed, and the child collected, by `Service()` on the host stack.
// `InstallCompletionNotification` takes SIGCHLD for the interval in which a builder is outstanding
// -- the run takes it immediately BEFORE the fork and gives it back the instant the exact builder is
// consumed, because SIGCHLD is process-wide and holding it while no builder exists means an
// unrelated host child's exit raises this tier's completion. It returns false if the tier already
// holds it or if the current disposition is not one it may take.
//
// `CompletionDispositionAcceptable` is that admission test on its own, so `Arm()` can refuse a
// configuration before the guest runs and a test can drive every disposition. Only SIG_DFL without
// SA_NOCLDWAIT is acceptable: SIG_IGN and SA_NOCLDWAIT let the kernel auto-reap children, which
// would make the exact `waitpid` return ECHILD, and an installed handler belongs to someone else.
// `*why` receives a stable reason string; it is the same string `Arm()` prints.
//
// `RestoreCompletionNotification` puts the saved disposition back, clears any completion reason left
// behind by the window it closes, and is idempotent -- a no-op when nothing is held, which is every
// ordinary run. `CompletionNotificationHeld` reports whether the tier currently owns SIGCHLD.
// ---------------------------------------------------------------------------------------------
// T5d2b1: the loaded, validated artifact view.
//
// IMMUTABLE AND VALIDATED, OR ABSENT. `LoadedArtifactView` returns nullptr until a load has
// succeeded in full, so a caller cannot reach an unvalidated pointer; after that it returns the
// same const view for the life of the load. Nothing in this struct is a promotion: a base address
// and a bounded table are what a future installer will READ, and this checkpoint hands them to
// nobody.
//
// LIFETIME. From the successful `LoadAndValidateArtifact` to `ReleaseLoadedArtifact`, which the run
// performs once, after its final report. Every failure path inside the loader closes the handle
// before returning, so a refused artifact leaks nothing and leaves no view behind.
struct LoadedArtifact {
	void *handle{nullptr};	       // dlopen handle, owned by this view
	u8 const *base{nullptr};       // link_map l_addr: where the object was mapped
	AOTTabHeader const *tab{nullptr}; // the artifact's own table, validated against its file bytes
	u64 n_sym{0};		       // entries, equal to the count the file's section headers bound
	u32 spawn_gip{0};	       // the header this run spent its build on; proven present
	char const *path{nullptr};     // the exact PublishPath() this run renamed onto
};

// Load `path` and validate it, or refuse. Returns nullptr on ANY failure, having closed whatever it
// opened; `*why` receives a stable reason string ("ok" on success). `path` must be exactly
// `PublishPath()` and `spawn_gip` must be present in the artifact's table -- both are checked, not
// assumed. Host stack only: it reads a file, dlopens and dlsyms, none of which is legal in a signal
// handler, in generated code, or in the forked child.
LoadedArtifact const *LoadAndValidateArtifact(char const *path, u32 spawn_gip, char const **why);
LoadedArtifact const *LoadedArtifactView();
void ReleaseLoadedArtifact();

// ---------------------------------------------------------------------------------------------
// T5d2b2: the install, and its boundary.
//
// ONE ENTRY, THE EXACT ONE. `InstallLoadedArtifact` reads the LOADED view, finds the single table
// entry whose `gip` is the header this run spent its build on, and replaces THAT guest ip in the
// translation cache with an AOT block pointing at `base + aot_vaddr`. Every other symbol the
// artifact carries is left uninstalled -- an artifact-wide promotion is what `BootOneArtifact`
// does, and it would make it impossible to say which header produced an entry.
//
// PRECONDITIONS, CHECKED RATHER THAN ASSUMED, each with its own stable reason in `*why`: the mode
// is on, no install has happened yet, the tier is in LOADED (not PUBLISHED, not ARMED, not FAILED),
// a validated view exists, and it really carries the spawn header at a usable host address. Any
// failure returns false having changed NOTHING -- there is no partially installed state.
//
// WHAT IT DOES NOT DO. No `RelinkTo`, no `CacheBr`, no `CacheBrind`, no `RevokeTarget`, no entry
// into compiled code. Linking the escape's own slot and entering through the trampoline is
// `Execute()`'s existing direct-edge arm, unmodified; this function only makes the lookup that arm
// already performs resolve to the artifact. Audit gate T12 checks that against this file's symbols.
//
// Host stack only, from the in-run LOADED disposition: it allocates and mutates the translation
// cache, none of which is legal in a signal handler, in generated code, or in the forked child.
bool InstallLoadedArtifact(char const **why);

// The block this run installed, or nullptr before/after. Exposed so the run's own report and the
// test read the SAME object rather than two reconstructions of it.
TBlock const *InstalledBlock();

// Clear the installer's one-shot record. Mirrors `ReleaseLoadedArtifact`: the run performs it once,
// after its final report. It does NOT remove the block from the translation cache -- the cache and
// its arena belong to the process and are torn down with it.
void ReleaseInstalledBlock();

// ================================================================================================
// C5c PROMOTION-ROUTE CENSUS (--loop-tier-route-census, default off). See dbt/config.h for why it
// exists; this is its only entry point and `dbt/aot/loop_tier_route_census.cpp` is its only
// definition.
//
// PURE READ, AND STRUCTURALLY SO. It calls exactly one thing that touches the translation cache --
// `tcache::RouteCensus`, which is a const walk of that class's own indexes -- and one thing that
// reads the map without warming the L1 block cache, `tcache::PeekBlock`. It names no linking,
// caching, revoking, installing or entering entry point, which audit gate T14 checks by reading
// this file's symbols rather than by trusting this comment.
//
// TWO SAMPLES, AND THE FIRST ONE LATCHES. `when == "pre_install"` is taken from the installer's
// existing pre-mutation read block, so it sees the header's QCG block still in the map; it records
// that block's `tcode.ptr` so the `guest_exit` sample can say whether a slot STILL points at the
// pre-promotion code. Without the latch the second sample could only say "not the artifact", which
// is exactly the distinction C5B's premise turns on. `ResetRouteCensus()` clears the latch; it
// exists for the test, and the run never calls it.
void RouteCensusEmit(char const *when, u32 gip);
void ResetRouteCensus();

bool InstallCompletionNotification();
bool CompletionDispositionAcceptable(char const **why);
void RestoreCompletionNotification();
bool CompletionNotificationHeld();

// The publication's absolute path, derived from `loop_tier_stage` and the active VLEN. `Arm()`
// establishes it; `PublishPath()` reports it. Exposed so the disposition can be driven by a test
// against a real file, and so the run's evidence and the code agree on one spelling of the name.
void SetPublishPath();
char const *PublishPath();

} // namespace dbt::looptier
