#pragma once

#include "dbt/aot/aot_module.h"
#include "dbt/qmc/compile.h"
#include "dbt/tcache/objprof.h"

#include <sstream>

namespace dbt
{

void AOTCompileELF();
void LLVMAOTCompileELF();
// S3.7: the RVV direct-route contract's argv renderer, declared here so that a spawn site outside
// aot_boot.cpp can use the ONE table without copying it. The table itself does not move -- see
// kRvvRouteContract in aot_boot.cpp for why a route flag is added there and nowhere else, and
// scripts/vlen_propagation_audit.py for the check that every reachable elfaot execution renders it.
// `kRvvRouteArgMax` is an upper bound on the table's length, static_asserted against the real one at
// the definition, so a caller can size its buffers without seeing the rows.
// ORDER ITEM 4 (2026-09-19): raised 40 -> 48, then 48 -> 64. Both raises were forced by the
// static_assert at the table's definition firing on the build that added the row past the bound,
// which is the whole point of the bound existing -- the failure mode it prevents is a spawn site
// rendering the contract into a buffer one row too small. Raised with headroom rather than to the
// exact count so the next few rows do not each need a build cycle to discover it. The assert
// still fails closed if the table grows past this bound.
inline constexpr size_t kRvvRouteArgMax = 80;
// T5f: WHERE THE CHILD'S VALUE FOR A LOWERING-SUBSTRATE ROW COMES FROM. Route-policy and
// diagnostic rows ignore this entirely: they are the parent's live value at every site, as S3.7
// established. Exactly one row is not policy -- `--rvv-vector-ssa` -- and it is the parameter's
// whole subject; see kRvvRouteContract's T5f block in aot_boot.cpp for why one live boolean was
// spelling two different backends' representation choices.
enum class RvvChildSubstrate {
	// Render the parent's live `config::rvv_vector_ssa`. Correct wherever the parent is FREE to
	// choose that value: an operator who wants a vector-lowered child artifact passes
	// `--rvv-vector-ssa 1` to elfrun and inheritance delivers it.
	InheritParent,
	// Render the LLVM backend's own prerequisite (1), independently of the parent's value.
	// Required wherever the parent is STRUCTURALLY BARRED from carrying it -- the loop tier, whose
	// Arm() refuses `--loop-tier-side-exit` under `rvv_vector_ssa` (the QCG-side legality
	// precondition `side_exit_needs_committed_vector_state`). There, inheritance can only ever
	// deliver 0, and 0 is the one value at which no elfaot typed route can be taken.
	LlvmPrerequisite,
};
size_t RvvRouteArgv(char slots[kRvvRouteArgMax][64], char const *out[kRvvRouteArgMax],
		    RvvChildSubstrate substrate);
void BootAOTFile();
bool BootAOTFileInRun(); // Round-17 BCT: mid-run promotion (tolerates missing artifact)
void EvaluateAndMaybeEscalate(); // 2026-07-05 in-process closed-loop escalation (host stack only)
void P1ScanAndMaybePromote(); // P1 2026-07-23: exiled-hot scan + one-shot synchronous mid-run promote (host stack only)
long BootReuseArtifact(char const *path); // 2026-06-19 AARS: boot another binary's .aot.so by gip (cross-program reuse)

static constexpr char const *AOT_O_EXTENSION = ".aot.o";
static constexpr char const *AOT_SO_EXTENSION = ".aot.so";
static constexpr char const *AOT_SYM_AOTTAB = "_aot_tab";
// CPUState layout signature embedded in every artifact this build produces. Checked at load:
// the cache path is keyed only by the guest ELF checksum, so without this an artifact built
// against a different CPUState layout (e.g. before RVV added VectorState) would be loaded with
// stale baked-in field offsets. Artifacts that predate this symbol are refused for the same
// reason -- absence proves nothing about their layout.
static constexpr char const *AOT_SYM_ABI = "_aot_cpustate_abi";
// X4g2: the RVV VLEN this artifact was SPECIALIZED for, in bits. Kept as a symbol of its own
// rather than mixed into AOT_SYM_ABI so that a CPUState layout change and a VLEN change stay
// independently diagnosable at load. Necessary because the cache path is keyed only by the guest
// ELF checksum: a build at one VLEN and a run at another meet at the same path, and every other
// gate is structurally blind to it (CPUStateAbiSignature covers the compile-time VLEN_MAX_BYTES
// layout, not the runtime width). Artifacts predating this symbol are refused for the same reason
// AOT_SYM_ABI refuses its own predecessors: absence proves nothing about what they assumed.
// Emitted by the LLVM producer only; see llvmaot.cpp AddAOTTabSection and the note there.
static constexpr char const *AOT_SYM_VLEN = "_aot_rvv_vlen_bits";

struct AOTSymbol {
	u32 gip;
	u64 aot_vaddr;
	u32 gsize{}; // 2026-06-19 AARS: region guest byte-extent (max ip_end - entry); the byte-identity reuse gate
		     // compares EXACTLY this many bytes -> no over-reach into adjacent excluded regions, no magic window.
};

struct AOTTabHeader {
	u64 n_sym;
	AOTSymbol sym[];
};

// THE IDENTITY GATE EVERY ARTIFACT LOADER IN THIS PROCESS SHARES. Returns true iff `so_handle`'s
// embedded identity matches this process: the CPUState layout signature AND the RVV VLEN the
// artifact was specialized for. Fail-closed on all three outcomes -- match accepts, mismatch
// refuses, and a MISSING symbol refuses too, because an artifact built before a gate existed made
// no promise about the thing that gate checks.
//
// Declared here, and defined once in aot_boot.cpp, for the reason its own comment already gives:
// several entry points dlopen an artifact and all of them must gate the same way. T5d2b1 made it a
// shared declaration rather than adding a fourth copy -- `BootAOTFile`, `BootOneArtifact`,
// `BootReuseArtifact` and `looptier::LoadAndValidateArtifact` now call ONE implementation, so a
// check added here is inherited by all four at once and none of them can drift. Behaviour for the
// three pre-existing callers is unchanged: the function body was not touched, only its linkage.
bool AotAbiCompatible(void *so_handle, char const *what);

ModuleGraph BuildModuleGraph(objprof::PageData const &page);
// T5d1a: the two halves of the per-page build, exposed so that a whole-profile graph can record
// every page's nodes BEFORE any page's edges are analysed. RecordProfilePageNodes declares no entry
// of its own -- only what the profile marks -- and returns the page's executed block ips ascending.
std::vector<u32> RecordProfilePageNodes(ModuleGraph &mg, objprof::PageData const &page);
void AnalyseProfilePageEdges(ModuleGraph &mg, objprof::PageData const &page, std::vector<u32> const &iplist);
// T5d1a: ONE stitched module graph over every profiled executable page -- the CFG view the loop
// selector analyses, so that whether a loop is found does not depend on where the linker put its
// blocks. Region formation and compilation still use BuildModuleGraph per page, unchanged.
ModuleGraph BuildWholeProfileGraph();
// T5d1a (--dump-loop-candidates, default off): dry-run dump of the canonical hot-natural-loop
// candidate set of this profile. Builds the whole-profile graph and its dominator tree only -- forms
// no region, generates no code, marks nothing. The caller exits after it.
void DumpNaturalLoopCandidates();
void LinkAOTObject(std::vector<AOTSymbol> &aot_symbols);

void AOTCompileObject(CompilerRuntime *aotrt);

void ProcessLLVMStackmaps(std::vector<AOTSymbol> &aot_symbols);

} // namespace dbt
