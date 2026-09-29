// T5d2b1: LOAD AND VALIDATE the loop tier's own published artifact, in the run that built it.
//
// THE WHOLE OF THIS CHECKPOINT, and its boundary, in one sentence: the parent maps the artifact it
// just published and proves the mapping is the one it meant, and then stops. Nothing here allocates
// or replaces a TBlock, calls CacheBr/CacheBrind/Insert/InsertOrReplace/RelinkTo/Announce, or
// transfers control into compiled code. Installing what this produces is the NEXT checkpoint.
//
// THAT BOUNDARY IS WHY THIS IS ITS OWN TRANSLATION UNIT. `BootAOTFile` and `BootOneArtifact` load
// and promote in one function -- dlopen, gate, then `AllocateTBlock`/`Insert`/`CacheBr`/
// `CacheBrind`/`RelinkTo` in the same loop -- so "load without promoting" cannot be expressed by
// calling them with a flag. Splitting the primitive out is the only way to make the absence of
// promotion a property of the CODE rather than a claim about a test path, and keeping it in a file
// of its own makes that property checkable by reading one file's symbols: audit gate T11 fails if
// this TU so much as names a tcache mutation entry point.
//
// WHAT IS DELIBERATELY NOT COPIED FROM THE HISTORICAL IN-RUN TIER. No timer, no poll cadence, no
// artifact sequence or rung index, no escalation, no skip-ahead, no mtime bookkeeping, no
// workload-specific policy, and no admission decision of any kind. The path is exactly:
//
//     builder exit -> exact reap -> PUBLISHED -> this loader -> LOADED
//
// entered only from the T5d2b0 host-stack completion/reap path, never from a signal handler, never
// from generated code, and never from the child.

#include "dbt/aot/aot.h"
#include "dbt/aot/loop_tier.h"
#include "dbt/config.h"

#include <cstdio>
#include <cstring>
#include <vector>

extern "C" {
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <sys/stat.h>
#include <unistd.h>
}

namespace dbt::looptier
{

// The one validated view, and the only way out of this file. It is filled exactly once, by a
// successful `LoadAndValidateArtifact`, and is otherwise all zeroes; `LoadedArtifactView` returns
// nullptr until then, so no unvalidated pointer can reach a caller. Its lifetime is stated in
// loop_tier.h: from the successful load to `ReleaseLoadedArtifact`, which the run performs after
// the final report.
static LoadedArtifact g_view;
static bool g_loaded = false;

// A cap on how many entries this loader will consider. Not a policy: it bounds the stack the
// membership check below walks, and an artifact with more entries than this is REFUSED rather than
// truncated, which is the fail-closed answer for something this loader cannot fully inspect.
static constexpr size_t kMaxTableEntries = 4096;

// Read the whole of an ALREADY-OPEN regular file. The fd is the caller's and stays open: what is
// validated and what is mapped must be the same object, and a path re-resolved between the two is
// exactly how they stop being one (see the block comment on the loader below).
static bool SlurpFd(int fd, std::vector<u8> *out)
{
	struct stat st {};
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0)
		return false;
	out->resize((size_t)st.st_size);
	size_t got = 0;
	while (got < out->size()) {
		ssize_t r = pread(fd, out->data() + got, out->size() - got, (off_t)got);
		if (r <= 0)
			return false;
		got += (size_t)r;
	}
	return true;
}

// Is `vaddr` inside one of the object's own executable PT_LOAD ranges? Overflow-safe: `vaddr` is
// compared against each range's start and its end computed without wrapping, because a range whose
// end wraps was already refused by the reader.
static bool InExecRange(u64 vaddr, ExecRange const *r, long n)
{
	for (long i = 0; i < n; ++i)
		if (vaddr >= r[i].vaddr && vaddr - r[i].vaddr < r[i].memsz)
			return true;
	return false;
}

// THE VALIDATION, and every step of it is a runtime refusal with its own stable reason. There is no
// assert here and nothing is taken on the producer's word: this process built the artifact in a
// forked child that could have been killed, disk-full, or racing another writer, and "the file
// exists" is exactly the evidence that does not distinguish those from a good build.
//
// `*why` always receives one of the reason strings below, including on success ("ok"), so a caller
// can report the outcome without a second vocabulary.
LoadedArtifact const *LoadAndValidateArtifact(char const *path, u32 spawn_gip, char const **why)
{
	char const *sink = "";
	if (!why)
		why = &sink;
	*why = "ok";
	if (g_loaded) {
		*why = "already_loaded";
		return nullptr;
	}

	// 1. THE PATH IS THE ONE THIS RUN PUBLISHED. Not "a file with the right name": the exact string
	//    `PublishAtomically` renamed onto, so a loader pointed at some other artifact -- a stale one
	//    in the same directory, a reuse artifact, an operator's copy -- is refused before it is
	//    opened. PublishPath() is derived from the staging directory and the ACTIVE VLEN, so this
	//    also pins the width before the VLEN symbol is even read.
	if (!path || !*path || !PublishPath() || !*PublishPath() || strcmp(path, PublishPath()) != 0) {
		*why = "not_the_published_path";
		return nullptr;
	}

	// 2. ONE OPEN OBJECT, FROM HERE TO THE MAPPING.
	//
	// THIS IS THE DEFECT THIS STEP EXISTS FOR. The first version read the bytes, closed the fd, and
	// then called `dlopen(path)`. A publisher replacing the path between those two moments -- which
	// is precisely what `PublishAtomically`'s own rename(2) does -- left the loader validating one
	// inode and mapping another, and `strcmp(path, PublishPath())` cannot see that: the string is
	// identical either way. Measured, not deduced: with the path replaced in between, validating an
	// object whose marker is 111 and then dlopen'ing the same path yields 222.
	//
	// The fd is opened ONCE and held. The bytes below are read from it, and the mapping is taken
	// from `/proc/self/fd/<fd>`, which the dynamic loader resolves through this very descriptor --
	// so the object that is validated and the object that is mapped are the same inode by
	// construction, not by hoping the path did not move. Step 8 then proves it rather than assuming
	// the resolution worked.
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		*why = "artifact_unreadable";
		return nullptr;
	}
	struct stat fst {};
	std::vector<u8> image;
	if (fstat(fd, &fst) != 0 || !S_ISREG(fst.st_mode) || !SlurpFd(fd, &image)) {
		close(fd);
		*why = "artifact_unreadable";
		return nullptr;
	}

	// 3. THE TABLE AND THE EXECUTABLE RANGES, FROM THOSE BYTES, BOUNDED. `ArtifactLoopSymbols` is
	//    the reader the publish gate already uses, projecting the WHOLE entry: it parses the ELF
	//    with explicit bounds, refuses a `.aottab` whose declared `n_sym` cannot fit its own
	//    section, and requires every entry to have a defined `_x<gip>` symbol at exactly the address
	//    the entry records. Reusing it means the loader and the publish gate cannot disagree about
	//    what a well-formed table is, and it is why this file contains no second ELF parser.
	std::vector<AOTSymbol> syms(kMaxTableEntries);
	long n_file = ArtifactLoopSymbols(image.data(), image.size(), syms.data(), syms.size());
	if (n_file < 0) {
		close(fd);
		*why = "table_malformed";
		return nullptr;
	}
	if (n_file == 0) {
		close(fd);
		*why = "table_empty";
		return nullptr;
	}
	syms.resize((size_t)n_file);
	ExecRange xr[64];
	long n_xr = ArtifactExecRanges(image.data(), image.size(), xr, 64);
	if (n_xr < 0) {
		close(fd);
		*why = "phdr_malformed";
		return nullptr;
	}

	// 3b. EVERY ENTRY'S HOST ADDRESS IS INSIDE AN EXECUTABLE PT_LOAD OF THIS OBJECT.
	//
	// The first version compared `aot_vaddr` against the FILE'S BYTE LENGTH, which is not a bound on
	// a virtual address at all: the two are unrelated quantities, and an object whose entry pointed
	// outside every loadable segment -- or into a non-executable one -- would have passed. The ELF's
	// own program headers are what say where code can live, so that is what is asked.
	for (auto const &as : syms) {
		if (as.aot_vaddr == 0 || !InExecRange(as.aot_vaddr, xr, n_xr)) {
			close(fd);
			*why = "table_entry_bad_address";
			return nullptr;
		}
	}

	// 4. NO DUPLICATE GUEST IP. Two entries naming one guest address cannot both be installed, and
	//    which one a promoter would pick is exactly the kind of thing that must not be decided by
	//    table order. Refuse the artifact instead.
	for (size_t i = 0; i < syms.size(); ++i) {
		for (size_t k = i + 1; k < syms.size(); ++k) {
			if (syms[i].gip == syms[k].gip) {
				close(fd);
				*why = "table_duplicate_gip";
				return nullptr;
			}
		}
	}

	// 5. THE HEADER THIS RUN SPENT ITS BUILD ON IS IN THE TABLE. The tier selected exactly one
	//    guest loop header and handed it to the compiler; an artifact that does not contain it is
	//    not the artifact this run asked for, however well-formed it is.
	bool has_spawn = false;
	for (auto const &as : syms)
		has_spawn = has_spawn || (as.gip == spawn_gip);
	if (!has_spawn) {
		close(fd);
		*why = "spawn_header_absent";
		return nullptr;
	}

	// 6. ONLY NOW IS ANYTHING MAPPED, AND THE MAPPING IS TAKEN FROM THE OPEN DESCRIPTOR.
	//
	// `/proc/self/fd/<fd>` is resolved by the dynamic loader through THIS descriptor, so the object
	// mapped here is the inode step 2 read and validated -- not whatever the path names by now.
	// Verified with a standalone probe before it was adopted rather than assumed from the name:
	// with the published path replaced between the open and the dlopen, dlopen("/proc/self/fd/N")
	// returns the fd's own object while dlopen(path) returns the replacement.
	//
	// RTLD_NOW so an artifact with an unresolved relocation fails HERE rather than at the first call
	// into it -- which, for this checkpoint, would be a failure nothing ever observes.
	char fdpath[64];
	snprintf(fdpath, sizeof fdpath, "/proc/self/fd/%d", fd);
	void *handle = dlopen(fdpath, RTLD_NOW);
	if (!handle) {
		close(fd);
		*why = "dlopen_failed";
		return nullptr;
	}

	// 7. THE SHARED IDENTITY GATE. CPUState ABI signature and RVV VLEN, from dbt/aot/aot.h -- the
	//    same implementation `BootAOTFile`, `BootOneArtifact` and `BootReuseArtifact` call. Not a
	//    copy: a fourth copy is how an artifact ends up gated on one path and ungated on another.
	if (!AotAbiCompatible(handle, "loop tier load")) {
		dlclose(handle);
		close(fd);
		*why = "abi_or_vlen_mismatch";
		return nullptr;
	}

	link_map *lmap = nullptr;
	if (dlinfo(handle, RTLD_DI_LINKMAP, (void *)&lmap) < 0 || !lmap) {
		dlclose(handle);
		close(fd);
		*why = "no_link_map";
		return nullptr;
	}

	// 8. AND THE MAPPING REALLY IS THAT INODE. The loader records the name it was given, so
	//    resolving it again -- while the descriptor is still open, so it still resolves -- and
	//    comparing (st_dev, st_ino) against the fd's own is a check rather than a restatement of
	//    step 6's intent. A future libc that copied or re-resolved the name would fail here instead
	//    of silently reintroducing the defect.
	struct stat lst {};
	if (!lmap->l_name || stat(lmap->l_name, &lst) != 0 || lst.st_dev != fst.st_dev ||
	    lst.st_ino != fst.st_ino) {
		dlclose(handle);
		close(fd);
		*why = "mapping_is_not_the_validated_object";
		return nullptr;
	}

	// 9. THE MAPPED TABLE, AND IT MUST AGREE WITH THE FILE FIELD BY FIELD. dlsym gives a pointer
	//    with no length, so the in-memory table is bounded by the count the FILE's section headers
	//    already proved can fit -- and then every entry is compared IN FULL. Comparing only the gip
	//    would admit a mapped entry that names the same guest ip at a different host address, which
	//    is a different artifact wearing the right label.
	auto const *tab = (AOTTabHeader const *)dlsym(handle, AOT_SYM_AOTTAB);
	if (!tab) {
		dlclose(handle);
		close(fd);
		*why = "no_aot_tab";
		return nullptr;
	}
	if (tab->n_sym != (u64)n_file) {
		dlclose(handle);
		close(fd);
		*why = "table_count_disagrees";
		return nullptr;
	}
	auto const *base = (u8 const *)lmap->l_addr;
	for (u64 k = 0; k < tab->n_sym; ++k) {
		AOTSymbol const &m = tab->sym[k];
		AOTSymbol const &f = syms[(size_t)k];
		if (m.gip != f.gip || m.aot_vaddr != f.aot_vaddr || m.gsize != f.gsize) {
			dlclose(handle);
			close(fd);
			*why = "table_entry_disagrees";
			return nullptr;
		}
		// 10. ...AND THE RESOLVED HOST ADDRESS BELONGS TO THIS LOADED OBJECT. `dladdr` answers
		//     which mapped object contains an address; requiring its base to be this one's turns
		//     "base + vaddr looks plausible" into "the runtime agrees this address is inside the
		//     object we just mapped".
		Dl_info di{};
		void const *hostp = base + m.aot_vaddr;
		if (!dladdr(hostp, &di) || di.dli_fbase != (void *)base) {
			dlclose(handle);
			close(fd);
			*why = "entry_outside_loaded_object";
			return nullptr;
		}
	}

	// The descriptor's job is done: the mapping is established and proven, and dlclose owns it now.
	close(fd);
	g_view.handle = handle;
	g_view.base = base;
	g_view.tab = tab;
	g_view.n_sym = tab->n_sym;
	g_view.spawn_gip = spawn_gip;
	g_view.path = PublishPath();
	g_loaded = true;
	return &g_view;
}

LoadedArtifact const *LoadedArtifactView()
{
	return g_loaded ? &g_view : nullptr;
}

void ReleaseLoadedArtifact()
{
	if (!g_loaded)
		return;
	void *h = g_view.handle;
	g_view = LoadedArtifact{};
	g_loaded = false;
	// The view is cleared BEFORE the handle is closed, so no caller can observe a view whose
	// pointers name an unmapped object.
	if (h)
		dlclose(h);
}

} // namespace dbt::looptier
