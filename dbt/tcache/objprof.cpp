#include "dbt/tcache/objprof.h"
#include "dbt/aot/aot.h"
#include "dbt/config.h"
#include "dbt/util/fsmanager.h"
#include <fcntl.h>
#include <limits>

namespace dbt
{

static std::string g_dbt_cache_dir;

FileChecksum FileChecksum::FromFile(int fd)
{
	struct stat st;
	int res;
	if (res = fstat(fd, &st); res < 0) {
		Panic();
	}

	void *fmap;
	if (fmap = dbt::host_mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0); fmap == MAP_FAILED) {
		Panic();
	}

	FileChecksum sum;

	EVP_MD_CTX *mdctx;
	mdctx = EVP_MD_CTX_new();
	if (!EVP_DigestInit_ex(mdctx, EVP_md5(), NULL)) {
		Panic();
	}
	if (!EVP_DigestUpdate(mdctx, (uint8_t const *)fmap, st.st_size)) {
		Panic();
	}
	if (!EVP_DigestFinal_ex(mdctx, sum.data, NULL)) {
		Panic();
	}
	EVP_MD_CTX_free(mdctx);
	return sum;
}

void objprof::Init(char const *path, bool use_aot_)
{
	char buf[PATH_MAX];
	if (!realpath(path, buf)) {
		Panic(std::string("failed to resolve ") + path);
	}
	g_dbt_cache_dir = std::string(buf) + "/";
	use_aot_files = use_aot_;
}

static std::string MakeCachePath(FileChecksum const &csum, char const *extension)
{
	return g_dbt_cache_dir + csum.ToString() + extension;
}

// X4g3: ARTIFACT paths carry the RVV VLEN they were specialized for; the profile does not.
//
// The cache used to key artifacts on the guest ELF checksum alone, so a build at VLEN 512 and a
// build at VLEN 1024 produced DIFFERENT code at the SAME path: the second silently destroyed the
// first, and a later run at the first VLEN loaded the wrong specialization (X4c/X4d/X4e). The
// checksum answers "which program"; it cannot answer "specialized for which VLEN". Adding the
// active `config::vlen_bits` to the artifact name makes the two identities disjoint, so both can
// live in one cache and each run finds its own or finds nothing.
//
// Scope, deliberately: only VLEN. Other specialization axes (--rvv-vector-ssa, RVV_HOST_CHUNK_BITS
// and the rest of the codegen flags) still share one identity. This is a targeted repair for a
// measured defect, not a general cache-versioning framework.
//
// `.prof` is unaffected BY CONSTRUCTION, not by discipline: Announce() forms it through
// MakeCachePath() directly (see :69), never through this function. One profiling run therefore
// still serves builds at both VLENs, and the profile filename is byte-identical to what it was
// before this change. That separation is asserted mechanically by the focused path test.
std::string objprof::GetCachePath(char const *extension)
{
	assert(HasProfile());
	// e.g. <csum>.v512.aot.so -- qualifier between checksum and extension, so the extension stays
	// the final suffix and every existing `*.aot.so` / `*.aot.o` glob keeps matching.
	std::string qualifier = ".v" + std::to_string(config::vlen_bits);
	return MakeCachePath(elf_prof.fmap->csum, (qualifier + extension).c_str());
}

// The same construction Announce() uses for the profile file (:89), so "the path the run's profile
// lives at" has one definition rather than two that could disagree about the VLEN qualifier.
std::string objprof::GetProfilePath()
{
	assert(HasProfile());
	return MakeCachePath(elf_prof.fmap->csum, ".prof");
}

objprof::ElfProfile objprof::elf_prof{};
bool objprof::use_aot_files = false;

void objprof::Announce(int elf_fd, bool jit_mode)
{
	auto csum = FileChecksum::FromFile(elf_fd);
	auto path = MakeCachePath(csum, ".prof");

	auto &pfile = elf_prof;
	if (pfile.fmap)
		Panic("profile already announced");
	pfile.page2idx.clear();

	log_prof("Lookup profile at %s", path.c_str());
	pfile.mapping = dbt::fsmanager::OpenCacheFileMapping(path.c_str(), 64_MB, jit_mode);
	auto const file_state = pfile.mapping.state;
	pfile.fsize = pfile.mapping.size;

	if (file_state == fsmanager::CacheState::NO_FILE) {
		log_prof("No profile available at %s", path.c_str());
		return;
	}

	if (pfile.fsize < sizeof(FileHeader))
		Panic("truncated profile header " + path);
	pfile.fmap = (FileHeader *)pfile.mapping.data;

	if (file_state == fsmanager::CacheState::RDWR_NEW) {
		pfile.fmap->csum = csum;
		pfile.fmap->n_pages = 0;
	} else {
		if (pfile.fmap->n_pages > (pfile.fsize - sizeof(FileHeader)) / sizeof(PageData))
			Panic("profile count exceeds file capacity " + path);
		if (pfile.fmap->csum != csum) {
			Panic("bad checksum " + path);
		}
		for (u32 idx = 0; idx < pfile.fmap->n_pages; ++idx) {
			auto pageno = pfile.fmap->pages[idx].pageno;
			log_prof("Found PageData for pageno=%u", pageno);
			if (!pfile.page2idx.insert({pageno, idx}).second)
				Panic("duplicate page in profile " + path);
		}
		if (use_aot_files) {
			BootAOTFile();
		}
		// 2026-06-19 AARS: also boot a REUSE artifact (another binary's .aot.so) by gip. Loaded AFTER the binary's
		// own artifact so own-regions win; reuse fills the byte-identical shared (e.g. interpreter) regions.
		if (config::aot_reuse_path != nullptr && config::aot_reuse_path[0] != '\0') {
			BootReuseArtifact(config::aot_reuse_path);
		}
	}
}

void objprof::Destroy()
{
	auto &pfile = elf_prof;
	if (!pfile.fmap)
		return;
	// No profile reader may survive Destroy. Preserve the file lock until all
	// current/retained mappings are unmapped, then close on the fd-owning worker.
	if (munmap(pfile.fmap, pfile.fsize) != 0)
		Panic("unmap profile");
	for (auto const &[base, bytes] : pfile.retained_mappings)
		if (munmap(base, bytes) != 0)
			Panic("unmap retained profile");
	fsmanager::CloseCacheFileDescriptor(pfile.mapping.worker_fd);
	pfile = ElfProfile{};
}

u32 objprof::AllocatePageData(u32 pageno)
{
	log_prof("Allocate PageData for pageno=%u", pageno);
	auto &pfile = elf_prof;
	if (pfile.mapping.state != fsmanager::CacheState::RDWR_NEW &&
	    pfile.mapping.state != fsmanager::CacheState::RDWR_OLD)
		Panic("cannot append to readonly profile");
	u32 const idx = pfile.fmap->n_pages;
	if (idx == std::numeric_limits<u32>::max() ||
	    (size_t)idx + 1 > (std::numeric_limits<size_t>::max() - sizeof(FileHeader)) / sizeof(PageData))
		Panic("profile record count overflow");
	size_t const required = sizeof(FileHeader) + ((size_t)idx + 1) * sizeof(PageData);
	if (required > pfile.fsize) {
		// Geometric growth is a policy, not a new record cap. Clamp before
		// multiplication so neither size_t nor off_t can overflow.
		size_t const limit = (size_t)std::numeric_limits<off_t>::max();
		if (required > limit)
			Panic("profile file size overflow");
		size_t next_size = pfile.fsize;
		while (next_size < required)
			next_size = next_size > limit / 2 ? limit : next_size * 2;
		pfile.retained_mappings.emplace_back(pfile.fmap, pfile.fsize);
		fsmanager::GrowCacheFileMapping(pfile.mapping, next_size);
		pfile.fmap = (FileHeader *)pfile.mapping.data;
		pfile.fsize = pfile.mapping.size;
	}
	auto *page_data = &pfile.fmap->pages[idx];
	*page_data = PageData{};
	page_data->pageno = pageno;
	// Publish only after capacity and the new record exist. A capacity failure
	// must never leave an out-of-range count for the next reader/reopen.
	pfile.fmap->n_pages = idx + 1;
	return idx;
}

objprof::PageData *objprof::GetOrCreatePageData(u32 pageno)
{
	auto &pfile = elf_prof;
	auto it = pfile.page2idx.insert({pageno, 0});
	if (it.second) {
		it.first->second = AllocatePageData(pageno);
	}
	return &pfile.fmap->pages[it.first->second];
}

void objprof::UpdateProfile()
{
	if (elf_prof.mapping.state != fsmanager::CacheState::RDWR_NEW &&
	    elf_prof.mapping.state != fsmanager::CacheState::RDWR_OLD)
		Panic("cannot update unavailable or readonly profile");
	if (unlikely(dbt::config::qcg_freq_edge || dbt::config::qcg_freq_entry))
		tcache::FoldEdgeCounters(); // A-line EDGE/v3: drain arena slots into per-TB counts first
	auto &tmap = tcache::tcache_map;

	for (auto it = tmap.begin(); it != tmap.end();) {
		it = UpdatePageProfile(it);
	}
	// A-line RETIRE: a revoked-and-never-re-executed TB is absent from tcache_map, but its frozen
	// profile record must still land -- a missing node breaks ModuleGraph reachability in the
	// consumer (oracle-caught). Max-merge is exact here: if the TB was retranslated, its carry was
	// consumed at AnnounceRegion and it is not in this map.
	if (unlikely(dbt::config::qcg_freq_retire || dbt::config::sr_web_repack)) {
		for (auto const &[ip, c] : tcache::sat_carry) {
			if (!c.had_tb)
				continue; // TB-less block carry: skip-decision state only, never profile data
			auto *pd = GetOrCreatePageData(ip >> mmu::PAGE_BITS);
			auto idx = PageData::po2idx(ip & ~mmu::PAGE_MASK);
			pd->executed.set(idx);
			if (c.count > pd->exec_count[idx])
				pd->exec_count[idx] = c.count;
			if (c.instr > pd->exec_instr_count[idx])
				pd->exec_instr_count[idx] = c.instr;
			if (c.brt)
				pd->brind_target.set(idx);
			if (c.seg)
				pd->segment_entry.set(idx);
		}
	}
}

tcache::MapType::iterator objprof::UpdatePageProfile(tcache::MapType::iterator it)
{
	u32 const pageno = it->first >> mmu::PAGE_BITS;
	auto *const page_data = GetOrCreatePageData(pageno);
	assert(page_data->pageno == pageno);
	log_prof("Update PageData for pageno=%u", pageno);

	// 29th-cycle defensive fix: the inner page-group walk could dereference tcache_map.end()
	// past the final page (UB). Correctness-preserving (outputs verified byte-identical to
	// exact Wendell d312b122 + AOT on tinyxml2/libyaml). NOTE: this is NOT the cause of the
	// pageno=0 garbage-page family (those persist after this fix -- they are low-ip tcache
	// entries with impossible 2^32-scale counts, a separate writer-corruption/bring-up issue,
	// DEFECT_CARDS_A R3-1(3), assessed ~0% wall).
	for (; it != tcache::tcache_map.end() && (it->first >> mmu::PAGE_BITS) == pageno; ++it) {
		auto tb = it->second;
		auto po_idx = PageData::po2idx(it->first & ~mmu::PAGE_MASK);
		if (page_data->executed.test(po_idx) != true) {
			log_prof("new tb: %08x", it->first);
		}

		auto upd_observed = [&](PageData::PageBitset &bits, bool val) {
			if (val) {
				bits.set(po_idx);
			}
		};

		if (dbt::config::aot_profile_merge) {
			// R47 closed-loop: grow-only MAX merge. Keeps prior admitted counts (AOT regions may report
			// 0 exec during an aot run) and adds newly hot-in-QCG (drifted) regions -> convergent union.
			if (tb->flags.exec_instr_count > page_data->exec_instr_count[po_idx])
				page_data->exec_instr_count[po_idx] = tb->flags.exec_instr_count;
			if (tb->flags.exec_count > page_data->exec_count[po_idx])
				page_data->exec_count[po_idx] = tb->flags.exec_count;
		} else {
			page_data->exec_instr_count[po_idx] = tb->flags.exec_instr_count;
			page_data->exec_count[po_idx] = tb->flags.exec_count;
		}
		log_prof("Update PageData for pageno=%u, po_idx=%u, exec_instr_count=%llu, exec_count=%llu", pageno, po_idx, page_data->exec_instr_count[po_idx], page_data->exec_count[po_idx]);
		upd_observed(page_data->executed, true);
		upd_observed(page_data->brind_target, tb->flags.is_brind_target);
		upd_observed(page_data->segment_entry, tb->flags.is_segment_entry);
	}
	return it;
}

bool objprof::HasProfile()
{
	return elf_prof.fmap != nullptr;
}

std::span<const objprof::PageData> const objprof::GetProfile()
{
	assert(HasProfile());
	auto const *fmap = elf_prof.fmap;
	return {fmap->pages, fmap->n_pages};
}

} // namespace dbt
