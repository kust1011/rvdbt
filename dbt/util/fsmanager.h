#pragma once

#include <mutex>
#include <optional>
#include <utility>

namespace dbt::fsmanager
{

void Init(char const *cache_path);
void Destroy();

enum class CacheState {
	NO_FILE,
	RDONLY,
	RDWR_OLD,
	RDWR_NEW,
};

char const *CacheStateToStr(CacheState s);

std::pair<void *, CacheState> OpenCacheFile(char const *path, size_t size, bool wmode);

// Owned by the fsmanager worker's unshared descriptor table. Callers may use
// the mapping, but must grow/close the descriptor through the synchronous task
// API (the guest thread may have chrooted or reused this fd number).
struct CacheFileMapping {
	void *data{};
	size_t size{};
	int worker_fd{-1};
	CacheState state{CacheState::NO_FILE};
};
CacheFileMapping OpenCacheFileMapping(char const *path, size_t initial_size, bool wmode);
// Keeps the old mapping alive: callers release it after all borrowed pointers
// have expired. The same fd/flock remains held throughout growth.
void GrowCacheFileMapping(CacheFileMapping &mapping, size_t new_size);
void CloseCacheFileDescriptor(int worker_fd);


extern std::recursive_mutex dbtfslk;
#define DBT_FS_LOCK() std::lock_guard lk(dbt::fsmanager::dbtfslk)

void *CreateDumpFile(char const *path, size_t size);

} // namespace dbt::fsmanager
