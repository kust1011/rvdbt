#include "dbt/util/fsmanager.h"
#include "dbt/util/allocator.h"
#include "dbt/util/common.h"
#include "dbt/util/logger.h"
#include <condition_variable>
#include <functional>
#include <limits>
#include <thread>

#include <fcntl.h>
#include <sched.h>
#include <sys/file.h>
#include <sys/stat.h>

namespace dbt::fsmanager
{
LOG_STREAM(fsmanager);

std::recursive_mutex dbtfslk;

static struct {
	std::mutex rqmtx;
	std::mutex cvmtx;
	std::condition_variable cv;
	std::function<void()> task;
	bool joined{};
} g_fsmanager;

void Init(char const *cache_path)
{
	std::function<void()> task;

	static auto once [[maybe_unused]] = ([]() {
		static auto t = std::thread([st = &g_fsmanager]() {
			log_fsmanager("created");
			if (unshare(CLONE_FILES | CLONE_FS) < 0) {
				Panic("unshare");
			}
			while (true) {
				std::unique_lock lk(st->cvmtx);
				st->cv.wait(lk, [st] { return st->task || st->joined; });
				if (st->joined) {
					return;
				}
				log_fsmanager("execute task");
				st->task();
				st->task = {};
				lk.unlock();
				st->cv.notify_one();
			}
		});
		t.detach();
		return true;
	})();
}

void Destroy()
{
	auto st = &g_fsmanager;
	std::lock_guard lk_rq(st->rqmtx);
	std::lock_guard lk(st->cvmtx);
	st->joined = true;
	st->cv.notify_one();
}

static void SendTask(std::function<void()> &&task)
{
	auto st = &g_fsmanager;
	std::lock_guard lk_rq(st->rqmtx);

	{
		std::lock_guard lk(st->cvmtx);
		st->task = std::move(task);
	}

	log_fsmanager("send task");
	st->cv.notify_one();

	{
		std::unique_lock lk(st->cvmtx);
		st->cv.wait(lk, [st] { return !st->task; });
	}
}

static size_t GetFileSize(int fd)
{
	struct stat st;
	if (fstat(fd, &st) < 0) {
		Panic("fstat");
	}
	return st.st_size;
}

static bool xflock(int fd, bool ex, bool nb)
{
	int const op = (ex ? LOCK_EX : LOCK_SH) | (nb ? LOCK_NB : 0);
	if (flock(fd, op) < 0) {
		if (errno == EWOULDBLOCK) {
			return false;
		}
		Panic("xflock");
	}
	return true;
}

static bool xflock_unlock(int fd)
{
	if (flock(fd, LOCK_UN) < 0) {
		Panic("xflock_unlock");
	}
	return true;
}

// TODO: consistency if owner killed
static CacheFileMapping Task_OpenCacheFile(char const *path, size_t size, bool maywrite)
{
	CacheState fst = CacheState::NO_FILE;
	int fd;

	if (fd = open(path, maywrite ? O_RDWR : O_RDONLY, 0666); fd < 0) {
		if (errno != ENOENT) {
			Panic(std::string("failed to open: ") + path);
		}
		if (!maywrite) {
			// no cache file
			return {};
		}
		if (fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0666); fd < 0) {
			// just created by another process
			return {};
		}
		xflock(fd, true, false);
		if (ftruncate(fd, size) < 0) {
			Panic();
		}
		fst = CacheState::RDWR_NEW;
	} else {
		if (!xflock(fd, maywrite, true)) {
			close(fd);
			return {};
		}
		if (GetFileSize(fd) == 0) { // assume we locked fresh created file
			xflock_unlock(fd);
			close(fd);
			return {};
		}
		fst = maywrite ? CacheState::RDWR_OLD : CacheState::RDONLY;
	}

	bool const writable = fst == CacheState::RDWR_OLD || fst == CacheState::RDWR_NEW;
	int const prot = PROT_READ | (writable ? PROT_WRITE : 0);
	size_t const actual_size = GetFileSize(fd);
	void *fmap = host_mmap(NULL, actual_size, prot, MAP_SHARED, fd, 0);
	if (fmap == MAP_FAILED) {
		Panic();
	}
	// fd is opened and locked!
	return {fmap, actual_size, fd, fst};
}

CacheFileMapping OpenCacheFileMapping(char const *path, size_t size, bool wmode)
{
	CacheFileMapping res;
	SendTask([&res, path, size, wmode]() { res = Task_OpenCacheFile(path, size, wmode); });
	log_fsmanager("open cache file: %s: %s", path, CacheStateToStr(res.state));
	return res;
}

std::pair<void *, CacheState> OpenCacheFile(char const *path, size_t size, bool wmode)
{
	// Preserve the old interface and its process-lifetime descriptor ownership.
	auto res = OpenCacheFileMapping(path, size, wmode);
	return {res.data, res.state};
}

void GrowCacheFileMapping(CacheFileMapping &mapping, size_t new_size)
{
	SendTask([&mapping, new_size]() {
		if (mapping.worker_fd < 0 ||
		    (mapping.state != CacheState::RDWR_OLD && mapping.state != CacheState::RDWR_NEW) ||
		    new_size <= mapping.size || new_size > (size_t)std::numeric_limits<off_t>::max())
			Panic("invalid cache mapping growth");
		// Never close/reopen: dropping the existing flock here would permit a
		// reader/writer race. Only this worker can use its unshared descriptor.
		if (ftruncate(mapping.worker_fd, (off_t)new_size) < 0)
			Panic("grow cache file: ftruncate");
		void *next = host_mmap(nullptr, new_size, PROT_READ | PROT_WRITE,
				      MAP_SHARED, mapping.worker_fd, 0);
		if (next == MAP_FAILED)
			Panic("grow cache file: mmap");
		mapping.data = next;
		mapping.size = new_size;
	});
}

void CloseCacheFileDescriptor(int fd)
{
	SendTask([fd]() {
		if (fd < 0 || close(fd) != 0)
			Panic("close cache file");
	});
}

char const *CacheStateToStr(CacheState s)
{
	switch (s) {
	case CacheState::NO_FILE:
		return "no file available";
	case CacheState::RDONLY:
		return "readonly";
	case CacheState::RDWR_OLD:
		return "writable,old";
	case CacheState::RDWR_NEW:
		return "writable,new";
	}
	unreachable("");
}

void *CreateDumpFile(char const *path, size_t size)
{
	DBT_FS_LOCK();
	int fd;
	if (fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666); fd < 0) {
		Panic(std::string("failed to creat ") + path);
	}
	if (ftruncate(fd, size) < 0) {
		Panic();
	}

	void *fmap = host_mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (fmap == MAP_FAILED) {
		Panic();
	}
	close(fd);
	return fmap;
}

} // namespace dbt::fsmanager
