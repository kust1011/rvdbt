// Production archive integration: normal boot installs signals; no implementation
// cpp is included and no guest instruction, handler or retry is executed here.
#include "dbt/ukernel.h"
#include "dbt/mmu.h"
#include "dbt/rvv_host_copy.h"
#include "dbt/tcache/tcache.h"
#include "dbt/tcache/objprof.h"
#include "dbt/util/fsmanager.h"
#include <cstring>
#include <cstdlib>
#include <sys/mman.h>
#include <unistd.h>

static unsigned checks;
static void check(bool value, char const *name)
{
    ++checks;
    if (!value) { fprintf(stderr, "FAIL %s\n", name); std::exit(2); }
}

int main(int argc, char **argv)
{
    using namespace dbt;
    check(argc == 3, "arguments: fixture fsroot and isolated cache");
    fsmanager::Init(argv[2]);
    objprof::Init(argv[2], false);
    mmu::Init();
    tcache::Init();
    ukernel::SetFSRoot(argv[1]);
    char guest[] = "/t.elf";
    char *args[] = {guest};
    ukernel::MainThreadBoot(1, args);
    check(CPUState::Current() != nullptr, "normal boot owns CPUState");
    struct sigaction segv{}, bus{};
    check(sigaction(SIGSEGV, nullptr, &segv) == 0 &&
          sigaction(SIGBUS, nullptr, &bus) == 0, "installed signal actions readable");
    check((segv.sa_flags & SA_SIGINFO) && (bus.sa_flags & SA_SIGINFO), "SIGINFO installed");
    check(segv.sa_sigaction == bus.sa_sigaction && segv.sa_sigaction,
          "normal boot installs shared production callback");
    check(sigismember(&segv.sa_mask, SIGTERM) == 1 &&
          sigismember(&bus.sa_mask, SIGTERM) == 1, "initialized callback masks");
    auto page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    for (bool bus_fault : {false, true}) for (u32 width : {1u, 2u, 4u, 8u})
        for (bool store : {false, true}) {
            char file[] = "/tmp/rvv-linked-copy-XXXXXX";
            int fd = bus_fault ? mkstemp(file) : -1;
            if (bus_fault) {
                unlink(file);
                check(fd >= 0 && ftruncate(fd, 2*page) == 0, "file backing");
            }
            auto *memory = static_cast<u8 *>(mmap(nullptr, 2*page, PROT_READ|PROT_WRITE,
                bus_fault ? MAP_SHARED : MAP_PRIVATE|MAP_ANONYMOUS, fd, 0));
            check(memory != MAP_FAILED, "host fixture mapping");
            u8 element[8]; memset(element, 0x6a, sizeof(element));
            memset(memory, 0x35, page);
            u32 denied = 0;
            rvv_host_copy::ResetFault();
            check(rvv_host_copy::Copy(element, memory, 0, width, store, denied), "valid copy");
            check((store ? memory[0] : element[0]) == (store ? 0x6a : 0x35), "valid bytes");
            check(rvv_host_copy::LastFault().signal == 0, "valid copy has no host fault");
            if (bus_fault) {
                check(ftruncate(fd, page) == 0, "truncate before one denied invocation");
                close(fd);
            } else check(mprotect(memory+page, page, PROT_NONE) == 0, "denied host page");
            check(!rvv_host_copy::Copy(element, memory, page, width, store, denied), "production signal capture returns");
            auto fault = rvv_host_copy::LastFault();
            check(denied == page && fault.signal == (bus_fault ? SIGBUS : SIGSEGV), "fault address and signal");
            check(fault.code == (bus_fault ? BUS_ADRERR : SEGV_ACCERR), "actual kernel signal code");
            munmap(memory, 2*page);
        }
    printf("HOST_COPY_LINKAGE_PASS normal_boot=1 valid=16 denied=16 checks=%u guest_calls=0\n", checks);
    fsmanager::Destroy();
}
