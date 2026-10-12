// One-time host faults/state capture only. No guest handler, return or retry.
#define main prior_unit_test_main
#include "dbt/rv32_unit_memory_fault_test.cpp"
#undef main
#include <thread>
#include <sys/wait.h>
extern "C" void qcgstub_rv32_vlse(CPUState *, u32);
extern "C" void qcgstub_rv32_vsse(CPUState *, u32);
extern "C" void qcgstub_rv32_vlseg(CPUState *, u32);
extern "C" char rvv_copy_read_pc[], rvv_copy_write_pc[];

static void filters()
{
 siginfo_t info{};info.si_code=SEGV_ACCERR;info.si_addr=(void*)0x1234;
 ucontext_t uc{};uc.uc_mcontext.gregs[REG_RIP]=(greg_t)rvv_copy_read_pc;
 check(!rvv_host_copy::HandleSignal(SIGSEGV,&info,&uc),"unarmed exact leaf rejected");
 std::thread worker([] {
  check(rvv_host_copy::LastFault().signal==0,"thread-local capture starts empty");
 });worker.join();
}
static void threads()
{
 // Two simultaneous leaf failures have independent capture, without the global dispatcher jump.
 std::atomic<unsigned> passed{0};
 auto work = [&passed](bool store) {
  auto *p=(u8*)::mmap(nullptr,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  u8 element[8]={};u32 denied=99;
  if(p!=MAP_FAILED && !rvv_host_copy::Copy(element,p,0,8,store,denied) &&
     denied==0 && rvv_host_copy::LastFault().signal==SIGSEGV &&
     rvv_host_copy::LastFault().code==SEGV_ACCERR) ++passed;
  ::munmap(p,4096);
 };
 auto before=rvv_host_copy::LastFault();
 std::thread a(work,false),b(work,true);a.join();b.join();
 check(passed==2,"two threads capture real independent leaf faults");
 check(rvv_host_copy::LastFault().signal==before.signal,"worker faults preserve parent TLS");
}
static void helper(CPUState *s, bool store, bool bus, bool split)
{
 // File length one page, mapping two: second page has permission but SIGBUS.
 int fd=-1;
 if(bus) { char name[]="/tmp/rvv-copy123-XXXXXX";fd=mkstemp(name);unlink(name);
  check(fd>=0 && ftruncate(fd,8192)==0,"two-page backing before admission"); }
 check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE,
       MAP_FIXED|MAP_PRIVATE|(bus?0:MAP_ANONYMOUS),fd)!=MAP_FAILED,"map host fault");
 auto epoch=mmu::MappingEpoch();
 auto *mem=(u8*)mmu::g2h(data);mem[4092]=0x12;mem[4093]=0x34;mem[4094]=0x56;mem[4095]=0x78;
 // Bypass MMU to model a host fault after permission admission. Never repaired/retried.
 if(!bus)check(::mprotect(mem+4096,4096,PROT_NONE)==0,"host protection differs from admission");
 u32 denied=0;check(!mmu::FirstDenied(data+4094,8,store,denied),"permissions still admit");
 if(bus) { check(ftruncate(fd,4096)==0,"truncate backing after admission");close(fd); }
 check(mmu::MappingEpoch()==epoch,"host fault invisible to epoch");
 clear(s);s->vec.Reset(128);s->vec.vtype=16;s->vec.vl=3;s->vec.vreg[8].fill(0xa5);
 s->gpr[5]=data+4092;s->gpr[6]=split?2:4;
 if(store)memset(s->vec.elem_ptr(8,1,4,128),0xb6,4);
 config::rvv_census=true;
 u32 const host_mxcsr=rv32::rvdbt_mxcsr_get();
 config::rvv_fround_mxcsr_mode=2;
 config::g_mxcsr_resting=host_mxcsr & ~(rv32::FRound::MXCSR_RC|rv32::FRound::MXCSR_FLAGS);
 s->fpu.fcsr=0;
 rv32::rvv_fast::fround_run_open_or_continue(s->fpu,rv32::fp_mode(s->fpu,3));
 s->fpu.fround_run_open=true;
 rv32::rvdbt_mxcsr_set(rv32::rvdbt_mxcsr_get()|1);
 auto expected=s->vec;
 if(!store)memcpy(expected.elem_ptr(8,0,4,128),mem+4092,4);
 expected.vstart=1;
 u32 raw=word(4,store)|(2u<<26)|(6u<<20);
 if(sigsetjmp(trap_unwind_env,0)==0) {
  if(store)qcgstub_rv32_vsse(s,raw);else qcgstub_rv32_vlse(s,raw);
 }
 auto snap=ukernel::CaptureHelperMemoryFault(s);
 check(snap.event.origin==MemoryFaultEvent::Origin::HostCopy &&
       snap.event.reason==MemoryFaultEvent::Reason::HostFault,"host-copy provenance");
 check(snap.event.host_signal==(bus?SIGBUS:SIGSEGV) &&
       snap.event.host_code==(bus?BUS_ADRERR:SEGV_ACCERR),"actual host signal/code");
 check(snap.pc==pc && snap.event.raw==raw && snap.event.address==data+4096 &&
       snap.event.element==1 && snap.event.field==0 && snap.event.eew_bytes==4,
       "actual precise coordinates");
 check(snap.vreg==expected.vreg && snap.csrs[3]==1 && snap.csrs[7]==3,"all vector state and VL");
 check(!s->fpu.fround_run_open && (snap.csrs[0]&16) &&
       rv32::rvdbt_mxcsr_get()==config::g_mxcsr_resting,"host fault closes FP run and restores MXCSR");
 config::rvv_fround_mxcsr_mode=0;rv32::rvdbt_mxcsr_set(host_mxcsr);
 siginfo_t info{};ucontext_t uc{};info.si_code=SEGV_ACCERR;
 info.si_addr=mem+4096;uc.uc_mcontext.gregs[REG_RIP]=(greg_t)rvv_copy_read_pc;
 check(!rvv_host_copy::HandleSignal(SIGSEGV,&info,&uc),"boundary disarmed");
 check(!ukernel::DeliverHelperSignal(s,snap),"host fault delivery explicitly unsupported");
 if(store)check(mem[4092]==0xa5 && mem[4093]==0xa5 &&
                mem[4094]==(split?0xb6:0xa5) && mem[4095]==(split?0xb6:0xa5),
                "completed store and split-field byte prefix retained");
 ukernel::WriteMemoryFaultSnapshot(stdout,snap);
 ++cells;
}
static void segment(CPUState *s)
{
 char name[]="/tmp/rvv-seg123-XXXXXX";int fd=mkstemp(name);unlink(name);
 check(fd>=0 && ftruncate(fd,4096)==0,"segment file");
 check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE,MAP_FIXED|MAP_PRIVATE,fd)!=MAP_FAILED,"segment mapping");close(fd);
 auto *mem=(u8*)mmu::g2h(data);
 for(u32 b=4084;b<4096;++b)mem[b]=(u8)b;
 clear(s);s->vec.Reset(128);s->vec.vtype=16;s->vec.vl=3;s->gpr[5]=data+4084;
 s->vec.vreg[8].fill(0x65);s->vec.vreg[9].fill(0x76);auto expected=s->vec;
 memcpy(expected.elem_ptr(8,0,4,128),mem+4084,4);
 memcpy(expected.elem_ptr(9,0,4,128),mem+4088,4);
 memcpy(expected.elem_ptr(8,1,4,128),mem+4092,4);
 u32 raw=word(4,false)|(1u<<29);
 if(sigsetjmp(trap_unwind_env,0)==0)qcgstub_rv32_vlseg(s,raw);
 auto snap=ukernel::CaptureHelperMemoryFault(s);
 check(snap.event.host_signal==SIGBUS && snap.event.field==1 && snap.event.nf==2 &&
       snap.event.element==1 && snap.event.raw==raw && snap.pc==pc && snap.event.address==data+4096,
       "segment actual bus field coordinates");
 check(snap.vreg==expected.vreg && snap.csrs[3]==1 && snap.csrs[7]==3,"segment completed fields and fault field publication");
 ++cells;
}
static void fof(CPUState *s,u32 base)
{
 int fd;char name[]="/tmp/rvv-fof123-XXXXXX";fd=mkstemp(name);unlink(name);
 check(fd>=0 && ftruncate(fd,4096)==0,"FOF file");
 check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED,fd)!=MAP_FAILED,"FOF mapping");close(fd);
 clear(s);s->vec.Reset(128);s->vec.vtype=16;s->vec.vl=3;s->gpr[5]=base;s->vec.vreg[8].fill(0xcc);
 if(sigsetjmp(trap_unwind_env,0)==0)qcgstub_rv32_vleff(s,word(4,false)|(16u<<20));
 if(base==data+4096) {
  auto snap=ukernel::CaptureHelperMemoryFault(s);
  check(snap.event.host_signal==SIGBUS && snap.csrs[7]==3 && snap.csrs[3]==0,"FOF zero captures bus");
 } else check(s->trapno==rv32::TrapCode::NONE && s->vec.vl==1 && s->vec.vstart==0 &&
              !s->GetUThread()->memory_fault_pending,"FOF later bus trims without event");
 ++cells;
}
int main()
{
 mmu::Init();ukernel::process.main_thread=std::make_unique<uthread>();auto *s=CPUState::Current();
 struct sigaction sa{};sigfillset(&sa.sa_mask);sa.sa_flags=SA_SIGINFO;
 sa.sa_sigaction=dbt_sigaction_memory;
 check(sigaction(SIGSEGV,&sa,nullptr)==0 && sigaction(SIGBUS,&sa,nullptr)==0,"install production callback");
 config::vlen_bits=128;config::rvv_lowering=0;config::rvv_verify=false;
 filters();
 for(bool bus:{false,true})for(bool store:{false,true})for(bool split:{false,true})helper(s,store,bus,split);
 segment(s);fof(s,data+4092);fof(s,data+4096);threads();
 // An unrelated real host fault must retain fatal handling, not produce a captured event.
 auto *guard=(u8*)::mmap(nullptr,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 check(guard!=MAP_FAILED && !mmu::check_h2g(guard),"unrelated host guard mapping");
 for(bool inside:{false,true}) {
  pid_t child=fork();check(child>=0,"fork unrelated host fault");
  if(child==0) {
   if(inside) { u32 denied;rvv_host_copy::Copy(guard,(u8*)mmu::g2h(data),0,1,true,denied); }
   else *guard=1;
   _exit(99);
  }
  int status;check(waitpid(child,&status,0)==child,"wait unrelated fault");
  check(WIFSIGNALED(status) && WTERMSIG(status)==SIGABRT,"unrelated host fault retains fatal Panic");
 }
 ::munmap(guard,4096);
 printf("HOST_COPY_FAULT_PASS checks=%u cells=%u no_guest_retry\n",checks,cells);
}
