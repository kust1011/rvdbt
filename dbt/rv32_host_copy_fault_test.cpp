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

extern "C" char rvv_copy_read_pc_word[], rvv_copy_write_pc_word[];
extern "C" char rvv_copy_read_pc_dword[], rvv_copy_write_pc_dword[];
extern "C" char rvv_copy_read_pc_qword[], rvv_copy_write_pc_qword[];
extern "C" char rvv_bulk_read_pc_byte[], rvv_bulk_write_pc_byte[];
extern "C" char rvv_bulk_read_pc_word[], rvv_bulk_write_pc_word[];
extern "C" char rvv_bulk_read_pc_dword[], rvv_bulk_write_pc_dword[];
extern "C" char rvv_bulk_read_pc_qword[], rvv_bulk_write_pc_qword[];
static volatile sig_atomic_t probe_width, probe_store, probe_count, probe_errors, probe_bulk;
static void width_callback(int sig, siginfo_t *info, void *frame)
{
 auto *uc=(ucontext_t*)frame;
 if(probe_bulk) {
  char *reads[]={rvv_bulk_read_pc_byte,rvv_bulk_read_pc_word,rvv_bulk_read_pc_dword,rvv_bulk_read_pc_qword};
  char *writes[]={rvv_bulk_write_pc_byte,rvv_bulk_write_pc_word,rvv_bulk_write_pc_dword,rvv_bulk_write_pc_qword};
  unsigned idx=probe_bulk==8?3:probe_bulk==4?2:probe_bulk==2?1:0;
  if((uptr)uc->uc_mcontext.gregs[REG_RIP]!=(uptr)(probe_store?writes[idx]:reads[idx]) ||
     uc->uc_mcontext.gregs[REG_R8]!=3) ++probe_errors;
  ++probe_count;
  ucontext_t copy=*uc;
  copy.uc_mcontext.gregs[REG_R8]=5;
  if(rvv_host_copy::HandleSignal(sig,info,&copy)) ++probe_errors;
  copy=*uc;copy.uc_mcontext.gregs[REG_R8]=2;
  if(rvv_host_copy::HandleSignal(sig,info,&copy)) ++probe_errors;
  copy=*uc;copy.uc_mcontext.gregs[REG_RIP]=(greg_t)(probe_store?reads[idx]:writes[idx]);
  if(rvv_host_copy::HandleSignal(sig,info,&copy)) ++probe_errors;
 }
 if(probe_width) {
  char *reads[]={rvv_copy_read_pc,rvv_copy_read_pc_word,rvv_copy_read_pc_dword,rvv_copy_read_pc_qword};
  char *writes[]={rvv_copy_write_pc,rvv_copy_write_pc_word,rvv_copy_write_pc_dword,rvv_copy_write_pc_qword};
  unsigned idx=probe_width==8?3:probe_width==4?2:probe_width==2?1:0;
  uptr base=uc->uc_mcontext.gregs[REG_RDI];
  if((uptr)uc->uc_mcontext.gregs[REG_RIP]!=(uptr)(probe_store?writes[idx]:reads[idx])) ++probe_errors;
  ++probe_count;
  siginfo_t bad=*info;ucontext_t copy=*uc;
  bad.si_addr=(void*)(base+probe_width);
  if(rvv_host_copy::HandleSignal(sig,&bad,&copy)) ++probe_errors;
  bad.si_addr=(void*)(base-1);copy=*uc;
  if(rvv_host_copy::HandleSignal(sig,&bad,&copy)) ++probe_errors;
  copy=*uc;copy.uc_mcontext.gregs[REG_RIP]=(greg_t)(probe_store?reads[idx]:writes[idx]);
  if(rvv_host_copy::HandleSignal(sig,info,&copy)) ++probe_errors;
  bad=*info;bad.si_code=SI_USER;copy=*uc;
  if(rvv_host_copy::HandleSignal(sig,&bad,&copy)) ++probe_errors;
  copy=*uc;copy.uc_mcontext.gregs[REG_RIP]++;
  if(rvv_host_copy::HandleSignal(sig,info,&copy)) ++probe_errors;
  copy=*uc;copy.uc_mcontext.gregs[REG_RDI]++;
  if(rvv_host_copy::HandleSignal(sig,info,&copy)) ++probe_errors;
  // Exercise a kernel-permitted interior si_addr, without executing again.
  info->si_addr=(void*)(base+probe_width-1);
 }
 dbt_sigaction_memory(sig,info,frame);
}
static void widths()
{
 char *reads[]={rvv_copy_read_pc,rvv_copy_read_pc_word,rvv_copy_read_pc_dword,rvv_copy_read_pc_qword};
 char *writes[]={rvv_copy_write_pc,rvv_copy_write_pc_word,rvv_copy_write_pc_dword,rvv_copy_write_pc_qword};
 char name[]="/tmp/rvv-width124-XXXXXX";int fd=mkstemp(name);unlink(name);
 check(fd>=0 && ftruncate(fd,8192)==0,"width shared backing");
 auto *mem=(u8*)::mmap(nullptr,8192,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
 auto *alias=(u8*)::mmap(nullptr,8192,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);close(fd);
 check(alias!=MAP_FAILED,"denied store inspection alias");memset(alias+4096,0x5d,4096);
 check(mem!=MAP_FAILED,"width mapping");
 check(::mprotect(mem+4096,4096,PROT_NONE)==0,"width denied page");
 for(unsigned idx=0;idx<4;++idx)for(bool store:{false,true}) {
  u32 n=1u<<idx;auto *op=(u8*)(store?writes[idx]:reads[idx]);
  unsigned prefix=idx==1?0x66:idx==3?0x48:0;
  check((!prefix || *op++==prefix) && op[0]==(store?(idx?0x89:0x88):(idx?0x8b:0x8a)) && op[1]==0x07,
        "actual labeled instruction is element-width MOV through RDI");
  u8 element[8];memset(element,0xb7,8);memset(mem,0x3c,16);u32 denied=99;
  check(rvv_host_copy::Copy(element,mem,0,n,store,denied),"aligned width succeeds");
  for(u32 b=0;b<8;++b)check(element[b]==(store||b>=n?0xb7:0x3c),"successful load bounded publication");
  for(u32 b=0;b<16;++b)check(mem[b]==(store&&b<n?0xb7:0x3c),"successful store bounded width");
  memset(element,0xa6,8);probe_width=n;probe_store=store;probe_count=0;probe_errors=0;
  check(!rvv_host_copy::Copy(element,mem,4096,n,store,denied),"aligned denied width captures once");
  probe_width=0;
  check(probe_count==1 && probe_errors==0 && denied==4096+n-1,"actual executed width and interior address filters");
  check(rvv_host_copy::LastFault().signal==SIGSEGV && rvv_host_copy::LastFault().code==SEGV_ACCERR,"width fault provenance");
  for(u8 b:element)check(b==0xa6,"denied load leaves full destination untouched");
  for(u32 b=0;b<16;++b)check(mem[b]==(store&&b<n?0xb7:0x3c),"denied store preserves accessible memory");
  for(u32 b=0;b<16;++b)check(alias[4096+b]==0x5d,"denied aligned store writes no byte of field");
  if(n>1) {
   memset(element,0xe8,8);memset(mem+4096-n+1,0x2a,n-1);
   probe_width=1;probe_store=store;probe_count=0;probe_errors=0;
   check(!rvv_host_copy::Copy(element,mem,4096-n+1,n,store,denied),"misaligned crossing captures once");
   probe_width=0;
   check(probe_count==1 && !probe_errors && denied==4096,"misaligned fault uses byte leaf");
   for(u8 b:element)check(b==0xe8,"misaligned denied load unpublished");
   for(u32 b=0;b<n-1;++b)check(mem[4096-n+1+b]==(store?0xe8:0x2a),"misaligned store retains completed byte prefix");
   check(alias[4096]==0x5d,"misaligned store denied byte untouched");
  }
 }
 ::munmap(mem,8192);::munmap(alias,8192);
 // RV32 wrap uses byte addresses on both sides, not memory beyond 2^32.
 size_t const space=size_t{1}<<32;
 auto *base=(u8*)::mmap(nullptr,space,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE,-1,0);
 check(base!=MAP_FAILED,"separate wrap reservation");
 check(::mprotect(base+0xfffff000u,4096,PROT_READ|PROT_WRITE)==0 &&
       ::mprotect(base,4096,PROT_READ|PROT_WRITE)==0,"wrap edge pages");
 base[0xffffffffu]=0x12;base[0]=0x34;
 u8 element[8]={};u32 denied=99;
 check(rvv_host_copy::Copy(element,base,0xffffffffu,2,false,denied) && element[0]==0x12 && element[1]==0x34,"wrapping load byte decomposition");
 element[0]=0x56;element[1]=0x78;
 check(rvv_host_copy::Copy(element,base,0xffffffffu,2,true,denied) && base[0xffffffffu]==0x56 && base[0]==0x78,"wrapping store byte decomposition");
 u32 completed;
 u8 group[4]={0,0,0xa1,0xa2};
 check(rvv_host_copy::CopyElements(group,base,0xffffffffu,2,2,false,completed,denied) &&
       completed==2 && group[0]==0x56 && group[1]==0x78,"bulk RV32 wrap fallback frontier");
 ::munmap(base,space);
}

static void bulk()
{
 for (u32 width : {1u,2u,4u,8u}) for (bool store : {false,true}) for (bool bus : {false,true}) {
  int fd=-1;
  if(bus) { char name[]="/tmp/rvv-bulk127-XXXXXX";fd=mkstemp(name);unlink(name);
   check(fd>=0 && ftruncate(fd,8192)==0,"bulk file admission"); }
  check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE,
        MAP_FIXED|MAP_PRIVATE|(bus?0:MAP_ANONYMOUS),fd)!=MAP_FAILED,"bulk mapping");
  auto *memory=(u8*)mmu::g2h(data);memset(memory,0x3a,4096);
  u8 elements[64];memset(elements,0xc7,sizeof(elements));u32 completed=99,denied=99;
  check(rvv_host_copy::CopyElements(elements,(u8*)mmu::g2h(0),data,width,4,store,completed,denied)
        && completed==4,"bulk normal exact frontier");
  for(u32 b=0;b<sizeof(elements);++b)
   check(elements[b]==(store||b>=4*width?0xc7:0x3a),"bulk normal bounded publication");
  check(rvv_host_copy::CopyElements(elements,(u8*)mmu::g2h(0),data,width,0,store,completed,denied)
        && completed==0,"empty bulk no access");
  auto epoch=mmu::MappingEpoch();
  if(bus) {check(ftruncate(fd,4096)==0,"bulk truncate after admission");close(fd);}
  else check(::mprotect(memory+4096,4096,PROT_NONE)==0,"bulk host protection after admission");
  check(mmu::MappingEpoch()==epoch,"bulk backing not pinned by epoch");
  memset(elements,0xc7,sizeof(elements));
  probe_bulk=width;probe_store=store;probe_count=0;probe_errors=0;
  check(!rvv_host_copy::CopyElements(elements,(u8*)mmu::g2h(0),data+4096-3*width,
        width,5,store,completed,denied) && completed==3 && denied==data+4096,
        "bulk actual fault exact committed element frontier");
  probe_bulk=0;
  check(probe_count==1 && !probe_errors,"bulk exact PC and frontier filters");
  check(rvv_host_copy::LastFault().signal==(bus?SIGBUS:SIGSEGV) &&
        rvv_host_copy::LastFault().code==(bus?BUS_ADRERR:SEGV_ACCERR),"bulk actual signal provenance");
  for(u32 b=0;b<sizeof(elements);++b)
   check(elements[b]==(store||b>=3*width?0xc7:0x3a),"bulk failed load fault element unpublished");
  for(u32 b=0;b<3*width;++b)
   check(memory[4096-3*width+b]==(store?0xc7:0x3a),"bulk store retains completed elements");
  // Same shared boundary used by checked ordinary and whole-register suffixes.
  rv32::VectorState vs;vs.Reset(128);for(auto &r:vs.vreg)r.fill(0xad);vs.vstart=1;
  check(!rv32::rvv_ref::unit_stride_checked(vs,8,(u8*)mmu::g2h(0),data+4096-3*width,
        128,6,width,true,store,denied) && vs.vstart==3 && denied==data+4096,
        "checked bulk register-gap and nonzero vstart frontier");
  for(u32 e=0;e<6;++e)for(u32 b=0;b<width;++b)
   check(vs.elem_ptr(8,e,width,128)[b]==(!store&&e>=1&&e<3?0x3a:0xad),
         "checked bulk prefix completed suffix and fault publication");
 }
}

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
 sigset_t before{},after{};sigprocmask(SIG_SETMASK,nullptr,&before);
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
 auto *ut=s->GetUThread();ut->memory_fault_pending=false;ut->guest_signal_mask=0;
 ut->signal_actions[10]={pc,4,0};ut->signal_actions[6]={pc+8,4,0};s->gpr[2]=0x25008000;
 check(ukernel::DeliverHelperSignal(s,snap),"real captured helper delivered on host dispatcher stack");
 auto *frame=(u8*)mmu::g2h(s->gpr[2]);
 check(rv32_signal::get32(frame)==(bus?7u:11u) && rv32_signal::get32(frame+8)==2 &&
       rv32_signal::get32(frame+12)==snap.event.address,"real signal code address in RV32 frame");
 check(s->ip==pc+(bus?8:0) && s->gpr[10]==(bus?7u:11u) &&
       rv32_signal::get32(frame+rv32_signal::MC)==pc &&
       rv32_signal::get32(frame+rv32_signal::VS)==1 &&
       rv32_signal::get32(frame+rv32_signal::VS+4)==3,"real fault handler PC vstart VL");
 for(u32 r=0;r<32;++r)check(!memcmp(frame+rv32_signal::Data+r*16,snap.vreg[r].data(),16),"real vector frame bytes");
 sigprocmask(SIG_SETMASK,nullptr,&after);
 check(!memcmp(&before,&after,sizeof(before)),"real capture and delivery host mask unchanged");
 // End this local one-shot observation; never execute handler/sigreturn/retry.
 ut->signal_frame=0;ut->signal_frame_size=0;ut->guest_signal_mask=0;
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
 sa.sa_sigaction=width_callback;
 check(sigaction(SIGSEGV,&sa,nullptr)==0 && sigaction(SIGBUS,&sa,nullptr)==0,"install production callback");
 config::vlen_bits=128;config::rvv_lowering=0;config::rvv_verify=false;
 check(mmu::mmap(pc&~4095u,4096,PROT_READ|PROT_EXEC,MAP_FIXED|MAP_PRIVATE|MAP_ANON)!=MAP_FAILED,"delivery code mapping");
 check(mmu::mmap(0x25000000,32768,PROT_READ|PROT_WRITE,MAP_FIXED|MAP_PRIVATE|MAP_ANON)!=MAP_FAILED,"delivery stack mapping");
 filters();widths();bulk();
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
