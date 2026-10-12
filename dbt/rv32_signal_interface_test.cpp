// Local interface test, not external ISA conformance evidence.
#include "dbt/ukernel.cpp"
#include "dbt/guest/rv32_runtime.h"
#include <sys/wait.h>
using namespace dbt;
using namespace dbt::rv32_signal;
static unsigned checks;
static void check(bool ok, char const *why)
{ ++checks; if (!ok) { fprintf(stderr,"SIGNAL_INTERFACE_FAIL %s\n",why); exit(2); } }
static i32 call(CPUState *s,u32 no,u32 first,u32 in,u32 out,u32 size=8)
{
 s->gpr[17]=no; s->gpr[10]=first; s->gpr[11]=in; s->gpr[12]=out; s->gpr[13]=size;
 check(ukernel::SignalSyscall(s),"signal syscall handled"); return (i32)s->gpr[10];
}
// Run each direction in a child so the original unowned SIGBUS failure is
// observable independently. All transfers and callbacks are production APIs.
static void checked_buffers(CPUState *s, uthread *ut, u32 a, u32 code)
{
 u8 source[16], result[16];
 for(u32 i=0;i<16;++i)source[i]=0x40+i;
 check(CopyOut(a+4090,source,16),"normal cross-page output");
 check(CopyIn(result,a+4090,16) && !memcmp(source,result,16),"normal cross-page input");
 for(u32 address : {0u,0xfffffff8u,a+32760}) {
  memset(result,0x6d,16);
  check(!CopyIn(result,address,16),"null wrapping unmapped-crossing input denied");
  for(u8 byte:result)check(byte==0x6d,"preflight input leaves destination intact");
  check(!CopyOut(address,source,16),"null wrapping unmapped-crossing output denied");
 }
 check(mmu::mprotect(a+4096,4096,PROT_READ)==0,"copy read-only page");
 memset(result,0xa5,16);
 check(!CopyOut(a+4090,result,16),"cross-page output permission denied");
 check(CopyIn(result,a+4090,16) && !memcmp(source,result,16),"denied output leaves prefix intact");
 check(mmu::mprotect(a+4096,4096,PROT_WRITE)==0,"copy write-only page");
 memset(result,0x6d,16);
 check(!CopyIn(result,a+4090,16),"cross-page input permission denied");
 for(u8 byte:result)check(byte==0x6d,"denied input leaves prefix intact");
 check(CopyOut(a+4096,source,16),"guest write-only output allowed");
 check(mmu::mprotect(a+4096,4096,PROT_READ|PROT_WRITE)==0,"restore normal test permissions");
 unsigned child_checks=0;bool passed=true;
 for(bool store : {false,true}) {
  pid_t child=fork();check(child>=0,"truncated buffer fork");
  if(!child) {
   checks=0;
   struct sigaction sa{};sigfillset(&sa.sa_mask);sa.sa_flags=SA_SIGINFO;
   sa.sa_sigaction=dbt_sigaction_memory;
   check(sigaction(SIGSEGV,&sa,nullptr)==0 && sigaction(SIGBUS,&sa,nullptr)==0,"install production callbacks");
   constexpr u32 b=0x25000000;
   int fd=memfd_create("signal-buffer-task141",0);
   check(fd>=0 && ftruncate(fd,8192)==0,"signal file backing");
   check(mmu::mmap(b,8192,PROT_READ|PROT_WRITE,MAP_FIXED|MAP_SHARED,fd,0)!=MAP_FAILED,"signal file mapping");
   memset(mmu::g2h(b),0x3c,8192);
   check(ftruncate(fd,4096)==0,"truncate second page once");close(fd);
   check(mmu::CheckedRange(b+4096,16,PROT_READ|PROT_WRITE),"truncated backing retains permissions");
   memset(result,0x6d,16);
   check(!(store?CopyOut(b+4096,source,16):CopyIn(result,b+4096,16)),"truncated direct copy fails normally");
   check(rvv_host_copy::LastFault().signal==SIGBUS && rvv_host_copy::LastFault().code==BUS_ADRERR,
         "direct copy owned BUS_ADRERR");
   for(u8 byte:result)check(byte==0x6d,"first-byte input fault preserves buffer");
   check(!(store?CopyOut(b+4090,source,16):CopyIn(result,b+4090,16)),"truncated crossing fails normally");
   check(rvv_host_copy::LastFault().signal==SIGBUS,"crossing copy owned BUS");
   if(store)check(!memcmp(mmu::g2h(b+4090),source,6),"output fault retains checked byte prefix");
   else {
    for(u32 i=0;i<16;++i)check(result[i]==(i<6?0x3c:0x6d),"input fault prefix and suffix values");
   }
   u8 incoming[16]{};put32(incoming,code+4);put32(incoming+4,4);put64(incoming+8,1ull<<20);
   check(CopyOut(a,incoming,16),"fault syscall action input");
   ut->signal_actions[10]={code,0,1ull<<21};
   auto saved=ut->signal_actions[10];
   for(u32 out : {b+4096,b+4090,code,0xfffffff8u}) {
    check(call(s,134,11,a,out)==-EFAULT,"action output failure EFAULT");
    check(ut->signal_actions[10].handler==saved.handler && ut->signal_actions[10].flags==saved.flags &&
          ut->signal_actions[10].mask==saved.mask,"action unchanged after output failure");
   }
   check(call(s,134,11,b+4096,0)==-EFAULT,"truncated action input EFAULT");
   check(ut->signal_actions[10].handler==saved.handler && ut->signal_actions[10].mask==saved.mask,
         "action unchanged after input failure");
   put64(incoming,1ull<<22);check(CopyOut(a,incoming,8),"fault syscall mask input");
   for(u32 how : {0u,1u,2u})for(u32 out : {b+4096,b+4090,code,0xfffffffcu}) {
    ut->guest_signal_mask=(1ull<<21)|(1ull<<22);u64 saved_mask=ut->guest_signal_mask;
    check(call(s,135,how,a,out)==-EFAULT,"mask output failure EFAULT");
    check(ut->guest_signal_mask==saved_mask,"mask unchanged after output failure");
   }
   u64 saved_mask=ut->guest_signal_mask;
   check(call(s,135,2,b+4096,0)==-EFAULT && ut->guest_signal_mask==saved_mask,"truncated mask input atomic EFAULT");
   check(call(s,134,11,0,b+4096)==-EFAULT && call(s,135,0,0,b+4096)==-EFAULT,"truncated query outputs EFAULT");
   // Direct host delivery/codec rejection only; no guest code or retry runs.
   s->vec.Reset(128);s->gpr[2]=b+8192;s->fpu.fround_run_open=false;
   ut->guest_signal_mask=0;ut->signal_actions[10]={code,4,0};
   MemoryFaultSnapshot snapshot{};snapshot.vlenb=16;snapshot.pc=code;
   snapshot.event.access=MemoryFaultEvent::Access::Load;
   snapshot.event.reason=MemoryFaultEvent::Reason::Unmapped;
   auto regs=s->gpr;auto vectors=s->vec.vreg;auto pc=s->ip;
   check(!ukernel::DeliverHelperSignal(s,snapshot) && s->gpr==regs && s->ip==pc &&
         !ut->signal_frame && !ut->guest_signal_mask,"truncated delivery rejects before state publication");
   ut->signal_frame=b+4096;ut->signal_frame_size=FrameSize(16);s->gpr[2]=ut->signal_frame;
   regs=s->gpr;saved_mask=ut->guest_signal_mask;
   check(!ukernel::RestoreSignalFrame(s) && s->gpr==regs && s->vec.vreg==vectors && s->ip==pc &&
         ut->guest_signal_mask==saved_mask && ut->signal_frame==b+4096,"truncated restore rejects before architectural writeback");
   printf("SIGNAL_BUFFER_CHILD_PASS direction=%s checks=%u guest_calls=0\n",store?"out":"in",checks);
   fflush(stdout);_exit(0);
  }
  int status=0;check(waitpid(child,&status,0)==child,"truncated buffer wait");
  fprintf(stderr,"SIGNAL_BUFFER_CHILD_STATUS direction=%s status=%d\n",store?"out":"in",status);
  passed &= WIFEXITED(status) && WEXITSTATUS(status)==0;
  ++child_checks;
 }
 check(passed && child_checks==2,"both truncated copy directions pass");
}
int main()
{
 mmu::Init();
 constexpr u32 a=0x22000000, code=0x23000000;
 check(mmu::mmap(a,32768,PROT_READ|PROT_WRITE,MAP_FIXED|MAP_PRIVATE|MAP_ANON)!=MAP_FAILED,"data");
 check(mmu::mmap(code,4096,PROT_READ|PROT_EXEC,MAP_FIXED|MAP_PRIVATE|MAP_ANON)!=MAP_FAILED,"code");
 ukernel::process.main_thread=std::make_unique<uthread>();
 auto *s=CPUState::Current(); auto *ut=s->GetUThread();
 checked_buffers(s,ut,a,code);
 u8 action[16]{};put32(action,code);put32(action+4,4);put64(action+8,~0ull);
 check(CopyOut(a,action,16),"action input");
 check(call(s,134,11,a,a+32)==0,"install");
 check(ut->signal_actions[10].handler==code && ut->signal_actions[10].mask==(~Unblockable),"private action");
 check(get32((u8*)mmu::g2h(a+32))==0,"old default");
 check(call(s,134,11,0,a+32)==0,"query");
 check(get32((u8*)mmu::g2h(a+32))==code,"query installed");
 check(call(s,134,11,a+32,a+32)==0,"aliased input/output");
 for(u32 n : {0u,9u,19u,65u})check(call(s,134,n,a,0)==-EINVAL,"invalid signal");
 check(call(s,134,11,a,0,16)==-EINVAL,"sigset size");
 check(call(s,134,10,a,0)==-EOPNOTSUPP,"unsupported signal installation");
 put32(action+4,0x08000000);CopyOut(a,action,16);
 check(call(s,134,11,a,0)==-EOPNOTSUPP,"altstack flag unsupported");
 check(ut->signal_actions[10].flags==4,"failed install atomic");
 check(call(s,134,11,0xfffffff8,0)==-EFAULT,"wrapping input");
 check(call(s,134,11,a,code)==-EFAULT,"read-only output");
 check(call(s,134,11,a+32760,0)==-EFAULT,"unmapped crossing");
 sigset_t before{},after{};sigprocmask(SIG_SETMASK,nullptr,&before);
 u8 mask[8];put64(mask,~0ull);CopyOut(a+64,mask,8);
 check(call(s,135,2,a+64,a+80)==0 && ut->guest_signal_mask==~Unblockable,"set guest mask");
 sigprocmask(SIG_SETMASK,nullptr,&after);
 check(!memcmp(&before,&after,sizeof(before)),"host mask unchanged");
 check(call(s,135,999,0,a+80)==0,"query ignores how");
 check(get64((u8*)mmu::g2h(a+80))==~Unblockable,"mask query");
 check(call(s,135,999,a+64,0)==-EINVAL,"invalid how with input");
 check(call(s,135,1,a+64,0)==0 && !ut->guest_signal_mask,"unblock");
 put64(mask,1ull<<10);CopyOut(a+64,mask,8);
 check(call(s,135,0,a+64,0)==0 && ut->guest_signal_mask==(1ull<<10),"block");
 check(call(s,135,2,0xfffffffcu,a+80)==-EFAULT,"mask wrapping input");
 check(mmu::mprotect(a+4096,4096,PROT_READ)==0,"protect");
 check(!mmu::CheckedRange(a+4090,16,PROT_WRITE),"cross-page write denied");
 check(mmu::mprotect(a+4096,4096,PROT_WRITE)==0,"write only");
 check(!mmu::CheckedRange(a+4096,8,PROT_READ),"guest write-only not readable");
 check(mmu::munmap(a+4096,4096)==0 && !mmu::CheckedRange(a+4096,1,PROT_WRITE),"unmap metadata");
 check(ukernel_syscall::linux_tgkill(1,1,11)==-ENOSYS,"tgkill unsupported");
 // Explicit host-to-RV32 mapping tests: synthetic metadata for all accepted
 // codes, both directions and supported action flags. No guest handler runs.
 struct Mapping { int host_signal, host_code; u32 signal, code; };
 for(auto m : {Mapping{SIGSEGV,SEGV_MAPERR,11,1}, Mapping{SIGSEGV,SEGV_ACCERR,11,2},
               Mapping{SIGBUS,BUS_ADRERR,7,2}, Mapping{SIGBUS,BUS_OBJERR,7,3},
               Mapping{0,0,11,1}, Mapping{0,0,11,2}})
 for(bool store : {false,true}) for(u32 flags : {0u,4u}) {
  put32(action,code+(m.signal==7?8:0));put32(action+4,flags);put64(action+8,1ull<<20);
  CopyOut(a,action,16);check(call(s,134,m.signal,a,0)==0,"install both synchronous signals");
  s->vec.Reset(128);s->vec.vtype=16;s->vec.vl=3;s->vec.vstart=1;
  for(u32 r=0;r<32;++r)s->vec.vreg[r].fill(0x21+r);
  s->gpr[2]=a+32768;s->gpr[10]=0xabcdef01;s->fpu.fround_run_open=false;
  ut->guest_signal_mask=1ull<<30;
  MemoryFaultEvent event;event.pc=code;event.address=0x24001002;event.eew_bytes=4;event.nf=2;event.field=1;
  event.element=1;event.access=store?MemoryFaultEvent::Access::Store:MemoryFaultEvent::Access::Load;
  if(m.host_signal) {
   event.origin=MemoryFaultEvent::Origin::HostCopy;event.reason=MemoryFaultEvent::Reason::HostFault;
   event.host_signal=m.host_signal;event.host_code=m.host_code;
  } else event.reason=m.code==1?MemoryFaultEvent::Reason::Unmapped:MemoryFaultEvent::Reason::Protection;
  ukernel::QueueHelperMemoryFault(s,event);auto v=ukernel::CaptureHelperMemoryFault(s);
  ut->memory_fault_pending=false;
  sigprocmask(SIG_SETMASK,nullptr,&before);
  check(ukernel::DeliverHelperSignal(s,v),"all synchronous mappings delivered");
  u32 f=s->gpr[2];std::vector<u8> b(FrameSize(16));check(CopyIn(b.data(),f,b.size()),"mapped frame read");
  check(get32(b.data()+Info)==m.signal && get32(b.data()+Info+4)==0 &&
        get32(b.data()+Info+8)==m.code && get32(b.data()+Info+12)==event.address,"RV32 siginfo exact mapping");
  check(s->gpr[10]==m.signal && s->gpr[11]==f && s->gpr[12]==f+UC &&
        s->ip==code+(m.signal==7?8:0),"signal-specific action and handler args");
  check(get32(b.data()+MC)==v.pc && get32(b.data()+MC+40)==v.gpr[10] &&
        get32(b.data()+VS)==1 && get32(b.data()+VS+4)==3,"fault PC GPR vstart VL");
  for(u32 r=0;r<32;++r)check(!memcmp(b.data()+Data+16*r,v.vreg[r].data(),16),"captured vector frame bytes");
  check(v.event.access==event.access && v.event.field==1 && v.event.element==1 &&
        v.event.host_signal==m.host_signal && v.event.host_code==m.host_code,"metadata direction retained");
  check(get64(b.data()+Mask)==(1ull<<30) &&
        ut->guest_signal_mask==((1ull<<30)|(1ull<<20)|(1ull<<(m.signal-1))),"signal-specific mask");
  check(!ukernel::DeliverHelperSignal(s,v),"cross/same signal nesting rejected");
  auto other=v;other.event.origin=MemoryFaultEvent::Origin::HostCopy;other.event.reason=MemoryFaultEvent::Reason::HostFault;
  other.event.host_signal=m.signal==7?SIGSEGV:SIGBUS;other.event.host_code=m.signal==7?int(SEGV_MAPERR):int(BUS_ADRERR);
  check(!ukernel::DeliverHelperSignal(s,other),"cross signal nesting rejected");
  u8 bad[4];put32(bad,0);CopyOut(f+Header,bad,4);
  auto regs=s->gpr;auto mask_saved=ut->guest_signal_mask;
  check(!ukernel::RestoreSignalFrame(s) && s->gpr==regs && ut->guest_signal_mask==mask_saved &&
        ut->signal_frame==f,"both signals badframe atomic");
  CopyOut(f,b.data(),b.size());check(ukernel::RestoreSignalFrame(s),"local frame restore both signals");
  check(ut->guest_signal_mask==(1ull<<30) && s->vec.vstart==1 && s->vec.vl==3 && s->ip==code,
        "architectural state restored locally");
  sigprocmask(SIG_SETMASK,nullptr,&after);check(!memcmp(&before,&after,sizeof(before)),"delivery/restore host mask unchanged");
  for(u32 handler : {0u,1u,code+1,0x24000000u}) {
   ut->signal_actions[m.signal-1].handler=handler;
   check(!ukernel::DeliverHelperSignal(s,v),"default ignored odd unmapped handler refused");
  }
  ut->signal_actions[m.signal-1]={code,flags,0};ut->guest_signal_mask=1ull<<(m.signal-1);
  check(!ukernel::DeliverHelperSignal(s,v),"matching blocked signal refused");
  ut->guest_signal_mask=1ull<<(m.signal==7?10:6);
  s->gpr[2]=a+32768;
  check(ukernel::DeliverHelperSignal(s,v),"other fault signal mask does not block");
  check(ukernel::RestoreSignalFrame(s),"local second frame restore");
  ut->guest_signal_mask=0;s->gpr[2]=16;
  check(!ukernel::DeliverHelperSignal(s,v),"stack underflow refused");
  s->gpr[2]=code+4096;check(!ukernel::DeliverHelperSignal(s,v),"unwritable stack refused");
  s->gpr[2]=a+32768;ut->signal_actions[m.signal-1].flags=0x40000000;
  check(!ukernel::DeliverHelperSignal(s,v),"unsupported action flags refused at delivery");
 }
 for(u32 sig : {7u,11u}) {
  for(u32 flags : {0x08000000u,0x10000000u,0x40000000u,0x80000000u,0x04000000u,1u}) {
   put32(action,code);put32(action+4,flags);CopyOut(a,action,16);
   auto saved=ut->signal_actions[sig-1];
   check(call(s,134,sig,a,a+32)==-EOPNOTSUPP,"both signals unsupported flags");
   check(ut->signal_actions[sig-1].handler==saved.handler && ut->signal_actions[sig-1].flags==saved.flags,
         "unsupported installation atomic");
  }
  put32(action,1);put32(action+4,4);CopyOut(a,action,16);
  check(call(s,134,sig,a,0)==-EOPNOTSUPP,"both signals ignore installation unsupported");
 }
 // Reject codes/sources outside the captured leaf contract without creating a frame.
 s->vec.Reset(128);s->gpr[2]=a+32768;ut->guest_signal_mask=0;
 MemoryFaultSnapshot unsupported{};unsupported.vlenb=16;unsupported.pc=code;
 unsupported.event.origin=MemoryFaultEvent::Origin::HostCopy;
 unsupported.event.reason=MemoryFaultEvent::Reason::HostFault;
 for(auto m : {Mapping{SIGBUS,BUS_ADRALN,0,0}, Mapping{SIGBUS,SI_USER,0,0},
               Mapping{SIGSEGV,SI_KERNEL,0,0}, Mapping{SIGSEGV,SI_USER,0,0},
               Mapping{SIGILL,1,0,0}, Mapping{SIGBUS,999,0,0}}) {
  unsupported.event.host_signal=m.host_signal;unsupported.event.host_code=m.host_code;
  check(!ukernel::DeliverHelperSignal(s,unsupported) && !ut->signal_frame,"unsupported source/code explicit");
 }
 unsupported.event.origin=MemoryFaultEvent::Origin::PredictedHelper;
 check(!ukernel::DeliverHelperSignal(s,unsupported),"predicted event cannot carry host provenance");
 unsupported.event.origin=static_cast<MemoryFaultEvent::Origin>(99);
 check(!ukernel::DeliverHelperSignal(s,unsupported),"unknown source refused");
 // Exercise validation and restoration on an explicitly queued helper event.
 s->vec.Reset(1024);s->vec.vtype=16;s->vec.vl=9;s->vec.vstart=7;
 s->gpr[2]=a+32768;s->gpr[10]=0x12345678;s->fpu.fround_run_open=false;
 ut->guest_signal_mask=0;ut->signal_actions[10]={code,4,0};
 MemoryFaultEvent e;e.pc=code;e.address=0x24000000;e.eew_bytes=4;e.nf=1;
 ukernel::QueueHelperMemoryFault(s,e);
 auto snap=ukernel::CaptureHelperMemoryFault(s);ut->memory_fault_pending=false;
 check(ukernel::DeliverHelperSignal(s,snap),"helper delivery");
 u32 frame=s->gpr[2]; auto bytes=std::vector<u8>(FrameSize(128));CopyIn(bytes.data(),frame,bytes.size());
 check(!ukernel::DeliverHelperSignal(s,snap),"nested delivery rejected");
 for(u32 off : {Reserved,Header,Header+4,VS+16,VS+20,UC+12}) {
  u8 bad[4];put32(bad,0xffffffff);CopyOut(frame+off,bad,4);
  auto gpr=s->gpr;auto vr=s->vec.vreg;
  check(!ukernel::RestoreSignalFrame(s),"bad frame rejected");
  check(s->gpr==gpr && s->vec.vreg==vr && ut->signal_frame==frame,"badframe atomic");
  CopyOut(frame,bytes.data(),bytes.size());
 }
 // A handler-edited PC/a0 is restored without ordinary syscall writeback.
 u8 word[4];put32(word,code+4);CopyOut(frame+MC,word,4);
 put32(word,0x87654321);CopyOut(frame+MC+40,word,4);
 s->gpr[17]=139;check(ukernel::SignalSyscall(s),"sigreturn handled");
 check(s->ip==code+4 && s->gpr[10]==0x87654321 && !ut->signal_frame,"StateRestored syscall outcome");
 // Test the actual vector opener contract in all MXCSR modes. Modes 1/2
 // omit per-run SAVE, so a deliberately stale saved slot must not be restored.
 u32 host=rv32::rvdbt_mxcsr_get();
 config::g_mxcsr_resting=host & ~(rv32::FRound::MXCSR_RC|rv32::FRound::MXCSR_FLAGS);
 for(u32 mode=0;mode<3;++mode) {
  config::rvv_fround_mxcsr_mode=mode;
  s->fpu.fcsr=0;s->fpu.fround_run_saved_mxcsr=0;
  rv32::rvv_fast::fround_run_open_or_continue(s->fpu,rv32::fp_mode(s->fpu,3));
  s->fpu.fround_run_open=true;
  rv32::rvdbt_mxcsr_set(rv32::rvdbt_mxcsr_get()|1); // accrued invalid exception
  ukernel::QueueHelperMemoryFault(s,e);
  if(sigsetjmp(trap_unwind_env,0)==0) { rv32::FinishHelperMemoryFault(s);check(false,"helper unwind"); }
  check(!s->fpu.fround_run_open && (s->fpu.fflags()&16),"unwind harvests older flags");
  check(rv32::rvdbt_mxcsr_get()==(mode?config::g_mxcsr_resting:host),"mode-specific host FP restore");
  ut->memory_fault_pending=false;s->trapno=rv32::TrapCode::NONE;
  rv32::rvdbt_mxcsr_set(host);
 }
 // An already closed deferred run may still leave its rounding mode behind.
 config::rvv_fround_mxcsr_mode=2;
 rv32::rvdbt_mxcsr_set(config::g_mxcsr_resting|rv32::FRound::MXCSR_RC);
 ukernel::QueueHelperMemoryFault(s,e);
 if(sigsetjmp(trap_unwind_env,0)==0) { rv32::FinishHelperMemoryFault(s);check(false,"closed-run unwind"); }
 check(rv32::rvdbt_mxcsr_get()==config::g_mxcsr_resting,"closed mode2 boundary resets host RC");
 ut->memory_fault_pending=false;s->trapno=rv32::TrapCode::NONE;
 rv32::rvdbt_mxcsr_set(host);
 config::rvv_fround_mxcsr_mode=0;
 for(u32 bits : {128u,256u,512u,2048u,4096u}) {
  s->vec.Reset(bits);s->vec.vtype=0;s->vec.vl=bits/8;s->vec.vstart=bits/8-1;
  s->gpr[2]=a+32768;
  for(u32 r=0;r<32;++r)s->vec.vreg[r].fill(0x37+r);
  ukernel::QueueHelperMemoryFault(s,e);
  auto v=ukernel::CaptureHelperMemoryFault(s);ut->memory_fault_pending=false;
  check(ukernel::DeliverHelperSignal(s,v),"VLEN frame delivery");
  for(u32 r=0;r<32;++r)s->vec.vreg[r].fill(0xee);
  check(ukernel::RestoreSignalFrame(s),"VLEN frame restore");
  for(u32 r=0;r<32;++r) {
   check(!memcmp(s->vec.vreg[r].data(),v.vreg[r].data(),bits/8),"configured vector bytes restored");
   if(bits/8<rv32::VLEN_MAX_BYTES)check(s->vec.vreg[r][bits/8]==0xee,"unconfigured storage retained");
  }
 }
 s->gpr[17]=139;check(ukernel::SignalSyscall(s),"sigreturn handled");
 check(ut->terminating && ut->termination_code==1,"unowned sigreturn terminates");
 ukernel::process.main_thread.reset();mmu::Destroy();
 printf("SIGNAL_INTERFACE_PASS checks=%u guest_calls=0 external_ISA_tests=0\n",checks);
}
