// Local interface test, not external ISA conformance evidence.
#include "dbt/ukernel.cpp"
#include "dbt/guest/rv32_runtime.h"
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
int main()
{
 mmu::Init();
 constexpr u32 a=0x22000000, code=0x23000000;
 check(mmu::mmap(a,32768,PROT_READ|PROT_WRITE,MAP_FIXED|MAP_PRIVATE|MAP_ANON)!=MAP_FAILED,"data");
 check(mmu::mmap(code,4096,PROT_READ|PROT_EXEC,MAP_FIXED|MAP_PRIVATE|MAP_ANON)!=MAP_FAILED,"code");
 ukernel::process.main_thread=std::make_unique<uthread>();
 auto *s=CPUState::Current(); auto *ut=s->GetUThread();
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
