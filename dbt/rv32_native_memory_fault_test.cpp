// One host fault, emitted terminal exit, real trampoline, terminal dispatcher
// snapshot. No guest signal delivery/return, mapping repair or same-PC retry.
#define RVV_NATIVE_FAULT_FIXTURE
#include "dbt/rv32_native_memory_site_test.cpp"
#include "dbt/rvv_native_fault.h"
#include "dbt/qmc/qcg/jitabi.h"
extern "C" u32 qcgstub_rv32_native_memory_safe(CPUState *, u32);
static unsigned caught;
static void recover_once(int sig, siginfo_t *info, void *frame)
{
 if (++caught != 1) _exit(95);
 dbt_sigaction_memory(sig,info,frame);
}
static void recovered_cell(CPUState *s, bool store, u32 eew, bool partial, bool first, bool pins, u32 inside=0)
{
 config::qcg_pin=pins;config::qcg_pin_k=pins?2:0;
 SiteRuntime runtime;runtime.relocate=false;MemArena arena(4u<<20);
 auto code=emit(runtime,arena,store,eew,partial);
 check(runtime.allocated_pins==0,"HAS_CALLS excludes actual QRA region pins");
 mmu::mprotect(data,8192,PROT_READ|PROT_WRITE);
 clear(s);s->vec.Reset(1024);s->vec.vtype=eew==4?16:24;
 s->vec.vl=partial?96/eew:128/eew;s->gpr[5]=data+4096-(first?0:64)-inside;s->gpr[6]=0;
 s->vec.vreg[8].fill(0x67);
 auto *memory=(u8*)mmu::g2h(s->gpr[5]);
 for(unsigned i=0;i<128;++i)memory[i]=(u8)(i*5+3);
 std::array<u8,128> input;memcpy(input.data(),memory,128);
 check(qcgstub_rv32_native_memory_safe(s,word(eew,store))==(inside?0u:1u),"native versus checked-crossing admission");
 // A distinct normal invocation, before the one-time fault child.
 jitabi::trampoline_to_jit(s,mmu::base,code.data());
 check(s->gpr[6]==0x123 && !s->vec.vstart && s->trapno==rv32::TrapCode::NONE,"normal SIMD completion");
 for(unsigned i=0;i<128;++i)check(s->vec.vreg[8][i]==(!store && i<s->vec.vl*eew?input[i]:0x67),"normal SIMD destination/tail");
 memcpy(memory,input.data(),128);s->vec.vreg[8].fill(0x67);s->gpr[6]=0;s->ip=pc;
 auto epoch=mmu::MappingEpoch();
 pid_t child=fork();check(child>=0,"terminal dispatcher fork");
 if(!child) {
  caught=0;
  struct sigaction sa{};sa.sa_sigaction=recover_once;sa.sa_flags=SA_SIGINFO;sigfillset(&sa.sa_mask);
  sigaction(SIGSEGV,&sa,nullptr);sigaction(SIGBUS,&sa,nullptr);
  if(::mprotect(mmu::g2h(data+4096),4096,PROT_NONE) || mmu::MappingEpoch()!=epoch) _exit(92);
  // Deliberately open a deferred FP bracket: native memory has no local FP scope.
  config::rvv_fround_mxcsr_mode=0;s->fpu.fround_run_open=true;
  s->fpu.fround_run_saved_mxcsr=_mm_getcsr();_mm_setcsr(0x3f80);
  if(sigsetjmp(trap_unwind_env,0)==0) {
   jitabi::trampoline_to_jit(s,mmu::base,code.data());_exit(93);
  }
  check(caught==1,"exactly one synchronous host fault");
  check(s->trapno==rv32::TrapCode::MEMORY_FAULT && s->GetUThread()->memory_fault_pending,"dispatcher pending event");
  auto snapshot=ukernel::CaptureHelperMemoryFault(s);
  auto const &event=snapshot.event;
  u32 const prefix=(first?0:64)+inside;
  check(s->ip==pc+4 && snapshot.pc==pc+4 && s->gpr[6]==0x123,"actual instruction and older scalar state");
  check(s->vec.vstart==prefix/eew && snapshot.csrs[3]==prefix/eew,"precise page-contained first denied element");
  check(event.origin==(inside?MemoryFaultEvent::Origin::HostCopy:MemoryFaultEvent::Origin::NativeUnit) && event.pc==pc+4 &&
        event.raw==word(eew,store) && event.element==prefix/eew && event.address==data+4096 &&
        event.eew_bytes==eew && event.nf==1 && !event.field && event.host_signal==SIGSEGV &&
        event.host_code==SEGV_ACCERR,"native event coordinates");
  check(!s->fpu.fround_run_open && _mm_getcsr()==s->fpu.fround_run_saved_mxcsr,"cold FP cleanup");
  for(unsigned i=0;i<128;++i)check(s->vec.vreg[8][i]==(!store && i<prefix?input[i]:0x67),"dispatcher full destination");
  for(unsigned i=0;i<prefix;++i)check(memory[i]==(store?0x67:input[i]),"earlier memory publication");
  char filename[128];snprintf(filename,sizeof(filename),
   "dispatcher-store%d-eew%u-partial%d-first%d-pins%d-inside%u.bin",store,eew,partial,first,pins,inside);
  FILE *out=fopen(filename,"wb");check(out && fwrite(&snapshot,1,sizeof(snapshot),out)==sizeof(snapshot),"retain complete terminal dispatcher snapshot");fclose(out);
  snprintf(filename,sizeof(filename),"memory-store%d-eew%u-partial%d-first%d-pins%d-inside%u.bin",store,eew,partial,first,pins,inside);
  out=fopen(filename,"wb");check(out && fwrite(memory,1,prefix,out)==prefix,"retain completed earlier memory");fclose(out);
  printf("NATIVE_DISPATCH store=%d eew=%u partial=%d first=%d pin_requested=%d actual_pins=0 crossing=%u fault_count=%u pc=%08x vstart=%u address=%08x cleanup=PASS no_retry=1\n",
   store,eew,partial,first,pins,inside,caught,s->ip,s->vec.vstart,event.address);
  fflush(stdout);_exit(0);
 }
 int status;waitpid(child,&status,0);check(WIFEXITED(status)&&WEXITSTATUS(status)==0,"cold exit terminal snapshot child");
 ++cells;
}
static void exclusions(CPUState *s)
{
 SiteRuntime runtime;runtime.relocate=false;MemArena arena(4u<<20);auto code=emit(runtime,arena,false,4,true);
 clear(s);s->vec.Reset(1024);s->vec.vtype=16;s->vec.vl=24;s->gpr[5]=data+4096-68;
 check(qcgstub_rv32_unit_memory_safe(s,word(4,false))==1 &&
       qcgstub_rv32_native_memory_safe(s,word(4,false))==0,"cross-page active chunk falls back before SIMD");
 // A nominal chunk may cross the page if every crossing lane is inactive.
 s->vec.vl=1;s->gpr[5]=data+4092;
 check(qcgstub_rv32_native_memory_safe(s,word(4,false))==1,"partial VL ignores masked-off page");
 s->vec.vreg[8].fill(0x67);s->gpr[6]=0;
 u32 input=0x12345678;memcpy(mmu::g2h(s->gpr[5]),&input,4);
 check(::mprotect(mmu::g2h(data+4096),4096,PROT_NONE)==0,"inactive host page denied");
 jitabi::trampoline_to_jit(s,mmu::base,code.data());
 check(!memcmp(s->vec.vreg[8].data(),&input,4) && s->vec.vreg[8][4]==0x67 &&
       s->trapno==rv32::TrapCode::NONE,"actual masked-off page suppression");
 check(::mprotect(mmu::g2h(data+4096),4096,PROT_READ|PROT_WRITE)==0,"restore after normal completion");
 s->vec.vl=2;check(qcgstub_rv32_native_memory_safe(s,word(4,false))==0,"partial VL active crossing falls back");
 s->vec.vstart=1;check(qcgstub_rv32_native_memory_safe(s,word(4,false))==0,"restart goes to existing element helper");
 s->vec.vstart=0;
 auto const site=runtime.sites[0];ucontext_t uc{};siginfo_t info{};
 uc.uc_mcontext.gregs[REG_RIP]=(greg_t)((uptr)code.data()+site.code_offset);
 uc.uc_mcontext.gregs[REG_R13]=(greg_t)s;uc.uc_mcontext.gregs[REG_RAX]=s->gpr[5];
 uc.uc_mcontext.gregs[REG_RBP]=(greg_t)mmu::base;uc.uc_mcontext.gregs[REG_TRAPNO]=14;
 uc.uc_mcontext.gregs[REG_RDX]=1;
 uc.uc_mcontext.gregs[REG_ERR]=4;info.si_code=SEGV_ACCERR;info.si_addr=mmu::g2h(s->gpr[5]);
 rvv_native_fault::Arm(s);
 ++uc.uc_mcontext.gregs[REG_RIP];check(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc),"interior PC unowned");
 --uc.uc_mcontext.gregs[REG_RIP];
 info.si_code=BUS_ADRERR;check(!rvv_native_fault::HandleSignal(SIGBUS,&info,&uc),"BUS unowned");
 info.si_code=SEGV_ACCERR;uc.uc_mcontext.gregs[REG_TRAPNO]=13;
 check(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc),"non-page fault unowned");
 uc.uc_mcontext.gregs[REG_TRAPNO]=14;uc.uc_mcontext.gregs[REG_ERR]=36;
 check(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc),"PKU unowned");
 uc.uc_mcontext.gregs[REG_ERR]=4;info.si_addr=mmu::g2h(s->gpr[5]+128);
 check(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc),"unrelated footprint unowned");
 info.si_addr=mmu::g2h(s->gpr[5]);tcache::Invalidate();
 check(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc),"physical reset retires signal ownership");
}
int main()
{
 check(__builtin_cpu_supports("avx512f")&&__builtin_cpu_supports("bmi2"),"actual host512 no force");
 config::trace=false;config::fast_boot=true;tcache::Init();mmu::Init();ukernel::process.main_thread=std::make_unique<uthread>();
 FILE *layout=fopen("dispatcher-layout.json","w");check(layout,"snapshot layout receipt");
 fprintf(layout,"{\"size\":%zu,\"event\":%zu,\"pc\":%zu,\"gpr\":%zu,\"csrs\":%zu,\"vreg\":%zu,\"vreg_stride\":%zu}\n",
  sizeof(MemoryFaultSnapshot),offsetof(MemoryFaultSnapshot,event),offsetof(MemoryFaultSnapshot,pc),
  offsetof(MemoryFaultSnapshot,gpr),offsetof(MemoryFaultSnapshot,csrs),offsetof(MemoryFaultSnapshot,vreg),sizeof(rv32::VectorState{}.vreg[0]));
 fclose(layout);
 auto *s=CPUState::Current();check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE)!=MAP_FAILED,"ordinary anonymous RAM");
 for(bool store:{false,true})for(u32 eew:{4u,8u})for(bool partial:{false,true})for(bool first:{false,true})for(bool pins:{false,true})
  recovered_cell(s,store,eew,partial,first,pins);
 for(bool store:{false,true})for(u32 eew:{4u,8u})for(bool partial:{false,true})
  recovered_cell(s,store,eew,partial,false,false,eew);
 config::qcg_pin=false;exclusions(s);tcache::Destroy();
 printf("LOCAL_NATIVE_DISPATCH_PASS checks=%u cells=%u ABI=%016llx (terminal inspection only, restart NOT verified)\n",checks,cells,(unsigned long long)rv32::CPUStateAbiSignature());
}
