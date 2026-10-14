// Task189: bounded optional interpreter gather admission and terminal fault tests.
// Original SIGBUS is captured and terminated in its signal handler. Fixed faults
// use the existing owned copy boundary, then inspect the queued terminal event.
// No guest handler return, mapping repair, same-PC retry or forward-progress test.
#include "dbt/ukernel.cpp"
#include "dbt/guest/rv32_runtime.h"
#include <sys/wait.h>
#include <string>
using namespace dbt;
extern "C" void qcgstub_rv32_vlxei(CPUState *, u32);
static unsigned checks, normal_cells, fault_cells;
static void check(bool ok, char const *why) {
 ++checks; if(!ok){fprintf(stderr,"OPTIONAL_GATHER_FAIL %s\n",why);exit(2);}
}
constexpr u32 data=0x24000000, pc=0x80001234;
static CPUState *state;
static int receipt_fd;
static bool original;
static volatile sig_atomic_t caught;
struct OriginalReceipt { int signal, code; u32 address, start; u64 calls; u32 values[16]; };
static void terminal_signal(int sig, siginfo_t *info, void *frame) {
 if(++caught!=1)_exit(95);
 if(original) {
  OriginalReceipt r{};r.signal=sig;r.code=info->si_code;r.address=mmu::h2g(info->si_addr);
  r.start=state->vec.vstart;r.calls=rv32::rvv_gather::g_gather_calls;
  for(unsigned e=0;e<16;++e)r.values[e]=(u32)state->vec.elem_u(8,e,4,1024);
  if(write(receipt_fd,&r,sizeof(r))!=sizeof(r))_exit(96);
  _exit(0); // never return to the faulting gather
 }
 dbt_sigaction_memory(sig,info,frame); // owned copy leaf exit; no instruction retry
}
static u32 word(bool alias, bool ordered=false, bool masked=false) {
 return ((ordered?3u:1u)<<26)|(u32(!masked)<<25)|((alias?8u:9u)<<20)|(5u<<15)|(6u<<12)|(8u<<7)|7;
}
static void seed(bool alias,u32 start=0,u32 base=data) {
 state->trapno=rv32::TrapCode::NONE;state->GetUThread()->memory_fault_pending=false;
 state->ip=pc;state->vec.Reset(1024);state->vec.vtype=16;state->vec.vl=16;state->vec.vstart=start;
 state->gpr[5]=base;state->vec.vreg[8].fill(0x67);state->vec.vreg[0].fill(0xff);
 for(unsigned e=0;e<16;++e)state->vec.elem_put(alias?8:9,e,4,1024,e*4);
 rv32::rvv_gather::g_gather_calls=rv32::rvv_gather::g_gather_attempts=rv32::rvv_gather::g_gather_unmapped=0;
}
static std::string format(MemoryFaultSnapshot const &s) {
 char *buf=nullptr;size_t n=0;FILE *out=open_memstream(&buf,&n);check(out,"formatter stream");
 ukernel::WriteMemoryFaultSnapshot(out,s);check(fclose(out)==0,"formatter close");
 std::string result(buf,n);free(buf);return result;
}
static void origins() {
 MemoryFaultSnapshot s{};s.vlenb=16;
 for(auto pair:{std::pair{MemoryFaultEvent::Origin::PredictedHelper,"PredictedHelper"},
                std::pair{MemoryFaultEvent::Origin::HostCopy,"HostCopy"},
                std::pair{MemoryFaultEvent::Origin::NativeUnit,"NativeUnit"}}) {
  s.event.origin=pair.first;
  check(format(s).find(std::string("\"origin\":\"")+pair.second+"\"")!=std::string::npos,"exact origin formatting");
 }
}
static void normal(bool file,bool alias,u32 start,bool ordered=false,bool masked=false,u32 base=data) {
 int fd=-1;
 if(file) {char path[]="/tmp/gather189-XXXXXX";fd=mkstemp(path);unlink(path);check(fd>=0&&ftruncate(fd,8192)==0,"normal backing");}
 check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE,MAP_FIXED|(file?MAP_PRIVATE:MAP_PRIVATE|MAP_ANONYMOUS),fd)!=MAP_FAILED,"normal mapping");
 if(fd>=0)close(fd);
 auto *bytes=(u8*)mmu::g2h(data);for(unsigned b=0;b<8192;++b)bytes[b]=(u8)(b*7+3);
 seed(alias,start,base);auto before=state->vec.vreg;
 if(masked)state->vec.mask_set(0,5,false);
 u32 raw=word(alias,ordered,masked);qcgstub_rv32_vlxei(state,raw);
 bool fast=!file&&!start&&!ordered&&!masked;
 check(rv32::rvv_gather::g_gather_calls==(fast?1u:0u),"actual gather admission");
 check(rv32::rvv_gather::g_gather_attempts==(!start&&!ordered&&!masked?1u:0u),"actual shape gate");
 for(unsigned e=0;e<16;++e) {
  u32 expected;memcpy(&expected,before[8].data()+e*4,4);
  if(e>=start&&(!masked||e!=5))memcpy(&expected,mmu::g2h((u32)(base+e*4)),4);
  check(state->vec.elem_u(8,e,4,1024)==expected,"normal prefix/suffix and alias values");
  memcpy(before[8].data()+e*4,&expected,4);
 }
 check(state->vec.vreg[8]==before[8],"normal full destination including tail");
 for(unsigned r=0;r<32;++r)if(r!=8&&!(masked&&r==0))check(state->vec.vreg[r]==before[r],"normal other registers");
 check(!state->vec.vstart&&state->ip==pc+4&&state->trapno==rv32::TrapCode::NONE,"normal completion");
 printf("NORMAL file=%d alias=%d start=%u ordered=%d masked=%d base=%08x attempts=%llu calls=%llu\n",file,alias,start,ordered,masked,base,rv32::rvv_gather::g_gather_attempts,rv32::rvv_gather::g_gather_calls);++normal_cells;
}
static void admission_edges() {
 check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE)!=MAP_FAILED,"edge anonymous map");
 check(mmu::RangeReadableAnonymous(data+4094,4),"anonymous split span admitted");
 check(mmu::mprotect(data+4096,4096,PROT_NONE)==0,"edge denied page");
 check(!mmu::RangeReadableAnonymous(data+4094,4),"second page permission refusal");
 check(mmu::mprotect(data+4096,4096,PROT_READ|PROT_WRITE)==0,"edge readable again");
 check(mmu::munmap(data+4096,4096)==0&&!mmu::RangeReadableAnonymous(data+4094,4),"unmap clears admission");
 check(mmu::mmap(data+4096,4096,PROT_READ|PROT_WRITE)!=MAP_FAILED,"edge remap");
 check(!mmu::RangeReadableAnonymous(0xfffffffeu,4),"host span wrap refused");
 seed(false,0,0x80000000u);auto before=state->vec.vreg;
 check(!rv32::rvv_gather::rvv_gather_e32_avx2(&state->vec,8,9,mmu::base,state->gpr[5],1024,16),"signed gather offsets refused");
 check(state->vec.vreg==before&&!state->vec.vstart&&!rv32::rvv_gather::g_gather_calls,"refusal mutates no state");
 seed(false);state->vec.vl=0;qcgstub_rv32_vlxei(state,word(false));
 check(state->ip==pc+4&&!state->vec.vstart&&!rv32::rvv_gather::g_gather_calls,"empty VL no access or gather");
 // File mapping replacement must clear the old anonymous classification.
 char path[]="/tmp/gather189-edge-XXXXXX";int fd=mkstemp(path);unlink(path);
 check(fd>=0&&ftruncate(fd,4096)==0,"edge regular file");
 check(mmu::mmap(data+4096,4096,PROT_READ,MAP_PRIVATE|MAP_FIXED,fd)!=MAP_FAILED,"replace anonymous with file");close(fd);
 check(mmu::range_readable(data+4094,4)&&!mmu::RangeReadableAnonymous(data+4094,4),"permission alone admits but backing predicate refuses");
 seed(true);for(unsigned e=0;e<16;++e)state->vec.elem_put(8,e,4,1024,e?0:4094);
 before=state->vec.vreg;
 check(!rv32::rvv_gather::rvv_gather_e32_avx2(&state->vec,8,8,mmu::base,data,1024,16)&&state->vec.vreg==before,"mixed anonymous/file split refuses before alias writes");
}
static void fault(bool alias,u32 prefix,u32 start=0,bool split=false,bool permission=false,bool wrap=false) {
 fflush(nullptr);pid_t child=fork();check(child>=0,"fault fork");
 int status;
 if(!child) {
  caught=0;struct sigaction sa{};sa.sa_sigaction=terminal_signal;sa.sa_flags=SA_SIGINFO;sigfillset(&sa.sa_mask);
  sigaction(SIGBUS,&sa,nullptr);sigaction(SIGSEGV,&sa,nullptr);
  char path[]="/tmp/gather189-fault-XXXXXX";int fd=mkstemp(path);unlink(path);
  check(fd>=0&&ftruncate(fd,4096)==0,"fault file one page backing");
  check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED,fd)!=MAP_FAILED,"readable file beyond EOF");close(fd);
  auto *bytes=(u8*)mmu::g2h(data);for(unsigned b=0;b<4096;++b)bytes[b]=(u8)(b*7+3);
  if(permission)check(mmu::mprotect(data+4096,4096,PROT_NONE)==0,"permission denial");
  if(wrap)check(mmu::mmap(0xfffff000,4096,PROT_READ|PROT_WRITE)!=MAP_FAILED,"wrap top mapping");
  seed(alias,start,wrap?0xffffffe0u:data);
  for(unsigned e=0;e<16;++e)state->vec.elem_put(alias?8:9,e,4,1024,split?4094u:(e<prefix?e*4:4096u+(e-prefix)*4));
  if(wrap)for(unsigned e=0;e<16;++e)state->vec.elem_put(alias?8:9,e,4,1024,e*4);
  auto expected=state->vec.vreg;
  for(unsigned e=start;e<prefix;++e)memcpy(expected[8].data()+e*4,mmu::g2h((u32)(state->gpr[5]+e*4)),4);
  u32 raw=word(alias);
  if(sigsetjmp(trap_unwind_env,0)==0){qcgstub_rv32_vlxei(state,raw);_exit(93);}
  check(!original,"original must terminate in signal callback");
  check(caught==((permission||wrap)?0:1),"exact one-time host fault or predicted denial");
  check(rv32::rvv_gather::g_gather_calls==0 && rv32::rvv_gather::g_gather_attempts==(start?0u:1u),"fault fallback before publication");
  auto snapshot=ukernel::CaptureHelperMemoryFault(state);auto const &ev=snapshot.event;
  check(state->trapno==rv32::TrapCode::MEMORY_FAULT&&state->GetUThread()->memory_fault_pending,"terminal pending event");
  check(snapshot.pc==pc&&ev.pc==pc&&ev.raw==raw&&ev.element==prefix&&snapshot.csrs[3]==prefix&&snapshot.csrs[7]==16,"exact PC/raw/prefix/vstart/VL");
  check(snapshot.vreg==expected,"full committed prefix and unchanged fault/suffix/index operands");
  check(ev.address==(wrap?0u:data+4096)&&ev.eew_bytes==4&&ev.nf==1&&!ev.field,"fault address/geometry");
  check(ev.origin==((permission||wrap)?MemoryFaultEvent::Origin::PredictedHelper:MemoryFaultEvent::Origin::HostCopy),"source-owned fault origin");
  if(!permission&&!wrap)check(ev.host_signal==SIGBUS&&ev.host_code==BUS_ADRERR,"actual EOF SIGBUS");
  auto record=format(snapshot);fputs(record.c_str(),stdout);
  printf("TERMINAL alias=%d prefix=%u start=%u split=%d permission=%d wrap=%d caught=%d calls=%llu no_retry=1\n",alias,prefix,start,split,permission,wrap,(int)caught,rv32::rvv_gather::g_gather_calls);
  fflush(stdout);_exit(0);
 }
 check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"terminal child success");++fault_cells;
}
int main(int argc,char **argv) {
 check(__builtin_cpu_supports("avx2"),"actual AVX2 required, no force");
 original=argc==2&&std::string(argv[1])=="--original";
 config::trace=false;config::fast_boot=true;config::vlen_bits=1024;config::rvv_gather=true;
 mmu::Init();ukernel::process.main_thread=std::make_unique<uthread>();state=CPUState::Current();
 if(original) {
  for(bool alias:{false,true}) {
   int p[2];check(pipe(p)==0,"original receipt pipe");receipt_fd=p[1];
   // fault() forks, and its signal callback exits without returning to SIGBUS.
   fault(alias,8);close(p[1]);OriginalReceipt r{};check(read(p[0],&r,sizeof(r))==sizeof(r),"original terminal receipt");close(p[0]);
   check(r.signal==SIGBUS&&r.code==BUS_ADRERR&&r.address==data+4096&&r.start==0&&r.calls==1,"original unowned fault after admitted gather");
   for(unsigned e=0;e<16;++e) {
    u32 expected=alias?(e<8?e*4:4096+(e-8)*4):0x67676767;
    if(e<8){u8 b[4];for(unsigned k=0;k<4;++k)b[k]=(u8)((e*4+k)*7+3);memcpy(&expected,b,4);}
    check(r.values[e]==expected,"original earlier chunk committed and fault chunk undisturbed");
   }
   printf("ORIGINAL_DEFECT alias=%d signal=%d code=%d address=%08x prefix=8 vstart=%u calls=%llu terminal_only=1\n",alias,r.signal,r.code,r.address,r.start,(unsigned long long)r.calls);
  }
 } else {
  origins();admission_edges();
  for(bool file:{false,true})for(bool alias:{false,true})for(u32 start:{0u,3u,16u})normal(file,alias,start);
  normal(false,false,0,false,false,data+1);normal(false,true,0,false,false,data+4094);
  normal(false,false,0,true);normal(false,true,0,false,true);
  // Unsigned base+index wrap producing low addresses is eligible when safe.
  check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE)!=MAP_FAILED,"addition wrap anonymous map");
  seed(true,0,0xfffffff0u);for(u32 e=0;e<16;++e)state->vec.elem_put(8,e,4,1024,data+16+e*4);
  qcgstub_rv32_vlxei(state,word(true));check(rv32::rvv_gather::g_gather_calls==1&&!state->vec.vstart,"safe wrapped address addition admitted");
  for(u32 e=0;e<16;++e){u32 value;memcpy(&value,mmu::g2h(data+e*4),4);check(state->vec.elem_u(8,e,4,1024)==value,"safe wrapped addition alias values");}++normal_cells;
  for(bool alias:{false,true})for(u32 prefix:{0u,8u})fault(alias,prefix);
  fault(true,8,3);fault(true,0,0,true);fault(true,8,0,false,true);fault(true,8,0,false,false,true);
 }
 printf("OPTIONAL_GATHER_%s_PASS checks=%u normal_cells=%u terminal_cells=%u restart_NOT_verified=1\n",original?"ORIGINAL":"FIXED",checks,normal_cells,fault_cells);
}
