// One host fault, emitted terminal exit, real trampoline, terminal dispatcher
// snapshot. No guest signal delivery/return, mapping repair or same-PC retry.
#define RVV_NATIVE_FAULT_FIXTURE
#include "dbt/rv32_native_memory_site_test.cpp"
#include "dbt/rvv_native_fault.h"
#include <thread>
#include "dbt/qmc/qcg/jitabi.h"
extern "C" u32 qcgstub_rv32_native_memory_safe(CPUState *, u32);
extern "C" u32 qcgstub_rv32_native_memory_span(CPUState *, u32, u32, u32, u32);
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
  char *formatted=nullptr;size_t formatted_size=0;
  FILE *formatted_out=open_memstream(&formatted,&formatted_size);check(formatted_out,"origin stream");
  ukernel::WriteMemoryFaultSnapshot(formatted_out,snapshot);check(fclose(formatted_out)==0,"origin close");
  std::string formatted_record(formatted,formatted_size);free(formatted);
  check(formatted_record.find(inside?"\"origin\":\"HostCopy\"":"\"origin\":\"NativeUnit\"")!=std::string::npos,
        "actual terminal snapshot exact origin formatting");
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
 info.si_code=BUS_ADRALN;check(!rvv_native_fault::HandleSignal(SIGBUS,&info,&uc),"alignment BUS unowned");
 info.si_code=SEGV_ACCERR;uc.uc_mcontext.gregs[REG_TRAPNO]=13;
 check(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc),"non-page fault unowned");
 uc.uc_mcontext.gregs[REG_TRAPNO]=14;uc.uc_mcontext.gregs[REG_ERR]=36;
 check(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc),"PKU unowned");
 uc.uc_mcontext.gregs[REG_ERR]=4;info.si_addr=mmu::g2h(s->gpr[5]+128);
 check(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc),"unrelated footprint unowned");
 info.si_addr=mmu::g2h(s->gpr[5]);tcache::Invalidate();
 check(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc),"physical reset retires signal ownership");
}
// Translation and execution on different host threads must use offsets, never
// the translator's absolute TLS slot. Exercise the actual emitted memory frame.
static void publication_thread_case(CPUState *s)
{
 SiteRuntime runtime;runtime.relocate=false;MemArena arena(4u<<20);
 auto code=emit(runtime,arena,false,4,true);
 auto const offsets=rvv_native_fault::GetPublicationOffsets();
 rvv_native_fault::Arm(nullptr);
 unsigned failures=0;
 std::thread worker([&] {
  auto thread_state=std::make_unique<uthread>();
  auto local=std::make_unique<CPUState>(thread_state.get());
  auto *t=local.get();clear(t);t->vec.Reset(1024);t->vec.vtype=16;t->vec.vl=1;
  t->gpr[5]=data+128;
  auto const other=rvv_native_fault::GetPublicationOffsets();
  if(offsets.owner!=other.owner || offsets.membase!=other.membase) ++failures;
  // Clearing helper ownership must be undone by this invocation's publication.
  rvv_native_fault::Arm(nullptr);
  jitabi::trampoline_to_jit(t,mmu::base,code.data());
  if(t->gpr[6]!=0x123 || t->vec.vstart) ++failures;
  ucontext_t uc{};siginfo_t info{};auto const &site=runtime.sites[0];
  uc.uc_mcontext.gregs[REG_RIP]=(greg_t)((uptr)code.data()+site.code_offset);
  uc.uc_mcontext.gregs[REG_R13]=(greg_t)t;uc.uc_mcontext.gregs[REG_RAX]=t->gpr[5];
  uc.uc_mcontext.gregs[REG_RBP]=(greg_t)mmu::base;uc.uc_mcontext.gregs[REG_TRAPNO]=14;
  uc.uc_mcontext.gregs[REG_RDX]=1;uc.uc_mcontext.gregs[REG_ERR]=4;
  info.si_code=SEGV_ACCERR;info.si_addr=mmu::g2h(t->gpr[5]);
  // A different state cannot consume the freshly published owner.
  uc.uc_mcontext.gregs[REG_R13]=(greg_t)s;
  if(rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc)) ++failures;
  uc.uc_mcontext.gregs[REG_R13]=(greg_t)t;
  if(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc)) ++failures;
  if((uptr)uc.uc_mcontext.gregs[REG_RIP]!=(uptr)code.data()+site.cold_offset) ++failures;
  // The signal consumes ownership; a second delivery is rejected.
  uc.uc_mcontext.gregs[REG_RIP]=(greg_t)((uptr)code.data()+site.code_offset);
  if(rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc)) ++failures;
 });
 worker.join();check(!failures,"cross-thread emitted TLS publication and precise ownership");
 // Worker publication cannot arm the translator/main thread.
 ucontext_t uc{};siginfo_t info{};auto const &site=runtime.sites[0];
 uc.uc_mcontext.gregs[REG_RIP]=(greg_t)((uptr)code.data()+site.code_offset);
 uc.uc_mcontext.gregs[REG_R13]=(greg_t)s;uc.uc_mcontext.gregs[REG_RAX]=data+128;
 uc.uc_mcontext.gregs[REG_RBP]=(greg_t)mmu::base;uc.uc_mcontext.gregs[REG_TRAPNO]=14;
 uc.uc_mcontext.gregs[REG_RDX]=1;uc.uc_mcontext.gregs[REG_ERR]=4;
 info.si_code=SEGV_ACCERR;info.si_addr=mmu::g2h(data+128);
 check(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc),"publication remains thread local");
}
static void admission_equivalence(CPUState *s)
{
 // Retain the previous per-chunk predicate as a differential reference for
 // the page-granularity optimization, independently of emitted instructions.
 auto previous = [&](u32 raw) {
  if(!qcgstub_rv32_unit_memory_safe(s,raw))return false;
  u32 const base=s->gpr[5], bytes=s->vec.vl*(((raw>>12)&7)==6?4u:8u);
  u32 const chunk=std::min(s->vec.vlenb,u32(RVV_HOST_CHUNK_BITS/8));
  if(u64(base)+bytes>mmu::ASPACE_SIZE)return false;
  for(u32 off=0;off<bytes;off+=chunk) {
   u32 const active=std::min(chunk,bytes-off);
   if(((base+off)&(mmu::PAGE_SIZE-1))+active>mmu::PAGE_SIZE ||
      !((raw&0x7f)==0x27?mmu::page_native_copy_ram(base+off):mmu::page_ordinary_ram(base+off)))return false;
  }
  return true;
 };
 for(u32 width:{128u,256u,512u,1024u,2048u,4096u})for(u32 eew:{4u,8u})
 for(bool store:{false,true})for(int permission:{PROT_READ|PROT_WRITE,PROT_READ,PROT_NONE}) {
  check(mmu::mprotect(data,8192,permission)==0,"admission permission setup");
  config::vlen_bits=width;s->vec.Reset(width);s->vec.vtype=eew==4?16:24;
  u32 const max=width/(8*eew), raw=word(eew,store);
  u32 const chunk_for_test=std::min(width/8,u32(RVV_HOST_CHUNK_BITS/8));
  for(u32 vl:{0u,1u,max/2,max-1,max})for(u32 offset=0;offset<4096;++offset) {
   s->vec.vl=vl;s->gpr[5]=data+offset;
   bool const expected=previous(raw);
   check(bool(qcgstub_rv32_native_memory_safe(s,raw))==expected,"page and chunk admission agree");
   check(bool(qcgstub_rv32_native_memory_span(s,s->gpr[5],vl*eew,chunk_for_test,store))==expected,
         "specialized span and independent chunk admission agree");
  }
 }
 check(mmu::mprotect(data,8192,PROT_READ|PROT_WRITE)==0,"restore admission permissions");
 config::vlen_bits=1024;
}
// Exercise the same generated PC while live metadata changes. Compare complete
// destination/page state against the checked helper; include guest write-only
// mappings (host x86 permissions alone cannot enforce guest load permission).
static void single_page_metadata_cases(CPUState *s)
{
 auto const *table=mmu::NativeAccessPages();
 for(bool store:{false,true})for(bool partial:{false,true})for(u32 eew:{4u,8u}) {
  SiteRuntime runtime;runtime.relocate=false;MemArena arena(4u<<20);
  auto code=emit(runtime,arena,store,eew,partial);
  for(int permission:{PROT_READ|PROT_WRITE,PROT_NONE,PROT_WRITE,PROT_READ,PROT_READ|PROT_WRITE})
  for(u32 vl:{0u,1u,96/eew,128/eew})for(u32 offset:{128u,4096u-128u,4096u-eew}) {
   check(mmu::mprotect(data,8192,PROT_READ|PROT_WRITE)==0,"single page reset permission");
   std::array<u8,8192> input;input.fill(0x35);memcpy(mmu::g2h(data),input.data(),input.size());
   clear(s);s->vec.Reset(1024);s->vec.vtype=eew==4?16:24;s->vec.vl=vl;
   s->gpr[5]=data+offset;s->vec.vreg[8].fill(0x67);auto initial=s->vec;
   check(mmu::mprotect(data,8192,permission)==0,"single page live permission");
   u8 const expected_flags=((permission&PROT_READ)?1:0)|((permission&PROT_WRITE)?2:0);
   check(table==mmu::NativeAccessPages() && table[data>>12]==expected_flags &&
         table[(data>>12)+1]==expected_flags,"live stable directional access bytes");
   s->ip=pc+4;invoke(s,word(eew,store),store);
   auto expected=s->vec;auto expected_trap=s->trapno;auto expected_ip=s->ip;
   mmu::mprotect(data,8192,PROT_READ|PROT_WRITE);
   std::array<u8,8192> expected_mem;memcpy(expected_mem.data(),mmu::g2h(data),expected_mem.size());
   clear(s);s->vec=initial;s->gpr[6]=0;memcpy(mmu::g2h(data),input.data(),input.size());
   mmu::mprotect(data,8192,permission);
   if(sigsetjmp(trap_unwind_env,0)==0)jitabi::trampoline_to_jit(s,mmu::base,code.data());
   check(s->vec.vreg==expected.vreg && s->vec.vstart==expected.vstart &&
         s->trapno==expected_trap && s->ip==expected_ip && s->gpr[6]==0x123,
         "single page emitted guard complete helper semantics");
   mmu::mprotect(data,8192,PROT_READ|PROT_WRITE);
   check(!memcmp(mmu::g2h(data),expected_mem.data(),expected_mem.size()),"single page complete memory");
  }
 }
 // Remapping and unmapping update the same stable table; mprotect must not
 // change its anonymous identity or enable file stores.
 FILE *file=tmpfile();check(file && ftruncate(fileno(file),8192)==0,"metadata file setup");
 check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED,fileno(file),0)!=MAP_FAILED,
       "metadata anonymous to file remap");
 check(table[data>>12]==1 && table[(data>>12)+1]==1 && !mmu::page_native_copy_ram(data),"file load capability without anonymous identity or store capability");
 check(mmu::mprotect(data,8192,PROT_READ|PROT_WRITE)==0 && table[data>>12]==1,"file protect retains load-only capability");
 check(mmu::munmap(data,8192)==0 && table[data>>12]==0 && table[(data>>12)+1]==0,"unmap clears live flags");
 check(mmu::mmap(data,8192,PROT_WRITE)!=MAP_FAILED && table[data>>12]==2,"anonymous remap preserves write only");
 check(mmu::mprotect(data,8192,PROT_READ|PROT_WRITE)==0 && table[data>>12]==3,"restore native access flags");
 fclose(file);
}
// Execute both sides of the static maximum-span proof with exact partial
// work, live directional permissions and backing changes at the same JIT PC.
// The expected result is byte-derived; no admission predicate supplies it.
static void maximum_span_boundary_cases(CPUState *s)
{
 for(bool store:{false,true})for(u32 eew:{4u,8u}) {
  SiteRuntime runtime;runtime.relocate=false;MemArena arena(4u<<20);
  auto code=emit(runtime,arena,store,eew,true);
  FILE *file=tmpfile();check(file && !ftruncate(fileno(file),8192),"boundary file setup");
  for(bool file_backed:{false,true,false}) {
   check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED|
         (file_backed?0:MAP_ANONYMOUS),file_backed?fileno(file):-1,0)!=MAP_FAILED,"same-PC backing transition");
   for(u32 offset:{3967u,3968u,3969u,4032u,4096u-eew})
   for(u32 vl:{0u,1u,64u/eew,96u/eew,128u/eew})
   for(int permission:{PROT_NONE,PROT_READ,PROT_WRITE,PROT_READ|PROT_WRITE}) {
    check(!mmu::mprotect(data,8192,PROT_READ|PROT_WRITE),"boundary reset permissions");
    std::array<u8,8192> input;for(u32 b=0;b<input.size();++b)input[b]=(u8)(b*17+9);
    memcpy(mmu::g2h(data),input.data(),input.size());
    clear(s);s->vec.Reset(1024);s->vec.vtype=eew==4?16:24;s->vec.vl=vl;
    s->gpr[5]=data+offset;s->vec.vreg[8].fill(0x67);s->gpr[6]=0;
    check(!mmu::mprotect(data+4096,4096,permission),"boundary live directional permission");
    u32 completed=0;
    for(;completed<vl;++completed) {
     u32 end=offset+(completed+1)*eew;
     if(end>4096 && !(permission&(store?PROT_WRITE:PROT_READ)))break;
    }
    if(sigsetjmp(trap_unwind_env,0)==0)jitabi::trampoline_to_jit(s,mmu::base,code.data());
    bool fault=completed<vl;
    check(s->trapno==(fault?rv32::TrapCode::MEMORY_FAULT:rv32::TrapCode::NONE) &&
          s->vec.vstart==(fault?completed:0u) && s->vec.vl==vl &&
          s->gpr[6]==0x123 && s->ip==(fault?pc+4:pc+8),"byte-derived boundary frontier and prior scalar state");
    for(u32 b=0;b<128;++b)
     check(s->vec.vreg[8][b]==(!store && b<completed*eew?input[offset+b]:0x67),"byte-derived boundary destination and tail");
    check(!mmu::mprotect(data,8192,PROT_READ|PROT_WRITE),"boundary inspect complete memory");
    auto *memory=(u8*)mmu::g2h(data);
    for(u32 b=0;b<input.size();++b)
     check(memory[b]==(store && b>=offset && b<offset+completed*eew?0x67:input[b]),"byte-derived boundary memory and untouched bytes");
   }
  }
  fclose(file);
 }
 check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE)!=MAP_FAILED,"restore boundary anonymous mapping");
}
static void guarded_span_cases(CPUState *s)
{
 for(bool store:{false,true})for(bool partial:{false,true}) {
  SiteRuntime runtime;runtime.relocate=false;MemArena arena(4u<<20);
  auto code=emit(runtime,arena,store,4,partial);
  // Compare actual emitted guard misses against the existing element helper.
  for(unsigned mismatch=0;mismatch<6;++mismatch) {
   mmu::mprotect(data,8192,PROT_READ|PROT_WRITE);
   clear(s);s->vec.Reset(1024);s->vec.vtype=16;s->vec.vl=32;s->gpr[5]=data+128;
   s->vec.vreg[8].fill(0x67);
   if(mismatch==0)s->vec.vlenb=64;
   if(mismatch==1)s->vec.vtype=16|0xc0;
   if(mismatch==2)s->vec.vstart=1;
   if(mismatch==3)s->vec.vl=33;
   if(mismatch==4)s->vec.vtype=0x80000010;
   if(mismatch==5)s->gpr[5]=0xfffffffcu;
   auto initial=s->vec;
   std::array<u8,8192> input;input.fill(0x35);memcpy(mmu::g2h(data),input.data(),input.size());
   s->ip=pc+4;invoke(s,word(4,store),store);
   auto expected=s->vec;auto expected_trap=s->trapno;auto expected_ip=s->ip;
   std::array<u8,8192> expected_mem;memcpy(expected_mem.data(),mmu::g2h(data),expected_mem.size());
   clear(s);s->vec=initial;s->gpr[6]=0;memcpy(mmu::g2h(data),input.data(),input.size());
   rvv_native_fault::Arm(nullptr);
   if(sigsetjmp(trap_unwind_env,0)==0)jitabi::trampoline_to_jit(s,mmu::base,code.data());
   check(s->vec.vreg==expected.vreg && s->vec.vstart==expected.vstart &&
         s->trapno==expected_trap && s->ip==expected_ip && s->gpr[6]==0x123,
         "mismatched geometry preserves helper semantics and prior scalar state");
   check(!memcmp(mmu::g2h(data),expected_mem.data(),expected_mem.size()),"guard miss complete memory");
   ucontext_t uc{};siginfo_t info{};auto const &site=runtime.sites[0];
   uc.uc_mcontext.gregs[REG_RIP]=(greg_t)((uptr)code.data()+site.code_offset);
   uc.uc_mcontext.gregs[REG_R13]=(greg_t)s;uc.uc_mcontext.gregs[REG_RAX]=s->gpr[5];
   uc.uc_mcontext.gregs[REG_RBP]=(greg_t)mmu::base;uc.uc_mcontext.gregs[REG_TRAPNO]=14;
   uc.uc_mcontext.gregs[REG_ERR]=store?6:4;info.si_code=SEGV_ACCERR;info.si_addr=mmu::g2h(s->gpr[5]);
   check(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc),"guard miss never arms native span ownership");
  }
  // Mixed page permissions must be rechecked on each invocation, including
  // stores to host-readable write-only mappings and zero-length partial bodies.
  for(int permission:{PROT_NONE,PROT_READ,PROT_WRITE,PROT_READ|PROT_WRITE})for(u32 vl:{0u,16u,24u,32u}) {
   mmu::mprotect(data,8192,PROT_READ|PROT_WRITE);
   clear(s);s->vec.Reset(1024);s->vec.vtype=16;s->vec.vl=vl;s->gpr[5]=data+4096-64;
   s->vec.vreg[8].fill(0x67);
   std::array<u8,8192> input;input.fill(0x35);memcpy(mmu::g2h(data),input.data(),input.size());
   mmu::mprotect(data+4096,4096,permission);
   auto initial=s->vec;s->ip=pc+4;invoke(s,word(4,store),store);
   auto expected=s->vec;auto expected_trap=s->trapno;auto expected_ip=s->ip;
   mmu::mprotect(data+4096,4096,PROT_READ|PROT_WRITE);
   std::array<u8,8192> expected_mem;memcpy(expected_mem.data(),mmu::g2h(data),expected_mem.size());
   clear(s);s->vec=initial;s->gpr[6]=0;memcpy(mmu::g2h(data),input.data(),input.size());
   mmu::mprotect(data+4096,4096,permission);
   if(sigsetjmp(trap_unwind_env,0)==0)jitabi::trampoline_to_jit(s,mmu::base,code.data());
   check(s->vec.vreg==expected.vreg && s->vec.vstart==expected.vstart &&
         s->trapno==expected_trap && s->ip==expected_ip && s->gpr[6]==0x123,
         "mixed permission and zero-length emitted behavior agrees with helper");
   mmu::mprotect(data+4096,4096,PROT_READ|PROT_WRITE);
   check(!memcmp(mmu::g2h(data),expected_mem.data(),expected_mem.size()),"mixed permission complete memory");
   if(expected_trap==rv32::TrapCode::MEMORY_FAULT) {
    // Repair the denied mapping, then re-enter the same emitted instruction
    // with the published vstart. Its guard must select the restartable helper.
    check(s->vec.vstart==16,"mixed permission publishes completed first page");
    clear(s);
    if(sigsetjmp(trap_unwind_env,0)==0)jitabi::trampoline_to_jit(s,mmu::base,code.data());
    check(s->trapno==rv32::TrapCode::NONE && !s->vec.vstart && s->ip==pc+8,
          "same-PC retry after mapping repair completes through restart guard");
    for(u32 i=0;i<128;++i)check(s->vec.vreg[8][i]==(!store && i<vl*4?0x35:0x67),
          "restart destination and untouched tail");
    auto *memory=(u8*)mmu::g2h(data);
    for(u32 i=0;i<8192;++i)check(memory[i]==(store && i>=4032 && i<4032+vl*4?0x67:0x35),
          "restart complete memory");
   }
  }
 }
}
// Compare the proven producer edge with the original handler, retaining byte
// expectations and both real SIGBUS and permission-denial fault coordinates.
static void checked_contract_cases(CPUState *s)
{
 struct sigaction saved_segv{},saved_bus{},sa{};
 sa.sa_sigaction=recover_once;sa.sa_flags=SA_SIGINFO;sigfillset(&sa.sa_mask);
 sigaction(SIGSEGV,&sa,&saved_segv);sigaction(SIGBUS,&sa,&saved_bus);
 for(bool store:{false,true})for(u32 eew:{4u,8u}) {
  SiteRuntime runtime;runtime.relocate=false;MemArena arena(4u<<20);
  auto code=emit(runtime,arena,store,eew,true);
  FILE *file=tmpfile();check(file,"contract file");
  for(unsigned mode:{0u,1u,2u})for(u32 vl:{0u,1u,96/eew,128/eew}) {
   std::array<u8,8192> input;
   for(u32 b=0;b<input.size();++b)input[b]=(u8)(b*13+9);
   rv32::VectorState initial;initial.Reset(1024);initial.vtype=eew==4?16:24;initial.vl=vl;
   for(auto &reg:initial.vreg)reg.fill(0x67);
   rv32::VectorState reference;
   MemoryFaultEvent reference_event{};rv32::TrapCode reference_trap{};u32 reference_ip=0;
   std::array<u8,8192> reference_memory;
   for(bool emitted:{false,true}) {
    check(!ftruncate(fileno(file),8192),"contract reset file length");
    check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED,fileno(file),0)!=MAP_FAILED,"contract same-PC file mapping");
    memcpy(mmu::g2h(data),input.data(),input.size());
    clear(s);s->vec=initial;s->gpr[5]=data+4032;s->gpr[6]=0;s->ip=pc+4;caught=0;
    // mode0 permitted file; mode1 live protection; mode2 actual truncation.
    if(mode==1)check(!mmu::mprotect(data+4096,4096,PROT_NONE),"contract protected second page");
    if(mode==2)check(!ftruncate(fileno(file),4096),"contract truncate second page");
    if(emitted) {
     if(sigsetjmp(trap_unwind_env,0)==0)jitabi::trampoline_to_jit(s,mmu::base,code.data());
    } else invoke(s,word(eew,store),store);
    u32 const completed=mode && vl>64/eew?64/eew:vl;
    bool const fault=completed<vl;
    check(s->trapno==(fault?rv32::TrapCode::MEMORY_FAULT:rv32::TrapCode::NONE) &&
          s->vec.vstart==(fault?completed:0) && s->ip==(fault?pc+4:pc+8),"contract independently derived frontier/PC");
    check(caught==(fault && mode==2?1u:0u),"contract real SIGBUS count");
    auto event=fault?ukernel::CaptureHelperMemoryFault(s).event:MemoryFaultEvent{};
    if(!emitted){reference=s->vec;reference_trap=s->trapno;reference_ip=s->ip;reference_event=event;}
    else {
     check(s->vec.vreg==reference.vreg && s->vec.vl==reference.vl && s->vec.vtype==reference.vtype &&
           s->vec.vstart==reference.vstart && s->trapno==reference_trap && s->ip==reference_ip &&
           s->gpr[6]==0x123,"contract complete differential state");
     if(fault)check(event.pc==reference_event.pc && event.raw==reference_event.raw &&
        event.address==reference_event.address && event.element==reference_event.element &&
        event.origin==(!store && mode==2?MemoryFaultEvent::Origin::NativeUnit:reference_event.origin) && event.reason==reference_event.reason &&
        event.host_signal==reference_event.host_signal && event.host_code==reference_event.host_code &&
        event.eew_bytes==reference_event.eew_bytes && event.nf==reference_event.nf && event.field==reference_event.field,
        "contract exact fault ownership and coordinates");
    }
    for(u32 b=0;b<rv32::VLEN_MAX_BYTES;++b)
     check(s->vec.vreg[8][b]==(!store && b<completed*eew?input[4032+b]:0x67),"contract independent vector and tail bytes");
    check(!ftruncate(fileno(file),8192) && !mmu::mprotect(data,8192,PROT_READ|PROT_WRITE),"contract repair before inspection/restart");
    // A truncated private second page is recreated as zero; bytes in the
    // accessible prefix and outside the transfer remain independently checked.
    auto *memory=(u8*)mmu::g2h(data);
    for(u32 b=0;b<(mode==2?4096u:8192u);++b)
     check(memory[b]==(store && b>=4032 && b<4032+completed*eew?0x67:input[b]),"contract independent memory prefix and untouched bytes");
    if(!emitted)memcpy(reference_memory.data(),memory,8192);
    else check(!memcmp(memory,reference_memory.data(),8192),"contract complete differential page bytes");
    if(emitted && fault) {
     // Preserve published vstart, repair input suffix and enter the same PC.
     memcpy(memory+4096,input.data()+4096,4096);clear(s);caught=0;
     if(sigsetjmp(trap_unwind_env,0)==0)jitabi::trampoline_to_jit(s,mmu::base,code.data());
     check(!caught && s->trapno==rv32::TrapCode::NONE && !s->vec.vstart && s->ip==pc+8,"contract same-PC repaired restart");
     for(u32 b=0;b<rv32::VLEN_MAX_BYTES;++b)
      check(s->vec.vreg[8][b]==(!store && b<vl*eew?input[4032+b]:0x67),"contract restart full vector/tail");
     for(u32 b=0;b<8192;++b)
      check(memory[b]==(store && b>=4032 && b<4032+vl*eew?0x67:input[b]),"contract restart all page bytes");
     printf("CHECKED_CONTRACT_RESTART store=%d eew=%u mode=%u vl=%u PASS\n",store,eew,mode,vl);
    }
   }
  }
  fclose(file);
 }
 sigaction(SIGSEGV,&saved_segv,nullptr);sigaction(SIGBUS,&saved_bus,nullptr);
 check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE)!=MAP_FAILED,"contract restore anonymous mapping");
}
// Real truncation at full and partial owned load PCs, including the first
// chunk and a later chunk after one already-published prefix. No helper oracle.
static void file_chunk_cases(CPUState *s)
{
 struct sigaction old_segv{},old_bus{},sa{};
 sa.sa_sigaction=recover_once;sa.sa_flags=SA_SIGINFO;sigfillset(&sa.sa_mask);
 sigaction(SIGSEGV,&sa,&old_segv);sigaction(SIGBUS,&sa,&old_bus);
 for(int backing:{MAP_PRIVATE,MAP_SHARED})for(u32 eew:{4u,8u})
 for(bool partial:{false,true})for(bool first:{false,true}) {
  SiteRuntime runtime;runtime.relocate=false;MemArena arena(4u<<20);
  auto code=emit(runtime,arena,false,eew,partial);
  FILE *file=tmpfile();check(file && !ftruncate(fileno(file),8192),"chunk file create");
  std::array<u8,8192> input;
  for(u32 b=0;b<input.size();++b)input[b]=(u8)(b*19+23);
  check(pwrite(fileno(file),input.data(),input.size(),0)==(ssize_t)input.size(),"independent file bytes");
  check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE,backing|MAP_FIXED,fileno(file),0)!=MAP_FAILED,"chunk regular backing");
  // Include dirty private COW pages, as in the established ELF BSS mapping.
  memcpy(mmu::g2h(data),input.data(),input.size());
  clear(s);s->vec.Reset(1024);s->vec.vtype=eew==4?16:24;
  s->vec.vl=(partial?96:128)/eew;s->vec.vxrm=3;s->vec.vxsat=1;s->fpu.fcsr=0x50;
  for(u32 r=0;r<32;++r)for(u32 b=0;b<rv32::VLEN_MAX_BYTES;++b)s->vec.vreg[r][b]=(u8)(r*7+b*3);
  auto initial=s->vec;s->gpr[5]=data+4096-(first?0:64);s->gpr[6]=0;
  u32 const offset=s->gpr[5]-data, prefix=first?0:64, active=s->vec.vl*eew;
  check(qcgstub_rv32_native_memory_safe(s,word(eew,false))==1,"file load admitted");
  check(qcgstub_rv32_native_memory_safe(s,word(eew,true))==0,"file SIMD store remains excluded");
  check(!ftruncate(fileno(file),4096),"actual truncate including private COW page");
  caught=0;
  if(sigsetjmp(trap_unwind_env,0)==0)jitabi::trampoline_to_jit(s,mmu::base,code.data());
  check(caught==1 && s->trapno==rv32::TrapCode::MEMORY_FAULT,"one real chunk SIGBUS");
  auto snap=ukernel::CaptureHelperMemoryFault(s);auto const &ev=snap.event;
  check(ev.origin==MemoryFaultEvent::Origin::NativeUnit && ev.host_signal==SIGBUS && ev.host_code==BUS_ADRERR &&
        ev.access==MemoryFaultEvent::Access::Load && ev.pc==pc+4 && ev.raw==word(eew,false) &&
        ev.address==data+4096 && ev.element==prefix/eew && ev.eew_bytes==eew && ev.nf==1 && !ev.field,
        "exact chunk BUS ownership raw PC address frontier");
  check(s->vec.vstart==prefix/eew && s->vec.vl==initial.vl && s->vec.vtype==initial.vtype &&
        s->vec.vlenb==initial.vlenb && s->vec.vxrm==3 && s->vec.vxsat==1 && s->ip==pc+4 && s->gpr[6]==0x123,
        "independent CSR frontier prior scalar state");
  check(snap.csrs[0]==16 && snap.csrs[1]==2 && snap.csrs[2]==0x50 && snap.csrs[3]==prefix/eew &&
        snap.csrs[4]==1 && snap.csrs[5]==3 && snap.csrs[6]==7 && snap.csrs[7]==initial.vl &&
        snap.csrs[8]==initial.vtype && snap.csrs[9]==initial.vlenb,"all snapshot architectural CSRs independently expected");
  for(u32 r=0;r<32;++r)for(u32 b=0;b<rv32::VLEN_MAX_BYTES;++b)
   check(s->vec.vreg[r][b]==(r==8 && b<prefix?input[offset+b]:initial.vreg[r][b]),"all vector bytes committed prefix and untouched chunk");
  for(u32 b=0;b<4096;++b)check(((u8*)mmu::g2h(data))[b]==input[b],"all surviving memory bytes untouched");
  // Repair without changing the generated PC; vstart requires checked restart
  // for the later fault, and first-chunk retry may run the native load again.
  check(!ftruncate(fileno(file),8192),"repair file size");
  check(pwrite(fileno(file),input.data()+4096,4096,4096)==4096,"repair independent suffix");
  clear(s);caught=0;
  if(sigsetjmp(trap_unwind_env,0)==0)jitabi::trampoline_to_jit(s,mmu::base,code.data());
  check(!caught && s->trapno==rv32::TrapCode::NONE && !s->vec.vstart && s->ip==pc+8 &&
        s->vec.vl==initial.vl && s->vec.vtype==initial.vtype && s->vec.vlenb==initial.vlenb &&
        s->vec.vxrm==3 && s->vec.vxsat==1 && s->fpu.fcsr==0x50,"same PC repaired restart CSRs");
  for(u32 r=0;r<32;++r)for(u32 b=0;b<rv32::VLEN_MAX_BYTES;++b)
   check(s->vec.vreg[r][b]==(r==8 && b<active?input[offset+b]:initial.vreg[r][b]),"same PC all vector bytes independent");
  for(u32 b=0;b<8192;++b)check(((u8*)mmu::g2h(data))[b]==input[b],"same PC full memory untouched");
  // Actual host SIGSEGV behind unchanged guest metadata exercises the same
  // file-load ownership, independently of predictable guest permission denial.
  clear(s);s->vec=initial;caught=0;
  check(!::mprotect(mmu::g2h(data+4096),4096,PROT_NONE),"raw file host protection");
  if(sigsetjmp(trap_unwind_env,0)==0)jitabi::trampoline_to_jit(s,mmu::base,code.data());
  auto segv=ukernel::CaptureHelperMemoryFault(s);
  check(caught==1 && segv.event.origin==MemoryFaultEvent::Origin::NativeUnit && segv.event.host_signal==SIGSEGV &&
        segv.event.host_code==SEGV_ACCERR && segv.event.raw==word(eew,false) && segv.event.pc==pc+4 &&
        segv.event.address==data+4096 && segv.event.element==prefix/eew && s->vec.vstart==prefix/eew,
        "actual file SIGSEGV exact ownership and prefix");
  for(u32 r=0;r<32;++r)for(u32 b=0;b<rv32::VLEN_MAX_BYTES;++b)
   check(s->vec.vreg[r][b]==(r==8 && b<prefix?input[offset+b]:initial.vreg[r][b]),"SEGV full vector prefix independently expected");
  check(!::mprotect(mmu::g2h(data+4096),4096,PROT_READ|PROT_WRITE),"raw host repair");
  for(u32 b=0;b<8192;++b)check(((u8*)mmu::g2h(data))[b]==input[b],"SEGV all memory untouched");
  clear(s);caught=0;
  if(sigsetjmp(trap_unwind_env,0)==0)jitabi::trampoline_to_jit(s,mmu::base,code.data());
  check(!caught && s->trapno==rv32::TrapCode::NONE && !s->vec.vstart && s->ip==pc+8 && s->fpu.fcsr==0x50,
        "SEGV same PC repaired restart");
  // Zero VL on fully truncated backing must neither access nor fault.
  check(!ftruncate(fileno(file),0),"truncate all for zero work");
  clear(s);s->vec=initial;s->vec.vl=0;caught=0;
  if(sigsetjmp(trap_unwind_env,0)==0)jitabi::trampoline_to_jit(s,mmu::base,code.data());
  check(!caught && s->trapno==rv32::TrapCode::NONE && s->vec.vreg==initial.vreg && !s->vec.vstart,"zero active mask no backing access");
  // Adversarial callback frames: rejection must precede consuming ownership.
  auto const &site=runtime.sites[0];ucontext_t uc{};siginfo_t info{};
  uc.uc_mcontext.gregs[REG_RIP]=(greg_t)((uptr)code.data()+site.code_offset);
  uc.uc_mcontext.gregs[REG_R13]=(greg_t)s;uc.uc_mcontext.gregs[REG_RAX]=data+128;
  uc.uc_mcontext.gregs[REG_RBP]=(greg_t)mmu::base;uc.uc_mcontext.gregs[REG_TRAPNO]=14;
  uc.uc_mcontext.gregs[REG_ERR]=4;uc.uc_mcontext.gregs[REG_RDX]=1;
  info.si_addr=mmu::g2h(data+128+site.displacement);info.si_code=BUS_ADRERR;
  rvv_native_fault::Arm(s);
  ++uc.uc_mcontext.gregs[REG_RIP];check(!rvv_native_fault::HandleSignal(SIGBUS,&info,&uc),"BUS interior PC rejected");--uc.uc_mcontext.gregs[REG_RIP];
  uc.uc_mcontext.gregs[REG_ERR]=6;check(!rvv_native_fault::HandleSignal(SIGBUS,&info,&uc),"BUS wrong direction rejected");uc.uc_mcontext.gregs[REG_ERR]=4;
  uc.uc_mcontext.gregs[REG_TRAPNO]=13;check(!rvv_native_fault::HandleSignal(SIGBUS,&info,&uc),"BUS non PF rejected");uc.uc_mcontext.gregs[REG_TRAPNO]=14;
  for(int code:std::array<int,5>{SI_USER,SI_TKILL,BUS_ADRALN,BUS_MCEERR_AR,BUS_MCEERR_AO}) {info.si_code=code;check(!rvv_native_fault::HandleSignal(SIGBUS,&info,&uc),"unsupported BUS code rejected");}
  info.si_code=BUS_ADRERR;info.si_addr=mmu::g2h(data+128+site.displacement+64);
  check(!rvv_native_fault::HandleSignal(SIGBUS,&info,&uc),"BUS unrelated footprint rejected");
  if(site.mask_reg==7) {
   info.si_addr=mmu::g2h(data+128+site.displacement);uc.uc_mcontext.gregs[REG_RDX]=0;
   check(!rvv_native_fault::HandleSignal(SIGBUS,&info,&uc),"BUS zero mask rejected");
   uc.uc_mcontext.gregs[REG_RDX]=5;check(!rvv_native_fault::HandleSignal(SIGBUS,&info,&uc),"BUS noncontiguous mask rejected");
  }
  rvv_native_fault::Arm(nullptr);
  printf("FILE_CHUNK_SIGBUS backing=%d eew=%u partial=%d first=%d prefix=%u resume_same_PC=PASS all_vector_memory_CSR=PASS\n",backing,eew,partial,first,prefix);
  fclose(file);
 }
 sigaction(SIGSEGV,&old_segv,nullptr);sigaction(SIGBUS,&old_bus,nullptr);
 check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE)!=MAP_FAILED,"restore anonymous after file chunks");
}

// Inline setup dominance, checked-helper joins, CSR/runtime-setup barriers and
// branch entries. Expectations use byte coordinates and the architectural min;
// no admission result or DUT vector helper supplies expected data.
static void config_reuse_sequences(CPUState *s)
{
 config::vlen_bits=1024;config::rvv_qcg_partial_vl=true;config::rvv_qcg_typed_chunk_falu=true;config::rvv_qcg_direct_setvl=true;config::rvv_qcg_typed_chunk=true;
 config::rvv_qcg_typed_chunk_vle=true;config::rvv_qcg_typed_chunk_vse=true;
 config::rvv_qcg_typed_chunk_mem_e64=true;config::aot_use_llvm=false;
 config::rvv_verify=false;config::rvv_direct=true;config::rvv_lowering=1;
 auto setup=[](u32 vt) {return (vt<<20)|(10u<<15)|(7u<<12)|(7u<<7)|0x57u;};
 for(unsigned mode=0;mode<9;++mode) {
  SiteRuntime runtime;runtime.relocate=false;MemArena arena(4u<<20);
  std::vector<u32> words;
  if(mode!=5)words.push_back(setup(16));
  words.push_back(word(4,false));
  if(mode==1)words.push_back((8u<<20)|(11u<<15)|(1u<<12)|0x73u); // csrw vstart,x11
  if(mode==2)words.push_back((0x40u<<25)|(12u<<20)|(10u<<15)|(7u<<12)|(7u<<7)|0x57u); // vsetvl x7,x10,x12
  if(mode==3) {words.push_back((11u<<15)|(4u<<8)|0x63u);words.push_back(setup(24));} // beq x11,x0,+8
  if(mode==5)words.push_back((1u<<25)|(8u<<20)|(8u<<15)|(10u<<7)|0x57u); // live-SEW vadd.vv on reentry
  if(mode==6) {
   words.push_back((1u<<20)|(11u<<15)|(1u<<12)|(13u<<7)|0x13u); // slli x13,x11,1
   words.push_back((1u<<25)|(8u<<20)|(8u<<15)|(10u<<7)|0x57u); // vadd.vv
  }
  if(mode==7)words.push_back((0x24u<<26)|(1u<<25)|(1u<<12)|(10u<<7)|0x57u); // vfmul.vv v10,v0,v0
  if(mode==4)words.push_back((16u<<20)|(7u<<12)|0x57u); // keep-VL form
  words.push_back((word(4,false)&~(31u<<7))|(9u<<7));
  CompilerJob job(&runtime,(uptr)words.data()-pc,CodeSegment(pc,4096),{{pc,pc+u32(words.size()*4)}},RvvEntryHint{16,true});
  auto *region=CompilerGenRegionIR(&arena,job);
  if(mode==8) {
   // Exercise the supported legacy/non-owned partial memory contract. It
   // consumes VL flags to select the partial body and must keep its guard.
   bool changed=false;
   for(auto &block:region->GetBlocks())for(auto &node:block.ilist) {
    if(!changed && node.GetOpcode()==Op::_rvvtypedchunkbegin) {
     auto *frame=static_cast<InstRVVTypedChunkBegin *>(&node);
     check(frame->guard_kind==InstRVVTypedChunkBegin::GuardKind::VTypeVlOrPartialVstartBaseLimit,"legacy split fixture uses actual partial body");
     frame->native_memory_pc=RVVRunMember::PC_UNUSED;changed=true;
    }
   }
   check(changed,"legacy split frame selected");
  }
  // Retain production region exits, including branch continuations.
  auto code=qcg::GenerateCode(&runtime,&job.segment,region,pc);
  FILE *out=fopen(("config-reuse-mode"+std::to_string(mode)+".bin").c_str(),"wb");
  check(out && fwrite(code.data(),1,code.size(),out)==code.size(),"config sequence emitted bytes");fclose(out);
  check(code.data()[0]==0x51,"config sequence nonleaf");
  for(u32 avl:{0u,1u,7u,32u,33u,0xffffffffu})for(bool crossing:{false,true})for(u32 selector:{0u,3u}) {
   check(!mmu::mprotect(data,8192,PROT_READ|PROT_WRITE),"config sequence live mapping");
   auto *mem=(u8*)mmu::g2h(data);for(u32 b=0;b<8192;++b)mem[b]=u8(7*b+19);
   clear(s);s->vec.Reset(1024);s->vec.vtype=selector?24:16;s->vec.vl=mode==5?7:3;
   s->vec.vlenb=mode==5?128:64;s->vec.vstart=mode==5?selector:9;
   s->gpr[5]=data+(crossing?4092:128);s->gpr[10]=avl;s->gpr[11]=selector;s->gpr[12]=24;
   s->vec.vreg[8].fill(0x67);s->vec.vreg[9].fill(0x67);
   s->vec.vreg[0].fill(0);s->vec.vreg[10].fill(0x67);s->fpu.fcsr=mode==7?(4u<<5):0;
   u32 vl1=mode==5?7:std::min(avl,32u), start1=mode==5?selector:0;
   u32 vl2=mode==2 || (mode==3 && selector)?std::min(avl,16u):vl1;
   u32 start2=mode==1?selector:0;
   std::array<u8,128> sum_expected;sum_expected.fill(0x67);
   if(mode==5 || mode==6) {
    u32 sew=mode==5 && selector?8u:4u,offset=s->gpr[5]-data;
    for(u32 e=0;e<vl1;++e) {
     u64 value=0;
     for(u32 b=0;b<sew;++b) {
      u32 i=e*sew+b;
      u8 byte=i>=start1*4 && i<vl1*4?u8(7*(offset+i)+19):0x67;
      value|=u64(byte)<<(8*b);
     }
     u64 sum=value+value;
     for(u32 b=0;b<sew;++b)sum_expected[e*sew+b]=u8(sum>>(8*b));
    }
   }
   printf("CONFIG_CASE mode=%u avl=%u crossing=%d selector=%u\n",mode,avl,crossing,selector);fflush(stdout);
   jitabi::trampoline_to_jit(s,mmu::base,code.data());
   // A conditional guest exit may end the first region. Dispatch its actual
   // continuation with a fresh, independently guarded region (same entry hint).
   for(unsigned step=0;s->ip<pc+words.size()*4 && step<4;++step) {
    SiteRuntime continuation;continuation.relocate=false;MemArena next_arena(4u<<20);
    CompilerJob next_job(&continuation,(uptr)words.data()-pc,CodeSegment(pc,4096),{{s->ip,pc+u32(words.size()*4)}},RvvEntryHint{16,true});
    auto *next_region=CompilerGenRegionIR(&next_arena,next_job);
    auto next_code=qcg::GenerateCode(&continuation,&next_job.segment,next_region,s->ip);
    jitabi::trampoline_to_jit(s,mmu::base,next_code.data());
   }
   check(s->ip==pc+words.size()*4,"config sequence dispatcher reaches interval end");
   check(s->trapno==rv32::TrapCode::NONE && !s->vec.vstart,"config sequence completion/vstart");
   check(s->vec.vl==vl2 && s->vec.vtype==((mode==2 || (mode==3 && selector) || (mode==5 && selector))?24u:16u) && s->vec.vlenb==128,"config sequence exact live geometry");
   check(s->fpu.fcsr==(mode==7?(4u<<5):0u),"config sequence live rounding and exact zero-product flags");
   for(u32 b=0;b<128;++b) {
    u32 offset=s->gpr[5]-data;
    check(s->vec.vreg[8][b]==(b>=start1*4 && b<vl1*4?u8(7*(offset+b)+19):0x67),"config sequence first load bytes/tail/prestart");
    check(s->vec.vreg[9][b]==(b>=start2*4 && b<vl2*4?u8(7*(offset+b)+19):0x67),"config sequence second load bytes/tail/prestart");
    if(mode==5 || mode==6)check(s->vec.vreg[10][b]==sum_expected[b],"config sequence live-SEW independent integer sum");
    if(mode==7)check(s->vec.vreg[10][b]==(b<vl1*4?0:0x67),"config sequence RMM helper independent zero product");
   }
  }
 }
 printf("CONFIG_REUSE_SEQUENCES_PASS modes=9 invocations=216 inline_setup_checked_join_CSR_runtime_setup_branch_keepVL_reentry=PASS\n");
}

static void config_reuse_fault_restart(CPUState *s)
{
 std::vector<u32> words={(16u<<20)|(10u<<15)|(7u<<12)|(7u<<7)|0x57u,
     word(4,false), (128u<<20)|(5u<<15)|(5u<<7)|0x13u,
     (word(4,false)&~(31u<<7))|(9u<<7)};
 SiteRuntime rt;rt.relocate=false;MemArena arena(4u<<20);
 CompilerJob job(&rt,(uptr)words.data()-pc,CodeSegment(pc,4096),{{pc,pc+16}},RvvEntryHint{16,true});
 auto *region=CompilerGenRegionIR(&arena,job);
 auto code=qcg::GenerateCode(&rt,&job.segment,region,pc);
 check(!mmu::mprotect(data,8192,PROT_READ|PROT_WRITE),"reuse restart map");
 auto *mem=(u8*)mmu::g2h(data);for(u32 b=0;b<8192;++b)mem[b]=u8(13*b+5);
 clear(s);s->vec.Reset(1024);s->vec.vtype=24;s->vec.vl=1;s->vec.vstart=17;
 s->gpr[5]=data+3964;s->gpr[10]=32;s->vec.vreg[8].fill(0x67);s->vec.vreg[9].fill(0x67);
 check(!mmu::mprotect(data+4096,4096,PROT_NONE),"reuse restart denial");
 if(sigsetjmp(trap_unwind_env,0)==0)jitabi::trampoline_to_jit(s,mmu::base,code.data());
 auto snap=ukernel::CaptureHelperMemoryFault(s);
 check(s->trapno==rv32::TrapCode::MEMORY_FAULT && s->ip==pc+12 && s->vec.vstart==1 &&
       snap.event.pc==pc+12 && snap.event.element==1 && snap.event.address==data+4096,
       "reuse second instruction exact fault ownership/frontier");
 for(u32 b=0;b<128;++b) {
  check(s->vec.vreg[8][b]==u8(13*(3964+b)+5),"reuse older instruction fully published");
  check(s->vec.vreg[9][b]==(b<4?u8(13*(4092+b)+5):0x67),"reuse fault prefix and untouched suffix");
 }
 check(!mmu::mprotect(data+4096,4096,PROT_READ|PROT_WRITE),"reuse restart repair");
 SiteRuntime resumed;resumed.relocate=false;MemArena resume_arena(4u<<20);
 CompilerJob resume_job(&resumed,(uptr)words.data()-pc,CodeSegment(pc,4096),{{pc+12,pc+16}},RvvEntryHint{16,true});
 auto *resume_region=CompilerGenRegionIR(&resume_arena,resume_job);
 auto resume_code=qcg::GenerateCode(&resumed,&resume_job.segment,resume_region,pc+12);
 clear(s);s->ip=pc+12;
 if(sigsetjmp(trap_unwind_env,0)==0)jitabi::trampoline_to_jit(s,mmu::base,resume_code.data());
 check(s->trapno==rv32::TrapCode::NONE && !s->vec.vstart && s->ip==pc+16,"reuse reentry at fault PC completes restart");
 for(u32 b=0;b<128;++b)check(s->vec.vreg[9][b]==u8(13*(4092+b)+5),"reuse restart complete independent bytes");
 for(u32 b=0;b<8192;++b)check(mem[b]==u8(13*b+5),"reuse restart memory untouched");
 printf("CONFIG_REUSE_FAULT_RESTART_PASS second_instruction_prefix=4 reentry_vstart=1 live_mapping_repair=PASS\n");
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
 config::qcg_pin=false;config_reuse_sequences(s);config_reuse_fault_restart(s);publication_thread_case(s);single_page_metadata_cases(s);maximum_span_boundary_cases(s);guarded_span_cases(s);checked_contract_cases(s);file_chunk_cases(s);exclusions(s);admission_equivalence(s);tcache::Destroy();
 printf("LOCAL_NATIVE_DISPATCH_PASS checks=%u cells=%u ABI=%016llx (terminal host faults only; checked mapping-repair restart also tested)\n",checks,cells,(unsigned long long)rv32::CPUStateAbiSignature());
}
