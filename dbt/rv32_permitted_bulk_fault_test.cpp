// Task132: terminal helper dispatcher observations, no delivery/handler/retry.
#define main PriorUnitMain
#include "dbt/rv32_unit_memory_fault_test.cpp"
#undef main
extern "C" void qcgstub_rv32_vlNre(CPUState *, u32);
extern "C" void qcgstub_rv32_vsNr(CPUState *, u32);
extern "C" u32 qcgstub_rv32_special_memory_safe(CPUState *, u32);
extern "C" u32 qcgstub_rv32_native_memory_safe(CPUState *, u32);
static volatile sig_atomic_t signals;
static u32 ordinal, skip;
static void callback(int sig, siginfo_t *info, void *frame)
{
 ++signals;
 dbt_sigaction_memory(sig, info, frame);
}
static void terminal(CPUState *s, bool whole, bool store, bool bus, u32 eew,
                     u32 nr, u32 vlen, u32 start, bool masked, bool split)
{
 if(ordinal++ < skip)return; // Resume an evidence batch without repeating captured cells.
 char name[]="/tmp/rvv-bulk132-XXXXXX";
 int fd=bus?mkstemp(name):-1;
 if(bus) { unlink(name);check(fd>=0 && ftruncate(fd,8192)==0,"full backing before admission"); }
 check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE,
       MAP_FIXED|MAP_PRIVATE|(bus?0:MAP_ANONYMOUS),fd)!=MAP_FAILED,"fresh mapping");
 auto *mem=(u8*)mmu::g2h(data);
 for(u32 b=0;b<8192;++b)mem[b]=(u8)(b*13+5);
 config::vlen_bits=vlen;
 clear(s);s->vec.Reset(vlen);
 s->vec.vtype=whole?rv32::VTYPE_VILL_BIT:(eew==1?0:eew==2?8:eew==4?16:24)|3u;
 s->vec.vl=whole?0:2*(vlen/8/eew);s->vec.vstart=start;
 for(u32 r=0;r<32;++r)for(u32 b=0;b<rv32::VLEN_MAX_BYTES;++b)s->vec.vreg[r][b]=(u8)(r*17+b*3);
 if(masked) { s->vec.vreg[0].fill(0);for(u32 e=0;e<s->vec.vl;++e)if(e%2==0)s->vec.mask_set(0,e,true); }
 u32 evl=whole?nr*vlen/8/eew:s->vec.vl;
 u32 prefix=nr>1 || !whole?std::min(evl-1,vlen/8/eew+2):evl/2;
 if(masked)prefix=(prefix+1)&~1u;
 u32 off=4096-prefix*eew-(split?eew-1:0);
 s->gpr[5]=data+off;s->gpr[6]=0x123;
 u32 raw=word(eew,store,!masked)|(whole?((8u<<20)|((nr-1)<<29)):0);
 u32 denied;
 auto epoch=mmu::MappingEpoch();
 check(!mmu::FirstDenied(data+off,evl*eew,store,denied),"entire span permission-admitted");
 if(whole)check(qcgstub_rv32_special_memory_safe(s,raw)==0,"unowned whole SIMD refused");
 if(bus && !whole && !masked && !start) {
  auto base=s->gpr[5];s->gpr[5]=data+128; // Page-contained: backing, not a crossing, refuses it.
  check(qcgstub_rv32_native_memory_safe(s,raw)==0,"file backing refuses native singleton before truncation");
  s->gpr[5]=base;
 }
 if(bus) {check(ftruncate(fd,4096)==0,"truncate after admission");close(fd);}
 else check(::mprotect(mem+4096,4096,PROT_NONE)==0,"raw host denial after admission");
 check(mmu::MappingEpoch()==epoch,"host fault leaves permission census/epoch unchanged");
 auto expected=s->vec;
 std::array<u8,4096> expected_mem;memcpy(expected_mem.data(),mem,4096);
 for(u32 e=start;e<prefix;++e) {
  if(masked && e%2)continue;
  u32 byte=e*eew,r=8+byte/(vlen/8),b=byte%(vlen/8);
  if(store)memcpy(expected_mem.data()+off+byte,expected.vreg[r].data()+b,eew);
  else memcpy(expected.vreg[r].data()+b,mem+off+byte,eew);
 }
 // Split checked leaves preserve the completed byte prefix of a faulting element.
 if(split) {
  u32 byte=prefix*eew,r=8+byte/(vlen/8),b=byte%(vlen/8);
  if(store)memcpy(expected_mem.data()+off+byte,expected.vreg[r].data()+b,eew-1);
 }
 expected.vstart=prefix;
 u32 mxcsr=rv32::rvdbt_mxcsr_get();config::rvv_fround_mxcsr_mode=2;
 config::g_mxcsr_resting=mxcsr & ~(rv32::FRound::MXCSR_RC|rv32::FRound::MXCSR_FLAGS);
 s->fpu.fcsr=0;rv32::rvv_fast::fround_run_open_or_continue(s->fpu,rv32::fp_mode(s->fpu,3));
 s->fpu.fround_run_open=true;rv32::rvdbt_mxcsr_set(rv32::rvdbt_mxcsr_get()|1);
 signals=0;
 if(sigsetjmp(trap_unwind_env,0)==0) {
  if(whole) {if(store)qcgstub_rv32_vsNr(s,raw);else qcgstub_rv32_vlNre(s,raw);}
  else {if(store)qcgstub_rv32_vse(s,raw);else qcgstub_rv32_vle(s,raw);}
  check(false,"fault must reach dispatcher");
 }
 auto snap=ukernel::CaptureHelperMemoryFault(s);
 check(signals==1 && snap.event.origin==MemoryFaultEvent::Origin::HostCopy,"exactly one owned host-copy fault");
 check(snap.event.host_signal==(bus?SIGBUS:SIGSEGV) && snap.event.host_code==(bus?BUS_ADRERR:SEGV_ACCERR),"original actual signal/code");
 check(snap.pc==pc && snap.event.raw==raw && snap.event.address==data+4096 &&
       snap.event.element==prefix && snap.event.eew_bytes==eew && snap.event.nf==nr &&
       snap.event.field==0 && snap.gpr[6]==0x123,"exact event and older scalar state");
 check(snap.vreg==expected.vreg && snap.csrs[3]==prefix && snap.csrs[7]==s->vec.vl &&
       snap.csrs[8]==s->vec.vtype,"complete register geometry/prefix/mask/tail/type");
 check(!memcmp(mem,expected_mem.data(),4096),"all accessible memory including completed store prefix");
 check(!s->fpu.fround_run_open && (snap.csrs[0]&16) && rv32::rvdbt_mxcsr_get()==config::g_mxcsr_resting,"dispatcher closes older FP state");
 printf("BULK132_CELL {\"whole\":%d,\"store\":%d,\"bus\":%d,\"eew\":%u,\"nr\":%u,\"vlen\":%u,\"start\":%u,\"masked\":%d,\"split\":%d,\"off\":%u,\"prefix\":%u,\"lowering\":%u,\"verify\":%d}\n",
        whole,store,bus,eew,nr,vlen,start,masked,split,off,prefix,config::rvv_lowering,config::rvv_verify);
 ukernel::WriteMemoryFaultSnapshot(stdout,snap);
 printf("BULK132_MEMORY ");for(u32 b=0;b<4096;++b)printf("%02x",mem[b]);printf("\n");
 config::rvv_fround_mxcsr_mode=0;rv32::rvdbt_mxcsr_set(mxcsr);++cells;
 // Mapping discarded by next independently initialized cell. Never repair/reenter.
}
static void fof_terminal(CPUState *s,bool zero)
{
 char name[]="/tmp/rvv-fof132-XXXXXX";int fd=mkstemp(name);unlink(name);
 check(fd>=0 && ftruncate(fd,4096)==0,"FOF backing");
 check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED,fd)!=MAP_FAILED,"FOF map");close(fd);
 config::vlen_bits=128;clear(s);s->vec.Reset(128);s->vec.vtype=16;s->vec.vl=3;s->gpr[5]=data+(zero?4096:4092);s->vec.vreg[8].fill(0xcc);
 signals=0;
 if(sigsetjmp(trap_unwind_env,0)==0)qcgstub_rv32_vleff(s,word(4,false)|(16u<<20));
 check(signals==1,"FOF one actual host signal");
 if(zero) {auto snap=ukernel::CaptureHelperMemoryFault(s);check(snap.event.host_signal==SIGBUS && snap.csrs[7]==3 && snap.csrs[3]==0,"FOF zero terminal event");ukernel::WriteMemoryFaultSnapshot(stdout,snap);}
 else check(s->trapno==rv32::TrapCode::NONE && s->vec.vl==1 && s->vec.vstart==0 && !s->GetUThread()->memory_fault_pending,"FOF later trims without ordinary fault");
 ++cells;
}
static void admission_only(CPUState *s)
{
 char name[]="/tmp/rvv-admit132-XXXXXX";int fd=mkstemp(name);unlink(name);
 check(fd>=0 && ftruncate(fd,8192)==0,"admission regular backing");
 config::vlen_bits=512;clear(s);s->vec.Reset(512);s->vec.vtype=16;s->vec.vl=16;s->gpr[5]=data+128;
 u32 denied;
 check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE,MAP_FIXED|MAP_PRIVATE,fd)!=MAP_FAILED,"file admission map");close(fd);
 check(!mmu::FirstDenied(data+128,64,false,denied) && mmu::page_ordinary_ram(data+128),"file page permitted and ordinary");
 check(!mmu::page_native_copy_ram(data+128) && qcgstub_rv32_native_memory_safe(s,word(4,false))==0,"page-contained file refuses native without access");
 check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE)!=MAP_FAILED,"replace with anonymous backing");
 check(mmu::page_native_copy_ram(data+128) && qcgstub_rv32_native_memory_safe(s,word(4,false))==1,"anonymous replacement preserves owned SIMD admission");
 check(mmu::munmap(data,8192)==0 && !mmu::page_native_copy_ram(data+128),"unmap clears native backing fact");
 printf("PERMITTED_BULK_ADMISSION_PASS checks=%u guest_accesses=0\n",checks);
}
int main(int argc, char **argv)
{
 bool admission=argc==2 && std::string(argv[1])=="--admission-only";
 if(argc==2 && !admission)skip=(u32)strtoul(argv[1],nullptr,10);
 mmu::Init();ukernel::process.main_thread=std::make_unique<uthread>();auto *s=CPUState::Current();
 struct sigaction sa{};sigfillset(&sa.sa_mask);sa.sa_flags=SA_SIGINFO;sa.sa_sigaction=callback;
 check(sigaction(SIGSEGV,&sa,nullptr)==0 && sigaction(SIGBUS,&sa,nullptr)==0,"install production fault handler");
 if(admission) {admission_only(s);return 0;}
 for(u32 mode:{0u,1u}) {
  config::rvv_lowering=mode;config::rvv_verify=mode;config::rvv_fixed_copy=mode;
  for(bool bus:{false,true})for(bool store:{false,true})for(u32 eew:{1u,2u,4u,8u})
   for(u32 start:{0u,1u})for(bool mask:{false,true})
    terminal(s,false,store,bus,eew,1,512,start,mask,false);
 }
 config::rvv_verify=false;
 for(bool bus:{false,true})for(bool store:{false,true})for(u32 vlen:{128u,512u,1024u})
  for(u32 nr:{1u,2u,4u,8u})for(u32 eew:{1u,2u,4u,8u}) {
   if(store && eew!=1)continue;
   terminal(s,true,store,bus,eew,nr,vlen,0,false,false);
  }
 for(bool store:{false,true})for(bool bus:{false,true})for(u32 eew:{2u,4u,8u}) {
  terminal(s,false,store,bus,eew,1,128,1,false,true);
  if(!store)terminal(s,true,false,bus,eew,2,128,1,false,true);
 }
 fof_terminal(s,false);fof_terminal(s,true);
 printf("PERMITTED_BULK_PASS checks=%u cells=%u no_guest_delivery_or_retry\n",checks,cells);
}
