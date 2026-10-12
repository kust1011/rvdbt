// Local host interface checks; not external ISA or guest restart coverage.
#include "dbt/ukernel.cpp"
#include "dbt/guest/rv32_runtime.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir_builder.h"
using namespace dbt;
using namespace dbt::qir;
extern "C" void qcgstub_rv32_vle(CPUState *, u32);
extern "C" void qcgstub_rv32_vse(CPUState *, u32);
extern "C" void qcgstub_rv32_vleff(CPUState *, u32);
static unsigned checks, cells;
static void check(bool ok, char const *why)
{ ++checks; if (!ok) { fprintf(stderr,"UNIT_MEMORY_FAIL %s\n",why); exit(2); } }
constexpr u32 data = 0x24000000, pc = 0x80001234;
static u32 word(u32 eew, bool store, bool vm=true)
{
 u32 width = eew==1?0:eew==2?5:eew==4?6:7;
 return (u32(vm)<<25)|(5u<<15)|(width<<12)|(8u<<7)|(store?0x27:7);
}
static void clear(CPUState *s)
{
 s->trapno=rv32::TrapCode::NONE; s->GetUThread()->memory_fault_pending=false;
 s->fpu.fround_run_open=false; s->ip=pc;
}
static void invoke(CPUState *s,u32 raw,bool store)
{
 if (sigsetjmp(trap_unwind_env,0)==0) {
  if(store)qcgstub_rv32_vse(s,raw);else qcgstub_rv32_vle(s,raw);
 }
}
static void helpers(CPUState *s)
{
 config::vlen_bits=1024;
 for(u32 eew : {1u,2u,4u,8u}) for(bool store : {false,true})
 for(int prot : {PROT_NONE,PROT_READ,PROT_WRITE,-1})
 for(u32 start : {0u,1u,4u,6u,8u}) for(u32 mask : {0u,1u,2u}) {
  check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE)!=MAP_FAILED,"map helper");
  auto *memory=(u8*)mmu::g2h(data);
  for(u32 b=0;b<8192;++b)memory[b]=(u8)(b*17+3);
  clear(s); s->vec.Reset(1024);s->vec.vtype=(eew==1?0:eew==2?8:eew==4?16:24);
  s->vec.vl=6;s->vec.vstart=start;s->gpr[5]=data+4096-3*eew;
  for(u32 r=0;r<32;++r)for(u32 b=0;b<rv32::VLEN_MAX_BYTES;++b)s->vec.vreg[r][b]=(u8)(r*19+b*7);
  s->vec.vreg[0].fill(0);
  for(u32 e=0;e<6;++e)if(mask==0 || (mask==1 && (e&1)))s->vec.mask_set(0,e,true);
  auto expected=s->vec;
  std::array<u8,8192> expected_mem;memcpy(expected_mem.data(),memory,8192);
  bool denied= prot==-1 || !(prot&(store?PROT_WRITE:PROT_READ));
  u32 fault=6;
  for(u32 e=start;e<6;++e) {
   if(mask!=0 && !expected.mask_get(0,e))continue;
   if(e>=3 && denied){fault=e;break;}
   u32 off=4096-3*eew+e*eew;
   auto *reg=expected.elem_ptr(8,e,eew,1024);
   if(store)memcpy(expected_mem.data()+off,reg,eew);else memcpy(reg,expected_mem.data()+off,eew);
  }
  if(prot==-1)check(mmu::munmap(data+4096,4096)==0,"unmap");
  else check(mmu::mprotect(data+4096,4096,prot)==0,"protect helper");
  u32 raw=word(eew,store,mask==0);
  invoke(s,raw,store);
  expected.vstart=fault==6?0:fault;
  if(s->vec.vreg!=expected.vreg || s->vec.vstart!=expected.vstart || s->vec.vl!=6)
   fprintf(stderr,"cell eew=%u store=%d prot=%d start=%u mask=%u lowering=%u fault=%u actual_start=%u vl=%u trap=%u registers=%d\n",eew,store,prot,start,mask,config::rvv_lowering,fault,s->vec.vstart,s->vec.vl,(u32)s->trapno,s->vec.vreg==expected.vreg);
  check(s->vec.vreg==expected.vreg && s->vec.vstart==expected.vstart && s->vec.vl==6,"helper full vector state");
  check(s->ip==(fault==6?pc+4:pc),"actual instruction PC or normal advance");
  if(fault!=6) {
   auto const &ev=s->GetUThread()->memory_fault;
   check(s->trapno==rv32::TrapCode::MEMORY_FAULT && s->GetUThread()->memory_fault_pending,"queued trap");
   check(ev.pc==pc && ev.raw==raw && ev.element==fault && ev.address==s->gpr[5]+fault*eew,"event coordinates");
   check(ev.access==(store?MemoryFaultEvent::Access::Store:MemoryFaultEvent::Access::Load) && ev.eew_bytes==eew && ev.nf==1 && ev.field==0,"event geometry/direction");
   check(ev.reason==(prot==-1?MemoryFaultEvent::Reason::Unmapped:MemoryFaultEvent::Reason::Protection),"event reason");
   auto snapshot=ukernel::CaptureHelperMemoryFault(s);
   check(snapshot.vreg==expected.vreg && snapshot.csrs[3]==fault && snapshot.pc==pc,"dispatcher snapshot");
  } else check(s->trapno==rv32::TrapCode::NONE && !s->GetUThread()->memory_fault_pending,"normal no trap");
  if(prot==-1)check(mmu::mmap(data+4096,4096,PROT_READ|PROT_WRITE)!=MAP_FAILED,"remap after completed check");
  else check(mmu::mprotect(data+4096,4096,PROT_READ|PROT_WRITE)==0,"unprotect after completed check");
  // There is no return/retry execution here; each cell independently initializes state.
  check(!memcmp(memory,expected_mem.data(),prot==-1?4096:8192),"complete memory including inactive lanes");
  ++cells;
 }
 config::vlen_bits=128;
 // Split element denial checks the whole element before changing any byte.
 for(bool store : {false,true}) {
  clear(s);s->vec.Reset(128);s->vec.vtype=16;s->vec.vl=1;s->gpr[5]=data+4094;
  s->vec.vreg[8].fill(0x65);auto before=s->vec.vreg;
  auto *memory=(u8*)mmu::g2h(data);memory[4094]=0x34;memory[4095]=0x12;
  mmu::mprotect(data+4096,4096,PROT_NONE);
  invoke(s,word(4,store),store);
  check(s->GetUThread()->memory_fault.address==data+4096 && s->vec.vstart==0,"split fault first denied byte");
  check(s->vec.vreg==before && memory[4094]==0x34 && memory[4095]==0x12,"split element no partial update");
  mmu::mprotect(data+4096,4096,PROT_READ|PROT_WRITE);
 }
 // RV32 wrap: the first page is legal, address zero is denied. No host access at zero.
 check(mmu::mmap(0xfffff000,4096,PROT_READ|PROT_WRITE)!=MAP_FAILED,"top page");
 for(bool store : {false,true}) {
  clear(s);s->vec.Reset(128);s->vec.vtype=16;s->vec.vl=1;s->gpr[5]=0xfffffffe;
  s->vec.vreg[8].fill(0x78);auto before=s->vec.vreg;
  invoke(s,word(4,store),store);
  check(s->GetUThread()->memory_fault.address==0 && s->vec.vreg==before,"wrapped split denial");
 }
}

struct Runtime final : CompilerRuntime {
 void *mem{};size_t size{};
 ~Runtime(){if(mem)::munmap(mem,size);}
 void *AllocateCode(size_t n,uint) override {
  size=(n+64+4095)&~size_t(4095);mem=::mmap(nullptr,size,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANON,-1,0);
  check(mem!=MAP_FAILED,"executable allocation");return mem;
 }
 // Use the portable stub-table form. A JIT absolute-call literal pool is data
 // after the body and cannot be entered by this standalone return harness.
 bool AllowsRelocation() const override{return true;}
 void *AnnounceRegion(u32,std::span<u8> const &,u32) override{return nullptr;}
};
extern "C" __attribute__((noinline,naked)) void Enter(void *,void *,void *) {
 asm("pushq %rbp\n\tpushq %rbx\n\tpushq %r12\n\tpushq %r13\n\tpushq %r14\n\tpushq %r15\n\tmovq %rdi,%r13\n\tmovq %rsi,%rbp\n\t");
 asm("sub $%c0,%%rsp\n\t"::"i"(qcg::ArchTraits::spillframe_size+8));
 asm("callq *%rdx\n\t");
 asm("add $%c0,%%rsp\n\t"::"i"(qcg::ArchTraits::spillframe_size+8));
 asm("popq %r15\n\tpopq %r14\n\tpopq %r13\n\tpopq %r12\n\tpopq %rbx\n\tpopq %rbp\n\tretq\n\t");
}
static void native(CPUState *s)
{
 config::vlen_bits=128;
 StateReg regs[]={{(u16)offsetof(CPUState,gpr),VType::I32,"x0"}};StateInfo info{regs,1};
 for(bool store : {false,true}) for(bool loop : {false,true}) for(bool masked : {false,true}) {
  if(masked && !loop)continue; // typed chunk admission is unmasked only
  Runtime runtime;MemArena arena(4u<<20);auto *region=arena.New<Region>(&arena,&info);Builder b(region->CreateBlock());
  u32 raw=word(4,store,!masked);auto stub=store?RuntimeStubId::id_rv32_vse:RuntimeStubId::id_rv32_vle;
  b.Create_rvvtypedchunkbegin(16u,4u,raw,stub,loop?1u:2u,InstRVVTypedChunkBegin::GuardKind::VTypeIntegerNoRestart);
  if(loop)b.Create_vmemorynative(8,5,0,4,4,0,16,store,masked);
  else {
   auto v=VOperand::MakeVVPR(VType::V128,b.CreateVGPR(VType::V128));
   u32 regoff=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg)+8*rv32::VLEN_MAX_BYTES;
   if(store){b.Create_vstatechunkload(v,regoff);b.Create_vchunkstore(offsetof(CPUState,gpr)+5*4,0,v,4,0);}
   else{b.Create_vchunkload(v,offsetof(CPUState,gpr)+5*4,0,4,0);b.Create_vstatechunkstore(regoff,v,4,0,false);}
  }
  b.Create_rvvtypedchunkend(raw,stub);
  qcg::ArchTraits::init();auto code=qcg::GenerateCode(&runtime,nullptr,region,0);check(!code.empty(),"native generation");
  auto *bytes=(u8*)runtime.mem;size_t n=code.size();if(bytes[0]==0x51)bytes[n++]=0x59;bytes[n]=0xc3;

  for(u32 vl : {0u,1u,3u,4u}) for(u32 start : {0u,1u,vl}) for(int prot : {PROT_READ|PROT_WRITE,PROT_NONE,PROT_READ,PROT_WRITE}) {
   mmu::mprotect(data,8192,PROT_READ|PROT_WRITE);
   clear(s);s->vec.Reset(128);s->vec.vtype=16;s->vec.vl=vl;s->vec.vstart=start;s->gpr[5]=data+4096-8;
   auto *memory=(u8*)mmu::g2h(data);for(u32 i=0;i<8192;++i)memory[i]=(u8)(i*5+1);
   s->vec.vreg[8].fill(0x67);s->vec.vreg[0].fill(0);s->vec.vreg[0][0]=3;auto expected=s->vec;
   std::array<u8,8192> expected_mem;memcpy(expected_mem.data(),memory,8192);
   bool range_safe=vl<=2 || (prot&(store?PROT_WRITE:PROT_READ));
   bool admitted=range_safe && start==0;
   bool fault=!masked && !range_safe && start<vl;
   u32 fault_index=std::max(start,2u);
   for(u32 e=start;e<vl;++e) {
    if(masked && e>=2)continue;
    if(fault && e==fault_index)break;
    if(store)memcpy(expected_mem.data()+4088+4*e,expected.vreg[8].data()+4*e,4);
    else memcpy(expected.vreg[8].data()+4*e,expected_mem.data()+4088+4*e,4);
   }
   mmu::mprotect(data+4096,4096,prot);
   u64 fallbacks=s->rvv_direct_fallbacks,hits=s->rvv_direct_hits;

   if(sigsetjmp(trap_unwind_env,0)==0)Enter(s,mmu::base,bytes);
   check(s->rvv_direct_fallbacks-fallbacks==(admitted?0u:1u),"actual native/fallback admission");
   check(s->rvv_direct_hits-hits==(admitted?1u:0u),"actual native hit count");
   check(s->vec.vreg==expected.vreg && s->vec.vstart==(fault?fault_index:0u),"native/fallback full state");
   if(fault)check(s->ip==pc && s->GetUThread()->memory_fault.address==s->gpr[5]+fault_index*4,"native fallback event");
   else check(s->trapno==rv32::TrapCode::NONE && !s->GetUThread()->memory_fault_pending,"inactive/native normal no event");
   mmu::mprotect(data+4096,4096,PROT_READ|PROT_WRITE);
   check(!memcmp(memory,expected_mem.data(),8192),"native memory and inactive bytes");++cells;
  }
 }
}
static void fof_and_store_delivery(CPUState *s)
{
 config::vlen_bits=128;
 for(u32 start : {0u,1u}) {
  clear(s);s->vec.Reset(128);s->vec.vtype=16;s->vec.vl=4;s->vec.vstart=start;
  s->gpr[5]=data+4096-8;mmu::mprotect(data+4096,4096,PROT_NONE);
  if(sigsetjmp(trap_unwind_env,0)==0)qcgstub_rv32_vleff(s,word(4,false)|(16u<<20));
  check(s->trapno==rv32::TrapCode::NONE && s->vec.vl==2 && s->vec.vstart==0,"FOF later denial trims VL");
  check(!s->GetUThread()->memory_fault_pending,"FOF trim never queues ordinary fault");
 }
 clear(s);s->vec.Reset(128);s->vec.vtype=16;s->vec.vl=4;s->gpr[5]=data+4096;
 if(sigsetjmp(trap_unwind_env,0)==0)qcgstub_rv32_vleff(s,word(4,false)|(16u<<20));
 check(s->trapno==rv32::TrapCode::MEMORY_FAULT && s->vec.vl==4 && s->vec.vstart==0,"FOF element zero queues without trim");
 mmu::mprotect(data+4096,4096,PROT_READ|PROT_WRITE);
 // Actual store-event capture and host frame delivery, without executing a guest
 // handler, sigreturn, repairing the fault mapping, or repeating the instruction.
 constexpr u32 handler=0x25000000,stack=0x26000000;
 check(mmu::mmap(handler,4096,PROT_READ|PROT_EXEC)!=MAP_FAILED,"handler mapping");
 check(mmu::mmap(stack,32768,PROT_READ|PROT_WRITE)!=MAP_FAILED,"signal stack");
 clear(s);s->vec.Reset(128);s->vec.vtype=16;s->vec.vl=4;s->gpr[5]=data+4096-8;
 s->gpr[2]=stack+32768;mmu::mprotect(data+4096,4096,PROT_READ);
 invoke(s,word(4,true),true);
 auto snapshot=ukernel::CaptureHelperMemoryFault(s);auto *ut=s->GetUThread();
 ut->signal_actions[10]={handler,4,0};ut->guest_signal_mask=0;
 check(snapshot.event.access==MemoryFaultEvent::Access::Store,"store snapshot access");
 check(ukernel::DeliverHelperSignal(s,snapshot),"store fault host frame delivery");
 auto *frame=(u8*)mmu::g2h(s->gpr[2]);
 check(rv32_signal::get32(frame+rv32_signal::Info)==11 &&
       rv32_signal::get32(frame+rv32_signal::Info+8)==2 &&
       rv32_signal::get32(frame+rv32_signal::Info+12)==data+4096,"store siginfo direction-independent Linux fields");
 check(rv32_signal::get32(frame+rv32_signal::MC)==pc &&
       rv32_signal::get32(frame+rv32_signal::VS)==2,"store frame PC and vstart");
}

int main()
{
 mmu::Init();ukernel::process.main_thread=std::make_unique<uthread>();auto *s=CPUState::Current();
 config::rvv_lowering=0;config::rvv_verify=false;
 helpers(s);
 config::rvv_lowering=1;config::rvv_census=true;helpers(s); // permitted chunked dispatch and same precise fault fallback
 config::rvv_qcg_hit_counter=true; native(s);
 fof_and_store_delivery(s);
 printf("LOCAL_UNIT_MEMORY_PASS checks=%u cells=%u ABI=%016llx (no guest retry)\n",checks,cells,(unsigned long long)rv32::CPUStateAbiSignature());
}
