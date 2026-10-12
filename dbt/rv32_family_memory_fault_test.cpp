// Local host state/permission checks. No guest handler execution or retry.
#define main UnitMemoryMain
#include "dbt/rv32_unit_memory_fault_test.cpp"
#undef main
#include "dbt/aot/aot.h"
#include <dlfcn.h>
extern "C" void qcgstub_rv32_vlse(CPUState *,u32);
extern "C" void qcgstub_rv32_vsse(CPUState *,u32);
extern "C" void qcgstub_rv32_vlxei(CPUState *,u32);
extern "C" void qcgstub_rv32_vsxei(CPUState *,u32);
extern "C" void qcgstub_rv32_vlseg(CPUState *,u32);
extern "C" void qcgstub_rv32_vsseg(CPUState *,u32);
static u32 family_word(u32 eew,bool store,u32 mop,u32 nf,bool vm)
{ return word(eew,store,vm)|(mop<<26)|((nf-1)<<29)|(16u<<20); }
static RuntimeStubId family_stub(bool store,u32 mop,u32 nf)
{
 if(nf>1)return store?RuntimeStubId::id_rv32_vsseg:RuntimeStubId::id_rv32_vlseg;
 if(mop==2)return store?RuntimeStubId::id_rv32_vsse:RuntimeStubId::id_rv32_vlse;
 return store?RuntimeStubId::id_rv32_vsxei:RuntimeStubId::id_rv32_vlxei;
}
static void family_invoke(CPUState *s,u32 raw,RuntimeStubId stub)
{
 if(sigsetjmp(trap_unwind_env,0)==0) {
  switch(stub) {
#define CALL(n) case RuntimeStubId::id_rv32_##n:qcgstub_rv32_##n(s,raw);break;
   CALL(vlse) CALL(vsse) CALL(vlxei) CALL(vsxei) CALL(vlseg) CALL(vsseg)
#undef CALL
   default:check(false,"bad family stub");
  }
 }
}
static void family_helpers(CPUState *s)
{
 for(u32 lmul:{0u,1u,2u}) for(u32 vlen:{128u,1024u}) for(u32 eew:{1u,2u,4u,8u})
 for(u32 mop:{0u,1u,2u,3u}) for(u32 nf:{1u,2u,3u}) {
  if(mop==0 && nf==1)continue;
  for(u32 idx:{1u,2u,4u}) {
   if(!(mop&1) && idx!=1)continue;
   u32 sewlog=eew==1?0:eew==2?1:eew==4?2:3;
   u32 vt=sewlog*8+lmul; // index and data groups may span registers independently
   auto shape=rv32::vseg_shape((family_word(mop&1?idx:eew,false,mop,nf,true)>>12)&7,mop,nf-1,rv32::VType{vt});
   if(nf>1 ? !rv32::vseg_registers_legal(shape,8,16,true,true):
      !rv32::vmemory_registers_legal(rv32::VType{vt},(family_word(mop&1?idx:eew,false,mop,nf,true)>>12)&7,mop,8,16,false,true))continue;
   u32 vl=std::min(6u,rv32::compute_vlmax(rv32::VType{vt},vlen));
   for(bool store:{false,true}) for(int prot:{PROT_NONE,PROT_READ,PROT_WRITE,-1})
   for(u32 start:{0u,1u,vl,vl+1}) for(u32 mask:{0u,1u,2u}) for(int direction:{1,-1,0}) {
    if(mop!=2 && direction!=1)continue;
    check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE)!=MAP_FAILED,"family mapping");
    auto *memory=(u8*)mmu::g2h(data);for(u32 b=0;b<8192;++b)memory[b]=(u8)(b*11+9);
    config::vlen_bits=vlen;clear(s);s->vec.Reset(vlen);s->vec.vtype=vt;s->vec.vl=vl;s->vec.vstart=start;
    s->gpr[5]=data+4096-2*nf*eew-eew;
    if(direction<0)s->gpr[5]=data+4096+2*nf*eew;
    if(direction==0)s->gpr[5]=data+4096;
    s->gpr[16]=(u32)(direction*(int)(nf*eew));
    for(u32 r=0;r<32;++r)s->vec.vreg[r].fill((u8)(r*7+1));
    for(u32 e=0;e<vl;++e)s->vec.elem_put(16,e,idx,vlen,e*nf*eew);
    s->vec.vreg[0].fill(0);for(u32 e=0;e<vl;++e)if(mask==0||(mask==1&&(e&1)))s->vec.mask_set(0,e,true);
    auto expected=s->vec;std::array<u8,8192> mem;memcpy(mem.data(),memory,8192);
    bool fault=false;u32 fault_e=0,fault_f=0,address=0;
    for(u32 e=start;e<vl && !fault;++e) {
     if(mask && !expected.mask_get(0,e))continue;
     u32 eb=s->gpr[5]+(mop&1?e*nf*eew:e*(mop==2?s->gpr[16]:nf*eew));
     for(u32 f=0;f<nf;++f) {
      u32 off=eb+f*eew-data;
      bool denied=(prot==-1||!(prot&(store?PROT_WRITE:PROT_READ))) && off+eew>4096;
      if(denied){fault=true;fault_e=e;fault_f=f;address=data+std::max(4096u,off);break;}
      auto *reg=expected.elem_ptr(8+f*shape.field_regs,e,eew,vlen);
      if(store)memcpy(mem.data()+off,reg,eew);else memcpy(reg,mem.data()+off,eew);
     }
    }
    if(prot==-1)mmu::munmap(data+4096,4096);else mmu::mprotect(data+4096,4096,prot);
    u32 raw=family_word(mop&1?idx:eew,store,mop,nf,mask==0);
    family_invoke(s,raw,family_stub(store,mop,nf));
    if(s->vec.vreg!=expected.vreg || s->vec.vstart!=(fault?fault_e:0) || s->vec.vl!=vl)
     fprintf(stderr,"family cell vlen=%u eew=%u idx=%u mop=%u nf=%u store=%d prot=%d start=%u mask=%u dir=%d expected_fault=%d e=%u f=%u actual_start=%u trap=%u registers=%d\n",vlen,eew,idx,mop,nf,store,prot,start,mask,direction,fault,fault_e,fault_f,s->vec.vstart,(u32)s->trapno,s->vec.vreg==expected.vreg);
    check(s->vec.vreg==expected.vreg && s->vec.vstart==(fault?fault_e:0) && s->vec.vl==vl,"family all register/CSR state");
    check(s->ip==(fault?pc:pc+4),"family PC");
    if(fault) {
     auto ev=s->GetUThread()->memory_fault;
     check(s->trapno==rv32::TrapCode::MEMORY_FAULT && ev.pc==pc && ev.raw==raw && ev.address==address && ev.element==fault_e && ev.field==fault_f && ev.nf==nf && ev.eew_bytes==eew,"family precise event");
     check(ev.access==(store?MemoryFaultEvent::Access::Store:MemoryFaultEvent::Access::Load) && ev.reason==(prot==-1?MemoryFaultEvent::Reason::Unmapped:MemoryFaultEvent::Reason::Protection),"family access/reason");
     auto snapshot=ukernel::CaptureHelperMemoryFault(s);check(snapshot.vreg==expected.vreg && snapshot.csrs[3]==fault_e,"family dispatcher snapshot");
    } else check(s->trapno==rv32::TrapCode::NONE && !s->GetUThread()->memory_fault_pending,"family normal suppression");
    if(prot==-1)mmu::mmap(data+4096,4096,PROT_READ|PROT_WRITE);else mmu::mprotect(data+4096,4096,PROT_READ|PROT_WRITE);
    check(!memcmp(memory,mem.data(),prot==-1?4096:8192),"family all memory/prefix fields");++cells;
   }
  }
 }
}
static void family_native(CPUState *s)
{
 config::vlen_bits=128;
 StateReg regs[]={{(u16)offsetof(CPUState,gpr),VType::I32,"x0"}};StateInfo info{regs,1};
 for(bool masked:{false,true}) for(u32 vlen:{128u,512u}) for(bool store:{false,true}) for(u32 mop:{0u,1u,2u,3u}) for(u32 nf:{1u,2u,3u}) {
  config::vlen_bits=vlen;config::rvv_qcg_typed_chunk_vlse_gather=true;config::rvv_qcg_typed_chunk_vlse_gather_census=true;
  if(mop==0 && nf==1)continue;
  auto stub=family_stub(store,mop,nf);u32 raw=family_word(4,store,mop,nf,!masked);
  Runtime runtime;MemArena arena(4u<<20);auto *region=arena.New<Region>(&arena,&info);Builder b(region->CreateBlock());
  b.Create_rvvtypedchunkbegin(16u,vlen/32,raw,stub,1,InstRVVTypedChunkBegin::GuardKind::VTypeInteger);
  b.Create_vmemorynative(8,5,16,4,4,mop&1?2:mop==2?1:0,vlen/8,store,masked,nf,1,vlen/32);
  b.Create_rvvtypedchunkend(raw,stub);qcg::ArchTraits::init();auto code=qcg::GenerateCode(&runtime,nullptr,region,0);
  auto *bytes=(u8*)runtime.mem;size_t n=code.size();if(bytes[0]==0x51)bytes[n++]=0x59;bytes[n]=0xc3;
  for(u32 start:{0u,1u,4u}) for(int prot:{PROT_READ|PROT_WRITE,PROT_NONE,PROT_READ,PROT_WRITE}) {
   mmu::mprotect(data,8192,PROT_READ|PROT_WRITE);
   clear(s);s->vec.Reset(vlen);s->vec.vtype=16;s->vec.vl=4;s->vec.vstart=start;s->vec.vreg[0][0]=3;s->gpr[5]=data+4096-2*nf*4;s->gpr[16]=nf*4;
   for(u32 e=0;e<4;++e)s->vec.elem_put(16,e,4,vlen,e*nf*4);
   s->vec.vreg[8].fill(0x45);auto initial=s->vec;
   std::array<u8,8192> initial_mem;auto *memory=(u8*)mmu::g2h(data);for(u32 i=0;i<8192;++i)memory[i]=(u8)(i*3+1);memcpy(initial_mem.data(),memory,8192);
   mmu::mprotect(data+4096,4096,prot);
   bool permitted=prot&(store?PROT_WRITE:PROT_READ);
   bool safe=permitted && start==0;
   auto hits=s->rvv_direct_hits,miss=s->rvv_direct_fallbacks;
   if(sigsetjmp(trap_unwind_env,0)==0)Enter(s,mmu::base,bytes);
   check(s->rvv_direct_hits-hits==(safe?1u:0u) && s->rvv_direct_fallbacks-miss==(safe?0u:1u),"family actual native/fallback counters");
   auto actual=s->vec;auto actual_event=s->GetUThread()->memory_fault;
   mmu::mprotect(data+4096,4096,PROT_READ|PROT_WRITE);std::array<u8,8192> actual_mem;memcpy(actual_mem.data(),memory,8192);
   // Independently reset and run the checked helper once, never a guest retry.
   clear(s);s->vec=initial;memcpy(memory,initial_mem.data(),8192);mmu::mprotect(data+4096,4096,prot);
   family_invoke(s,raw,stub);
   check(actual.vreg==s->vec.vreg && actual.vstart==s->vec.vstart,"native family/helper state equality");
   if(!permitted && !masked && start<4)check(actual_event.element==2 && actual_event.field==0 && actual_event.address==data+4096,"native fallback coordinates");
   mmu::mprotect(data+4096,4096,PROT_READ|PROT_WRITE);check(!memcmp(memory,actual_mem.data(),8192),"native family memory equality");++cells;
  }
 }
}
static void family_wrap_and_gather(CPUState *s)
{
 config::vlen_bits=128;
 check(mmu::mmap(0xfffff000,4096,PROT_READ|PROT_WRITE)!=MAP_FAILED,"family top page");
 for(bool store:{false,true}) for(u32 mop:{0u,1u,2u,3u}) for(u32 nf:{1u,2u}) {
  if(mop==0 && nf==1)continue;
  clear(s);s->vec.Reset(128);s->vec.vtype=16;s->vec.vl=2;s->gpr[5]=0xfffffff8;s->gpr[16]=8;
  s->vec.vreg[8].fill(0x79);s->vec.vreg[9].fill(0x57);
  s->vec.elem_put(16,0,4,128,0);s->vec.elem_put(16,1,4,128,8);
  auto initial=s->vec;u32 raw=family_word(4,store,mop,nf,true);
  family_invoke(s,raw,family_stub(store,mop,nf));
  u32 const fault_e=1;
  check(s->trapno==rv32::TrapCode::MEMORY_FAULT && s->vec.vstart==fault_e && s->GetUThread()->memory_fault.address==0 && s->GetUThread()->memory_fault.field==0,"family RV32 element address wrap");
  check(!memcmp(s->vec.elem_ptr(8,1,4,128),initial.elem_ptr(8,1,4,128),4),"family wrap denied element unchanged");
  // A field itself straddles the reservation; neither byte half is copied.
  clear(s);s->vec=initial;s->vec.vl=1;s->gpr[5]=0xfffffffe;
  family_invoke(s,raw,family_stub(store,mop,nf));
  check(s->GetUThread()->memory_fault.address==0 && s->vec.vstart==0 && s->vec.vreg==initial.vreg,"family wrapped split field atomic denial");
 }
 config::rvv_gather=true;
 for(int prot:{PROT_READ|PROT_WRITE,PROT_WRITE,PROT_NONE}) {
  mmu::mprotect(data,8192,PROT_READ|PROT_WRITE);
  clear(s);s->vec.Reset(128);s->vec.vtype=16;s->vec.vl=4;s->gpr[5]=data+4096-8;
  for(u32 e=0;e<4;++e)s->vec.elem_put(16,e,4,128,e*4);
  mmu::mprotect(data+4096,4096,prot);
  auto calls=rv32::rvv_gather::g_gather_calls;
  family_invoke(s,family_word(4,false,1,1,true),RuntimeStubId::id_rv32_vlxei);
  bool const safe=prot&PROT_READ;
  check(rv32::rvv_gather::g_gather_calls-calls==(safe && rv32::rvv_gather::host_has_avx2()?1u:0u),"AVX2 actual permission admission");
  if(!safe)check(s->vec.vstart==2 && s->GetUThread()->memory_fault.address==data+4096,"AVX2 precise denied fallback");
 }
 mmu::mprotect(data,8192,PROT_READ|PROT_WRITE);
}

static void family_illegal_groups(CPUState *s)
{
 config::vlen_bits=128;
 struct Row{u32 vt,raw;RuntimeStubId stub;};
 Row rows[]={
  {17,family_word(4,false,2,1,true)+(1u<<7),RuntimeStubId::id_rv32_vlse}, // M2 odd data
  {18,family_word(4,false,2,3,true),RuntimeStubId::id_rv32_vlseg}, // 3*EMUL4 > 8
  {16,family_word(8,false,1,1,true),RuntimeStubId::id_rv32_vlxei}, // RV32 index64
  {0,family_word(4,false,1,1,true)+(1u<<20),RuntimeStubId::id_rv32_vlxei}, // index EMUL4 odd
  {16,(family_word(4,false,1,2,true)&~(31u<<20))|(8u<<20),RuntimeStubId::id_rv32_vlseg}, // segment index overlap
  {16,family_word(4,false,2,1,false)&~(31u<<7),RuntimeStubId::id_rv32_vlse} // masked vd=v0
 };
 for(auto row:rows){
  clear(s);s->vec.Reset(128);s->vec.vtype=row.vt;s->vec.vl=1;s->gpr[5]=0;
  auto before=s->vec;family_invoke(s,row.raw,row.stub);
  check(s->trapno==rv32::TrapCode::ILLEGAL_INSN && !s->GetUThread()->memory_fault_pending && s->vec.vreg==before.vreg,"illegal groups reject before access");
 }
}

int main(int argc, char **argv)
{
 mmu::Init();ukernel::process.main_thread=std::make_unique<uthread>();auto *s=CPUState::Current();
 config::rvv_lowering=0;config::rvv_verify=false;family_helpers(s);
 config::rvv_qcg_hit_counter=true;family_native(s);check(rv32::g_vlse_gather_fast>0,"Z3 safe SIMD actually executed");family_wrap_and_gather(s);family_illegal_groups(s);
 if(argc==3) {
  config::vlen_bits=128;
  void *old=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL),*fresh=dlopen(argv[2],RTLD_NOW|RTLD_LOCAL);
  check(old && fresh,"local ABI fixtures load");
  check(!AotAbiCompatible(old,"Task116-local-fixture"),"old unchecked cache ABI rejected");
  check(AotAbiCompatible(fresh,"Task117-local-fixture"),"current ABI/VLEN cache admitted");
  dlclose(old);dlclose(fresh);
 }
 printf("LOCAL_FAMILY_MEMORY_PASS checks=%u cells=%u ABI=%016llx (no guest retry)\n",checks,cells,(unsigned long long)rv32::CPUStateAbiSignature());
}
