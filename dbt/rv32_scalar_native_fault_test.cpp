// Actual singleton QCG scalar loop; one-time terminal children only.
#define main inherited_main
#include "dbt/rv32_unit_memory_fault_test.cpp"
#undef main
#include "dbt/rvv_native_fault.h"
#include "dbt/qmc/qcg/jitabi.h"
#include <sys/wait.h>
extern "C" u32 qcgstub_rv32_scalar_memory_safe(CPUState *,u32);
struct ScalarRuntime final : CompilerRuntime {
 std::vector<NativeMemorySite> sites;
 void *AllocateCode(size_t n,uint a) override {return tcache::AllocateCode(n+16,a);}
 bool AllowsRelocation() const override {return true;}
 void *AnnounceRegion(u32,std::span<u8> const &,u32) override {return nullptr;}
 void PublishNativeMemorySites(std::span<u8> c,std::span<NativeMemorySite const> s) override {
  sites.assign(s.begin(),s.end());tcache::RegisterNativeMemorySites(c,s);
 }
};
static unsigned caught;
static void once(int sig,siginfo_t *info,void *context) {
 if(++caught!=1)_exit(95);dbt_sigaction_memory(sig,info,context);
}
static u32 rawword(u32 eew,bool store,u32 mode,u32 nf,bool masked) {
 u32 raw=word(mode==2?std::min(eew,4u):eew,store,!masked)|((nf-1)<<29);
 if(mode==1)raw|=(2u<<26)|(16u<<20);
 if(mode==2)raw|=(1u<<26)|(16u<<20);
 if(mode==3)raw=word(1,store)|(11u<<20);
 if(mode==4)raw=word(store?1:eew,store)|(8u<<20)|(1u<<29); // two registers
 return raw;
}
static std::span<u8> compile(ScalarRuntime &rt,MemArena &arena,u32 raw,u32 vt) {
 config::vlen_bits=512;config::rvv_qcg_typed_chunk=true;config::rvv_direct=true;
 config::rvv_qcg_typed_chunk_vle=false;config::rvv_qcg_typed_chunk_vse=false;
 config::rvv_qcg_whole_reg=false;config::rvv_qcg_typed_chunk_vlse_gather=false;
 config::aot_use_llvm=false;config::rvv_verify=false;config::rvv_lowering=1;
 config::qcg_pin=true;config::qcg_pin_k=2;
 u32 words[]={0x12300313,raw};CompilerJob job(&rt,(uptr)words-pc,CodeSegment(pc,4096),{{pc,pc+8}},RvvEntryHint{vt,true});
 auto *r=CompilerGenRegionIR(&arena,job);unsigned loops=0;
 for(auto &b:r->GetBlocks())for(auto it=b.ilist.begin();it!=b.ilist.end();) {
  auto *i=&*it++;if(i->GetOpcode()==Op::_gbr)IListBase::remove(i);
  if(i->GetOpcode()==Op::_vmemorynative)++loops;
 }
 if(loops!=1)fprintf(stderr,"raw=%08x vt=%u loops=%u\n",raw,vt,loops);check(loops==1,"actual translator scalar memory loop");auto c=qcg::GenerateCode(&rt,&job.segment,r,pc);
 check(r->n_pins==0,"actual HAS_CALLS pin exclusion");
 check(rt.sites.size()==(((raw>>26)&3)==0 && ((raw>>20)&31)==8?1u:((raw>>29)&7)+1),"only unrolled field MOV sites");
 char name[80];snprintf(name,sizeof name,"emit-%08x-vt%u.bin",raw,vt);FILE *f=fopen(name,"wb");check(f,"code receipt");fwrite(c.data(),1,c.size(),f);fclose(f);
 snprintf(name,sizeof name,"sites-%08x-vt%u.txt",raw,vt);f=fopen(name,"w");check(f,"site receipt");
 for(auto &s:rt.sites) {
  check(s.scalar_loop && s.guest_pc==pc+4 && s.raw==raw && s.cold_offset && s.address_reg==asmjit::x86::Gp::kIdDi && s.data_reg==asmjit::x86::Gp::kIdCx,"final scalar codec");
  NativeMemorySite found;check(tcache::InspectNativeMemorySite((uptr)c.data()+s.code_offset,found),"final exact PC registered");
  check(!tcache::InspectNativeMemorySite((uptr)c.data()+s.code_offset+1,found),"interior PC unowned");
  fprintf(f,"pc=%u cold=%u eew=%u field=%u nf=%u addr=EDI element=R8D data=RCX\n",s.code_offset,s.cold_offset,s.eew_bytes,s.field,s.nf);
 }
 fclose(f);auto *p=c.data();size_t end=c.size();check(p[0]==0x51,"nonleaf frame");p[end++]=0x59;p[end]=0xc3;return c;
}
static void cell(CPUState *s,u32 eew,bool store,u32 mode,u32 nf,bool masked,u32 kind,bool terminal) {
 // kind: 0 ordinary, 1 split, 3 BUS file page, 4 mask enumeration,
 // 5 negative stride, 6 architectural permission denial.
 if(mode==3 || (mode==4 && store))eew=1;
 u32 raw=rawword(eew,store,mode,nf,masked),vt=(eew==1?0:eew==2?8:eew==4?16:24);
 ScalarRuntime rt;MemArena arena(4u<<20);auto code=compile(rt,arena,raw,vt);
 clear(s);s->vec.Reset(512);s->vec.vtype=mode==4?0x80000000:vt;
 s->vec.vl=mode==3?31:4;s->vec.vstart=masked?1:0;s->gpr[6]=0;
 u32 evl=mode==4?128/eew:4,fields=mode>=3?1:nf;
 u32 fault_e=2,fault_f=fields>1?1:0;
 if(kind==1){fault_e=0;fault_f=0;s->vec.vstart=0;}
 if(kind==4){fault_e=3;fault_f=0;}
 u32 base=data+4096-(fault_e*fields+fault_f)*eew;
 if(kind==1)base=data+4096-eew/2;
 if(kind==5)base=data+4096+(fault_e-1)*fields*eew; // first page is the denied one
 s->gpr[5]=base;s->gpr[16]=kind==5?0u-fields*eew:fields*eew;
 for(u32 r=0;r<32;++r)for(u32 b=0;b<512;++b)s->vec.vreg[r][b]=(u8)(r*19+b*7);
 s->vec.vreg[0].fill(0);for(u32 e=0;e<evl;++e)s->vec.mask_set(0,e,kind!=4 || e==1 || e==3);
 if(mode==2)for(u32 e=0;e<evl;++e)s->vec.elem_put(16,e,std::min(eew,4u),512,e*fields*eew);
 check(mmu::mprotect(data,8192,PROT_READ|PROT_WRITE)==0,"reset mapping");
 FILE *backing=nullptr;
 if(kind==3){backing=tmpfile();check(backing && !ftruncate(fileno(backing),4096),"BUS backing");check(mmu::mmap(data+4096,4096,PROT_READ|PROT_WRITE,MAP_FIXED|MAP_SHARED,fileno(backing),0)!=MAP_FAILED,"file page");}
 std::array<u8,8192> mem;for(u32 b=0;b<8192;++b)((u8*)mmu::g2h(data))[b]=mem[b]=(u8)(b*11+9);
 auto before=s->vec;auto expected=before;
 auto address=[&](u32 e,u32 f){return base+(kind==5?0u-e*fields*eew:e*fields*eew)+f*eew;};
 auto active=[&](u32 e){return e>=before.vstart && (!masked || before.mask_get(0,e));};
 for(u32 e=0;e<evl;++e)if(active(e))for(u32 f=0;f<fields;++f){auto *v=expected.elem_ptr(8+f,e,eew,512);u32 a=address(e,f);if(!store)for(u32 b=0;b<eew;++b)v[b]=*(u8*)mmu::g2h(a+b);}
 bool native=kind!=1;
 check(qcgstub_rv32_scalar_memory_safe(s,raw)==native,"scalar admission versus split/wrap checked path");
 auto fallback=s->rvv_direct_fallbacks;Enter(s,mmu::base,code.data());
 if(s->vec.vreg!=expected.vreg) {fprintf(stderr,"normal raw=%08x eew=%u mode=%u nf=%u kind=%u vl=%u start=%u gpr6=%u\n",raw,eew,mode,nf,kind,s->vec.vl,s->vec.vstart,s->gpr[6]);for(u32 r=0;r<32;++r)for(u32 b=0;b<512;++b)if(s->vec.vreg[r][b]!=expected.vreg[r][b]){fprintf(stderr,"diff r%u b%u got%u want%u\n",r,b,s->vec.vreg[r][b],expected.vreg[r][b]);goto shown; }shown:;}
 check(s->vec.vreg==expected.vreg && !s->vec.vstart && s->vec.vl==before.vl && s->vec.vtype==before.vtype && s->gpr[6]==0x123,"normal complete fixed vector state and older scalar");
 check(s->rvv_direct_fallbacks==fallback+!native,"actual normal selected route");
 for(u32 e=0;e<evl;++e)if(active(e))for(u32 f=0;f<fields;++f)for(u32 b=0;b<eew;++b)check(*(u8*)mmu::g2h(address(e,f)+b)==(store?before.elem_ptr(8+f,e,eew,512)[b]:expected.elem_ptr(8+f,e,eew,512)[b]),"normal memory bytes");
 memcpy(mmu::g2h(data),mem.data(),8192);s->vec=before;s->gpr[6]=0;s->ip=pc;
 if(terminal){pid_t child=fork();check(child>=0,"terminal fork");if(!child){
  caught=0;struct sigaction sa{};sa.sa_sigaction=once;sa.sa_flags=SA_SIGINFO;sigfillset(&sa.sa_mask);sigaction(SIGSEGV,&sa,nullptr);sigaction(SIGBUS,&sa,nullptr);
  u32 denied_page=kind==5?data:data+4096;
  if(kind==3){if(ftruncate(fileno(backing),0))_exit(92);}
  else if(kind==6){if(mmu::mprotect(denied_page,4096,PROT_NONE))_exit(92);}
  else if(::mprotect(mmu::g2h(denied_page),4096,PROT_NONE))_exit(92);
  s->fpu.fround_run_open=true;s->fpu.fround_run_saved_mxcsr=_mm_getcsr();config::rvv_fround_mxcsr_mode=0;_mm_setcsr(0x3f80);
  if(!sigsetjmp(trap_unwind_env,0)){jitabi::trampoline_to_jit(s,mmu::base,code.data());_exit(93);}
  auto snap=ukernel::CaptureHelperMemoryFault(s);auto ev=snap.event;auto want=before;
  for(u32 e=0;e<evl;++e)if(active(e))for(u32 f=0;f<fields;++f){
   if(e>fault_e || (e==fault_e && f>=fault_f))continue;
   u32 a=address(e,f);auto *v=want.elem_ptr(8+f,e,eew,512);
   if(!store)memcpy(v,mem.data()+a-data,eew);
   for(u32 b=0;b<eew;++b)check(*(u8*)mmu::g2h(a+b)==(store?before.elem_ptr(8+f,e,eew,512)[b]:mem[a-data+b]),"earlier memory publication");
  }
  check(caught==(kind==6?0u:1u) && s->vec.vreg==want.vreg && s->vec.vstart==fault_e && s->vec.vl==before.vl && s->vec.vtype==before.vtype,"terminal full state frontier");
  u32 addr=(kind==1)?denied_page:address(fault_e,fault_f);
  check(ev.pc==pc+4 && ev.raw==raw && ev.address==addr && ev.element==fault_e && ev.field==fault_f && ev.eew_bytes==eew && ev.nf==(mode==4?2:fields),"precise scalar event");
  check(ev.origin==(kind==6?MemoryFaultEvent::Origin::PredictedHelper:(native?MemoryFaultEvent::Origin::NativeUnit:MemoryFaultEvent::Origin::HostCopy)) && ev.host_signal==(kind==6?0:kind==3?SIGBUS:SIGSEGV),"owned signal or checked event");
  check(s->gpr[6]==0x123 && s->ip==pc+4 && !s->fpu.fround_run_open && _mm_getcsr()==s->fpu.fround_run_saved_mxcsr,"dispatcher older state and FP cleanup");
  // A split checked store may expose byte primitives before an unexpected host
  // fault. Preserve and check that contract; never infer all-or-none from MOV.
  if((kind==1)&&store)for(u32 b=0;b<eew/2;++b)check(*(u8*)mmu::g2h(base+b)==before.elem_ptr(8,0,eew,512)[b],"unexpected host split-store byte prefix");
  char name[100];snprintf(name,sizeof name,"before-%08x-vt%u-kind%u.bin",raw,vt,kind);FILE *bf=fopen(name,"wb");check(bf,"before vectors");fwrite(before.vreg.data(),1,sizeof before.vreg,bf);fclose(bf);
  snprintf(name,sizeof name,"input-%08x-vt%u-kind%u.bin",raw,vt,kind);bf=fopen(name,"wb");check(bf,"input memory");fwrite(mem.data(),1,mem.size(),bf);fclose(bf);
  snprintf(name,sizeof name,"geometry-%08x-vt%u-kind%u.json",raw,vt,kind);bf=fopen(name,"w");check(bf,"geometry");
  fprintf(bf,"{\"raw\":%u,\"eew\":%u,\"mode\":%u,\"fields\":%u,\"store\":%u,\"masked\":%u,\"kind\":%u,\"base\":%u,\"evl\":%u,\"vl\":%u,\"vtype\":%u,\"start\":%u,\"fault_element\":%u,\"fault_field\":%u,\"address\":%u,\"native\":%u,\"caught\":%u}\n",raw,eew,mode,fields,store,masked,kind,base,evl,before.vl,before.vtype,before.vstart,fault_e,fault_f,addr,native,caught);fclose(bf);
  snprintf(name,sizeof name,"memory-%08x-vt%u-kind%u.bin",raw,vt,kind);bf=fopen(name,"wb");check(bf,"completed memory");
  for(u32 e=0;e<evl;++e)if(active(e))for(u32 f=0;f<fields;++f)if(e<fault_e || (e==fault_e && f<fault_f))fwrite(mmu::g2h(address(e,f)),1,eew,bf);
  if(kind==1 && store)fwrite(mmu::g2h(base),1,eew/2,bf);fclose(bf);
  snprintf(name,sizeof name,"snapshot-%08x-vt%u-kind%u.bin",raw,vt,kind);FILE *f=fopen(name,"wb");check(f,"snapshot receipt");fwrite(&snap,1,sizeof snap,f);fclose(f);
  printf("SCALAR_TERMINAL raw=%08x kind=%u native=%d signal=%d element=%u field=%u address=%08x full_state=PASS no_retry=1\n",raw,kind,native,ev.host_signal,ev.element,ev.field,ev.address);fflush(stdout);_exit(0);
 }int status;waitpid(child,&status,0);check(WIFEXITED(status)&&WEXITSTATUS(status)==0,"one-time terminal child");++cells;}
 if(backing){fclose(backing);check(mmu::mmap(data+4096,4096,PROT_READ|PROT_WRITE)!=MAP_FAILED,"restore anonymous page");}
}
static void wrapping(CPUState *s,bool store) {
 u32 raw=rawword(4,store,0,1,false);ScalarRuntime rt;MemArena arena(4u<<20);auto code=compile(rt,arena,raw,16);
 clear(s);s->vec.Reset(512);s->vec.vtype=16;s->vec.vl=2;s->gpr[5]=0xfffffffe;s->gpr[6]=0;
 s->vec.vreg[8].fill(0x67);auto before=s->vec;
 check(mmu::mmap(0xfffff000,4096,PROT_READ|PROT_WRITE)!=MAP_FAILED,"wrapped top page");
 auto *top=(u8*)mmu::g2h(0xfffffffe);top[0]=0x12;top[1]=0x34;
 check(qcgstub_rv32_scalar_memory_safe(s,raw)==0,"wrapped split goes checked");
 pid_t child=fork();check(child>=0,"wrapped terminal fork");if(!child) {
  caught=0;struct sigaction sa{};sa.sa_sigaction=once;sa.sa_flags=SA_SIGINFO;sigfillset(&sa.sa_mask);sigaction(SIGSEGV,&sa,nullptr);sigaction(SIGBUS,&sa,nullptr);
  if(!sigsetjmp(trap_unwind_env,0)){jitabi::trampoline_to_jit(s,mmu::base,code.data());_exit(93);}
  auto snap=ukernel::CaptureHelperMemoryFault(s);auto ev=snap.event;
  check(!caught && s->vec.vreg==before.vreg && !s->vec.vstart && top[0]==0x12 && top[1]==0x34,"wrapped split predicted denial no partial field");
  check(ev.pc==pc+4 && ev.raw==raw && !ev.address && !ev.element && !ev.field && ev.eew_bytes==4 && ev.origin==MemoryFaultEvent::Origin::PredictedHelper && !ev.host_signal && s->gpr[6]==0x123,"wrapped dispatcher coordinates");
  char name[80];snprintf(name,sizeof name,"wrapped-%08x.bin",raw);FILE *f=fopen(name,"wb");check(f,"wrap snapshot");fwrite(&snap,1,sizeof snap,f);fclose(f);
  printf("WRAP_TERMINAL raw=%08x host_faults=0 predicted=1 split_field_unchanged=1 no_retry=1\n",raw);fflush(stdout);_exit(0);
 }int status;waitpid(child,&status,0);check(WIFEXITED(status)&&WEXITSTATUS(status)==0,"wrapped terminal child");++cells;
}
static void address_wrap(CPUState *s,bool store) {
 u32 raw=rawword(4,store,2,2,false);ScalarRuntime rt;MemArena arena(4u<<20);auto code=compile(rt,arena,raw,16);
 clear(s);s->vec.Reset(512);s->vec.vtype=16;s->vec.vl=4;s->gpr[5]=0xfffffff0;s->vec.vreg[8].fill(0x67);s->vec.vreg[9].fill(0x45);
 for(u32 e=0;e<4;++e)s->vec.elem_put(16,e,4,512,(u32)(data+100+e*8-s->gpr[5]));
 auto before=s->vec,expected=before;auto *m=(u8*)mmu::g2h(data+100);for(u32 b=0;b<32;++b)m[b]=(u8)(b*11+9);
 check(qcgstub_rv32_scalar_memory_safe(s,raw)==1,"wrapped address formation admitted");
 for(u32 e=0;e<4;++e)for(u32 f=0;f<2;++f)if(!store)memcpy(expected.elem_ptr(8+f,e,4,512),m+e*8+f*4,4);
 Enter(s,mmu::base,code.data());check(s->vec.vreg==expected.vreg && !s->vec.vstart && s->gpr[6]==0x123,"actual EDI wrapped address formation");
 for(u32 e=0;e<4;++e)for(u32 f=0;f<2;++f)check(!memcmp(m+e*8+f*4,(store?before:expected).elem_ptr(8+f,e,4,512),4),"wrapped address bytes");
 // Reject CPUState/index/mask locations, interior PCs and software signals.
 auto const &site=rt.sites[0];ucontext_t uc{};siginfo_t info{};
 uc.uc_mcontext.gregs[REG_RIP]=(greg_t)((uptr)code.data()+site.code_offset);
 uc.uc_mcontext.gregs[REG_R13]=(greg_t)s;uc.uc_mcontext.gregs[REG_RDI]=data+100;
 uc.uc_mcontext.gregs[REG_RBP]=(greg_t)mmu::base;uc.uc_mcontext.gregs[REG_TRAPNO]=14;uc.uc_mcontext.gregs[REG_ERR]=store?6:4;
 info.si_code=SEGV_ACCERR;info.si_addr=mmu::g2h(data+100);rvv_native_fault::Arm(s);
 ++uc.uc_mcontext.gregs[REG_RIP];check(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc),"interior signal PC rejected");--uc.uc_mcontext.gregs[REG_RIP];
 info.si_addr=s->vec.elem_ptr(16,0,4,512);check(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc),"CPUState index address unowned");
 info.si_addr=s->vec.vreg[0].data();check(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc),"CPUState mask address unowned");
 info.si_addr=mmu::g2h(data+100);info.si_code=SI_USER;check(!rvv_native_fault::HandleSignal(SIGSEGV,&info,&uc),"software signal unowned");
 // Nonzero/completed restart and indexed overlap guard stay explicit.
 s->vec.vstart=4;auto saved=s->vec;Enter(s,mmu::base,code.data());check(s->vec.vreg==saved.vreg && !s->vec.vstart,"completed vstart has no access");
 s->vec.vstart=1;u32 overlapping=(raw & ~(31u<<7))|(16u<<7);if(!store)check(qcgstub_rv32_scalar_memory_safe(s,overlapping)==0,"indexed publication overlap keeps checked helper");
}
int main(int argc,char **argv){
 bool normal=argc==2 && !strcmp(argv[1],"--normal-only");check(argc==1 || normal,"bounded mode");
 check(__builtin_cpu_supports("avx512f")&&__builtin_cpu_supports("bmi2"),"actual host512");config::trace=false;config::fast_boot=true;tcache::Init();mmu::Init();ukernel::process.main_thread=std::make_unique<uthread>();auto *s=CPUState::Current();
 FILE *layout=fopen("layout.json","w");check(layout,"snapshot layout");fprintf(layout,"{\"size\":%zu,\"event\":%zu,\"pc\":%zu,\"gpr\":%zu,\"csrs\":%zu,\"vreg\":%zu,\"stride\":%zu}\n",sizeof(MemoryFaultSnapshot),offsetof(MemoryFaultSnapshot,event),offsetof(MemoryFaultSnapshot,pc),offsetof(MemoryFaultSnapshot,gpr),offsetof(MemoryFaultSnapshot,csrs),offsetof(MemoryFaultSnapshot,vreg),sizeof s->vec.vreg[0]);fclose(layout);
 check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE)!=MAP_FAILED,"map memory");
 for(bool store:{false,true})for(u32 eew:{1u,2u,4u,8u})for(u32 mode:{0u,1u,2u})cell(s,eew,store,mode,2,false,0,!normal);
 for(bool store:{false,true})for(u32 mode:{0u,1u,2u}){config::rvv_qcg_active_mask_memory=true;cell(s,4,store,mode,1,true,4,!normal);config::rvv_qcg_active_mask_memory=false;}
 for(bool store:{false,true}){cell(s,1,store,3,1,false,0,!normal);cell(s,4,store,4,1,false,0,!normal);cell(s,4,store,1,1,false,5,!normal);cell(s,4,store,0,2,false,3,!normal);cell(s,4,store,0,2,false,6,!normal);for(u32 k:{1u})cell(s,4,store,0,1,false,k,!normal);}
 if(!normal)for(bool store:{false,true})wrapping(s,store);
 for(bool store:{false,true})address_wrap(s,store);
 tcache::Destroy();printf("SCALAR_NATIVE_PASS checks=%u terminal_cells=%u ABI=%016llx restart_NOT_verified\n",checks,cells,(unsigned long long)rv32::CPUStateAbiSignature());
}
