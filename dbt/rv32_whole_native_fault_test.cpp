// Actual singleton emission and terminal dispatcher checks; no guest retry.
#define RVV_NATIVE_FAULT_FIXTURE
#include "dbt/rv32_native_memory_site_test.cpp"
#include "dbt/qmc/qcg/jitabi.h"
extern "C" u32 qcgstub_rv32_native_memory_safe(CPUState *, u32);
extern "C" u32 qcgstub_rv32_special_memory_safe(CPUState *, u32);
static unsigned caught;
static void once(int sig,siginfo_t *info,void *ctx) { if(++caught!=1)_exit(95);dbt_sigaction_memory(sig,info,ctx); }
static u32 whole(u32 eew,bool store,u32 n) { return word(eew,store)|(8u<<20)|((n-1)<<29); }
static std::span<u8> compile_whole(SiteRuntime &rt,MemArena &arena,u32 raw,u32 vlen) {
 config::vlen_bits=vlen;config::aot_use_llvm=false;config::rvv_direct=true;config::rvv_verify=false;config::rvv_lowering=1;
 config::rvv_qcg_whole_reg=true;config::rvv_qcg_whole_reg_force_emit=false;
 rt.relocate=false;
 u32 words[]={0x12300313,raw};
 CompilerJob job(&rt,(uptr)words-pc,CodeSegment(pc,4096),{{pc,pc+8}},RvvEntryHint{16,true});
 auto *region=CompilerGenRegionIR(&arena,job);unsigned loads=0,pubs=0;
 for(auto &b:region->GetBlocks())for(auto &i:b.ilist) {
  if(i.GetOpcode()==Op::_vchunkload){check(loads==pubs,"publish before later whole guest load");++loads;}
  if(i.GetOpcode()==Op::_vstatechunkstore)++pubs;
 }
 auto code=qcg::GenerateCode(&rt,&job.segment,region,pc);
 u32 bytes=(((raw>>29)&7)+1)*vlen/8,chunk=std::min(vlen/8,64u);
 check(rt.sites.size()==bytes/chunk,"actual singleton exact sites");
 for(auto &site:rt.sites)check(site.cold_offset && site.eew_bytes==(1u<<(rv32::eew_log2_from_width((raw>>12)&7)-3)) && site.mask_reg==255,"whole encoded EEW unmasked cold ABI");
 char name[96];snprintf(name,sizeof name,"emit-%08x-vlen%u.bin",raw,vlen);FILE *f=fopen(name,"wb");check(f,"code receipt");fwrite(code.data(),1,code.size(),f);fclose(f);
 snprintf(name,sizeof name,"sites-%08x-vlen%u.txt",raw,vlen);f=fopen(name,"w");check(f,"site receipt");
 for(auto &s:rt.sites)fprintf(f,"pc=%u disp=%u bytes=%u eew=%u mask=%u cold=%u\n",s.code_offset,s.displacement,s.bytes,s.eew_bytes,s.mask_reg,s.cold_offset);fclose(f);
 return code;
}
static void cell(CPUState *s,u32 vlen,u32 n,u32 eew,bool store,u32 mode,bool terminal=true) {
 SiteRuntime rt;MemArena arena(4u<<20);u32 raw=whole(eew,store,n);auto code=compile_whole(rt,arena,raw,vlen);
 check(mmu::mprotect(data,8192,PROT_READ|PROT_WRITE)==0,"map permissions");clear(s);s->vec.Reset(vlen);
 s->vec.vtype=0x80000000;s->vec.vl=0;
 u32 bytes=n*vlen/8,chunk=std::min(vlen/8,64u),prefix=bytes>chunk?chunk:0;
 if(mode==1)prefix+=eew; // active chunk crosses page: checked fallback
 if(prefix>=bytes)prefix=eew;
 s->gpr[5]=data+4096-prefix;s->gpr[6]=0;
 for(u32 r=0;r<32;++r)for(u32 b=0;b<rv32::VLEN_MAX_BYTES;++b)s->vec.vreg[r][b]=(u8)(r*19+b*7);
 auto before=s->vec;auto *mem=(u8*)mmu::g2h(s->gpr[5]);std::vector<u8> input(bytes);
 for(u32 b=0;b<bytes;++b)mem[b]=input[b]=(u8)(b*5+3);
 bool native=mode==0; s->vec.vstart=mode==2?1:mode==3?bytes/eew:0;
 check(qcgstub_rv32_special_memory_safe(s,raw)==0,"grouped/LLVM shared admission stays closed");
 check(qcgstub_rv32_native_memory_safe(s,raw)==native,"singleton native or checked admission");
 auto expected=before;expected.vstart=0;
 for(u32 e=s->vec.vstart;e<bytes/eew;++e)if(!store)memcpy(expected.elem_ptr(8,e,eew,vlen),input.data()+e*eew,eew);
 jitabi::trampoline_to_jit(s,mmu::base,code.data());
 check(s->vec.vreg==expected.vreg && !s->vec.vstart && s->vec.vl==0 && s->vec.vtype==0x80000000 && s->gpr[6]==0x123,"normal full register state and vill/VL independence");
 for(u32 b=0;b<bytes;++b)check(mem[b]==(store && b>=(mode==2?eew:mode==3?bytes:0)?*before.elem_ptr(8,b,1,vlen):input[b]),"normal required stores");
 if(mode==3 || !terminal)return;
 memcpy(mem,input.data(),bytes);s->vec=before;s->vec.vstart=mode==2?1:0;s->gpr[6]=0;s->ip=pc;
 pid_t child=fork();check(child>=0,"terminal fork");if(!child){
  caught=0;struct sigaction sa{};sa.sa_sigaction=once;sa.sa_flags=SA_SIGINFO;sigfillset(&sa.sa_mask);sigaction(SIGSEGV,&sa,nullptr);
  if(::mprotect(mmu::g2h(data+4096),4096,PROT_NONE))_exit(92);
  s->fpu.fround_run_open=true;s->fpu.fround_run_saved_mxcsr=_mm_getcsr();config::rvv_fround_mxcsr_mode=0;_mm_setcsr(0x3f80);
  if(!sigsetjmp(trap_unwind_env,0)){jitabi::trampoline_to_jit(s,mmu::base,code.data());_exit(93);}
  auto snap=ukernel::CaptureHelperMemoryFault(s);auto ev=snap.event;
  auto want=before;for(u32 e=mode==2?1:0;e<prefix/eew;++e)if(!store)memcpy(want.elem_ptr(8,e,eew,vlen),input.data()+e*eew,eew);
  check(caught==1 && s->vec.vreg==want.vreg && s->vec.vstart==prefix/eew && s->vec.vl==0 && s->vec.vtype==0x80000000,"terminal full state frontier");
  check(ev.pc==pc+4 && ev.raw==raw && ev.address==data+4096 && ev.element==prefix/eew && ev.eew_bytes==eew && ev.nf==n && !ev.field && ev.host_signal==SIGSEGV && ev.host_code==SEGV_ACCERR && ev.origin==(native?MemoryFaultEvent::Origin::NativeUnit:MemoryFaultEvent::Origin::HostCopy),"precise whole fault coordinates");
  check(s->gpr[6]==0x123 && s->ip==pc+4 && !s->fpu.fround_run_open && _mm_getcsr()==s->fpu.fround_run_saved_mxcsr,"older state dispatcher cleanup");
  for(u32 b=0;b<prefix;++b)check(mem[b]==(store && b>=(mode==2?eew:0)?*before.elem_ptr(8,b,1,vlen):input[b]),"required earlier store bytes");
  char name[100];snprintf(name,sizeof name,"snapshot-%08x-vlen%u-mode%u.bin",raw,vlen,mode);FILE *f=fopen(name,"wb");check(f,"snapshot receipt");fwrite(&snap,1,sizeof snap,f);fclose(f);
  printf("WHOLE_TERMINAL vlen=%u nregs=%u eew=%u store=%d mode=%u prefix=%u native=%d full_state=PASS no_retry=1\n",vlen,n,eew,store,mode,prefix,native);fflush(stdout);_exit(0);
 }
 int status;waitpid(child,&status,0);check(WIFEXITED(status)&&WEXITSTATUS(status)==0,"terminal dispatcher child");++cells;
}
static void grouped(CPUState *s) {
 config::vlen_bits=128;StateReg regs[]={{(u16)offsetof(CPUState,gpr),VType::I32,"x0"}};StateInfo info{regs,1};
 SiteRuntime rt;MemArena arena(4u<<20);auto *region=arena.New<Region>(&arena,&info);Builder b(region->CreateBlock());
 RVVRunMember members[]={{pc,whole(1,false,1),RuntimeStubId::id_rv32_vlNre},{pc+4,whole(1,true,1),RuntimeStubId::id_rv32_vsNr}};
 auto *begin=b.Create_rvvtypedchunkbegin(0,16,members,2,4,InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartBaseMask,1u<<5,0u-16,true);
 static_cast<InstRVVTypedChunkBegin *>(begin)->native_memory_pc=pc; // even an annotation cannot arm a multi-member frame
 auto v=VOperand::MakeVVPR(VType::V128,b.CreateVGPR(VType::V128));
 u32 off=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg)+8*rv32::VLEN_MAX_BYTES;
 b.Create_vchunkload(v,offsetof(CPUState,gpr)+20,0);b.Create_vstatechunkstore(off,v);
 b.Create_vstatechunkload(v,off);b.Create_vchunkstore(offsetof(CPUState,gpr)+20,0,v);b.Create_rvvtypedchunkend(members,2);
 auto code=qcg::GenerateCode(&rt,nullptr,region,pc);check(rt.sites.empty(),"multi-member has zero owned sites");
 auto *bytes=code.data();size_t end=code.size();if(bytes[0]==0x51)bytes[end++]=0x59;bytes[end]=0xc3;
 clear(s);s->vec.Reset(128);s->vec.vtype=0;s->vec.vl=16;s->gpr[5]=data;
 auto *mem=(u8*)mmu::g2h(data);for(u32 i=0;i<16;++i)mem[i]=(u8)(i*3);auto count=s->rvv_direct_fallbacks;
 Enter(s,mmu::base,bytes);check(s->rvv_direct_fallbacks==count+1,"actual grouped emitted guard selects helper");
 for(u32 i=0;i<16;++i)check(s->vec.vreg[8][i]==i*3 && mem[i]==i*3,"grouped checked full state");
}
int main(int argc,char **argv){
 check(argc==1 || (argc==2 && (!strcmp(argv[1],"--normal-only") || !strcmp(argv[1],"--extra-terminal"))),"known bounded test mode");
 check(__builtin_cpu_supports("avx512f")&&__builtin_cpu_supports("bmi2"),"real host512");config::trace=false;config::fast_boot=true;tcache::Init();mmu::Init();ukernel::process.main_thread=std::make_unique<uthread>();auto *s=CPUState::Current();check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE)!=MAP_FAILED,"anonymous mapping");
 if(argc==2 && !strcmp(argv[1],"--normal-only")) {
  for(u32 v:{128u,512u,1024u})for(u32 n:{1u,2u,4u,8u})for(u32 e:{1u,2u,4u,8u})cell(s,v,n,e,false,0,false);
  config::vlen_bits=512;clear(s);s->vec.Reset(512);s->vec.vtype=24;s->vec.vl=123;s->gpr[5]=data;
  FILE *file=tmpfile();check(file && !ftruncate(fileno(file),4096),"file backing fixture");
  check(mmu::mmap(data,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED,fileno(file),0)!=MAP_FAILED,"file mapping");
  check(!qcgstub_rv32_native_memory_safe(s,whole(8,false,1)),"page-contained file backing refused without guest access");
  SiteRuntime rt;MemArena arena(4u<<20);auto code=compile_whole(rt,arena,whole(8,false,1),512);
  auto *mem=(u8*)mmu::g2h(data);for(u32 b=0;b<64;++b)mem[b]=(u8)(b*9);s->vec.vreg[8].fill(0x67);
  auto fallback=s->rvv_direct_fallbacks;jitabi::trampoline_to_jit(s,mmu::base,code.data());
  check(s->rvv_direct_fallbacks==fallback+1 && !memcmp(s->vec.vreg[8].data(),mem,64),"actual emitted file fallback transfers full EVL");
  check(s->vec.vl==123 && s->vec.vtype==24 && !s->vec.vstart,"file fallback ignores ordinary VL/vtype");
  check(mmu::mmap(data,4096,PROT_READ|PROT_WRITE)!=MAP_FAILED,"anonymous replacement");
  check(qcgstub_rv32_native_memory_safe(s,whole(8,false,1))==1,"anonymous admission ignores ordinary vl/vtype geometry");
  mem=(u8*)mmu::g2h(data);for(u32 b=0;b<64;++b)mem[b]=(u8)(b*11);s->vec.vreg[8].fill(0x67);
  fallback=s->rvv_direct_fallbacks;jitabi::trampoline_to_jit(s,mmu::base,code.data());
  check(s->rvv_direct_fallbacks==fallback && !memcmp(s->vec.vreg[8].data(),mem,64) && s->vec.vl==123 && s->vec.vtype==24,"actual normal whole SIMD independent of ordinary VL/vtype");
  fclose(file);grouped(s);
 } else if(argc==2 && !strcmp(argv[1],"--extra-terminal")) {
  for(u32 n:{1u,4u,8u})for(u32 e:{4u,8u})cell(s,512,n,e,false,0);
 } else {

 for(u32 v:{128u,512u,1024u})for(u32 n:{1u,2u,4u,8u})cell(s,v,n,1,true,0);
 for(u32 e:{1u,2u,4u,8u})for(u32 v:{128u,1024u})cell(s,v,2,e,false,0);
 for(u32 mode:{1u,2u,3u}){cell(s,1024,2,8,false,mode);cell(s,1024,2,1,true,mode);}
 }
 tcache::Destroy();printf("WHOLE_NATIVE_PASS checks=%u terminal_cells=%u restart_NOT_verified\n",checks,cells);
}
