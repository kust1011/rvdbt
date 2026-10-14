// Production run admission, instruction barriers and one-time terminal state.
#define RVV_NATIVE_FAULT_FIXTURE
#include "dbt/rv32_native_memory_site_test.cpp"
#include "dbt/qmc/qcg/jitabi.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/guest/rv32_qir.h"
static unsigned caught;
static void once(int sig, siginfo_t *info, void *ctx) {
 if (++caught != 1) _exit(95);
 dbt_sigaction_memory(sig, info, ctx);
}
static u32 alu(u32 rd,u32 a,u32 b,bool x=false) {
 return (x?0x0bu:0u)<<26 | 1u<<25 | b<<20 | a<<15 | rd<<7 | 0x57;
}
static u32 memword(bool whole,bool store,u32 base=5) {
 return (word(whole && store?1:4,store)&~(31u<<15)) | base<<15 | (whole?8u<<20:0u);
}
static void configure(unsigned mode) {
 config::vlen_bits=1024;config::aot_use_llvm=false;config::rvv_direct=true;
 config::rvv_verify=false;config::rvv_lowering=1;config::rvv_vector_run=true;
 config::rvv_vector_ssa=true;config::rvv_qcg_typed_chunk=true;
 config::rvv_qcg_typed_chunk_xor=true;config::rvv_qcg_typed_chunk_vle=true;
 config::rvv_qcg_typed_chunk_vse=true;config::rvv_qcg_whole_reg=true;
 config::rvv_run_body_materialize=mode==1;config::rvv_run_order_chunk_major=mode==2;
 config::rvv_run_component_separable=mode==3;
 config::rvv_run_grouped_component_major=mode==4;
 config::rvv_run_live_range_split=false;config::rvv_run_dep_probe_depth=0;
}
static std::vector<u32> stream(bool whole,bool store,bool second) {
 std::vector<u32> w={0x12300313,alu(8,1,2),alu(9,8,3,true)};
 if(second) w.push_back(memword(whole,false,7)); // earlier complete load, same vd
 w.push_back(memword(whole,store));
 w.push_back(alu(8,8,4)); // later overwrite of the faulting destination
 w.push_back(alu(10,8,3,true));
 return w;
}
static std::span<u8> compile(SiteRuntime &rt,MemArena &arena,std::vector<u32> &w,
                            bool baseline,unsigned id) {
 rt.relocate=false;
 auto d=dbt::qir::rv32::RV32Translator::RvvAdmitVectorRun((uptr)w.data()-pc,pc+4,pc+w.size()*4,w.size()-1,16);
 printf("ADMISSION id=%u members=%u has_mem=%d cut=%s end=%08x ops=",id,d.n_members,d.has_mem,dbt::rv32::rvvrun::CutReasonName(d.cut),d.end_pc);
 for(unsigned i=0;i<d.n_members;++i)printf("%s%s@%08x",i?",":"",dbt::rv32::rvvrun::RunOpName(d.members[i].op),d.members[i].pc);
 puts("");
 if(!baseline)check(d.n_members==2 && !d.has_mem && d.end_pc==pc+12,"compute prefix stays promoted and stops before memory");
 CompilerJob job(&rt,(uptr)w.data()-pc,CodeSegment(pc,4096),{{pc,pc+w.size()*4}},RvvEntryHint{16,true});
 auto *region=CompilerGenRegionIR(&arena,job);
 unsigned groups=0,single=0,memgroups=0;
 FILE *ir=fopen(("ir-"+std::to_string(id)+".txt").c_str(),"w");check(ir,"IR receipt");
 for(auto &b:region->GetBlocks())for(auto &i:b.ilist) {
  if(i.GetOpcode()==Op::_rvvtypedchunkbegin) {
   auto &f=static_cast<InstRVVTypedChunkBegin &>(i);bool memory=false;
   for(unsigned m=0;m<f.n_members;++m) {
    auto raw=f.n_members==1?f.raw:f.run_members[m].raw;
    memory|=(raw&0x7f)==7 || (raw&0x7f)==0x27;
   }
   groups+=f.n_members>1;single+=f.n_members==1;memgroups+=memory && f.n_members>1;
   fprintf(ir,"begin members=%u memory=%d typed=%u component_major=%d pc=%08x raw=%08x\n",f.n_members,memory,f.n_typed,f.body_component_major,f.native_memory_pc,f.raw);
  }
  fprintf(ir,"op=%u\n",(unsigned)i.GetOpcode());
 }
 fclose(ir);
 auto code=qcg::GenerateCode(&rt,&job.segment,region,pc);
 printf("EMISSION id=%u compute_groups=%u singletons=%u memory_groups=%u sites=%zu pins=%u\n",id,groups,single,memgroups,rt.sites.size(),region->n_pins);
 if(!baseline)check(groups==2 && memgroups==0 && rt.sites.size()==(w.size()==7?4u:2u),"actual compute promotion and singleton SIMD sites");
 FILE *f=fopen(("emit-"+std::to_string(id)+".bin").c_str(),"wb");check(f,"code receipt");fwrite(code.data(),1,code.size(),f);fclose(f);
 f=fopen(("sites-"+std::to_string(id)+".txt").c_str(),"w");check(f,"site receipt");
 for(auto &s:rt.sites)fprintf(f,"offset=%u guest_pc=%08x raw=%08x disp=%u bytes=%u eew=%u store=%u cold=%u\n",s.code_offset,s.guest_pc,s.raw,s.displacement,s.bytes,s.eew_bytes,s.store,s.cold_offset);
 fclose(f);return code;
}
static void apply_alu(dbt::rv32::VectorState &v,u32 raw) {
 unsigned rd=(raw>>7)&31,a=(raw>>15)&31,b=(raw>>20)&31;
 for(unsigned e=0;e<32;++e) {
  u32 aa,bb;memcpy(&aa,v.elem_ptr(a,e,4,1024),4);memcpy(&bb,v.elem_ptr(b,e,4,1024),4);
  u32 r=(raw>>26)==0x0b?(aa^bb):(aa+bb);memcpy(v.elem_ptr(rd,e,4,1024),&r,4);
 }
}
static void cell(CPUState *s,bool whole,bool store,bool second,unsigned mode,bool terminal,bool baseline,unsigned id) {
 configure(mode);auto w=stream(whole,store,second);SiteRuntime rt;MemArena arena(4u<<20);
 auto code=compile(rt,arena,w,baseline,id);if(baseline)return;
 clear(s);s->vec.Reset(1024);s->vec.vtype=16;s->vec.vl=32;
 s->gpr[5]=data+4096-64;s->gpr[7]=data+512;s->gpr[6]=0;
 for(unsigned r:{11u,12u,28u,31u})s->gpr[r]=0x19100000u+r;
 std::array<u32,32> expected_gpr;
 for(unsigned r=0;r<32;++r)expected_gpr[r]=s->gpr[r];
 expected_gpr[6]=0x123; // The sole scalar write in stream(), before the fault.
 for(unsigned r=0;r<32;++r)for(unsigned b=0;b<512;++b)s->vec.vreg[r][b]=(u8)(r*19+b*7);
 auto before=s->vec;auto *memory=(u8*)mmu::g2h(data);
 for(unsigned b=0;b<8192;++b)memory[b]=(u8)(b*5+3);
 std::array<u8,8192> input;memcpy(input.data(),memory,8192);auto prior=before;
 apply_alu(prior,w[1]);apply_alu(prior,w[2]);
 if(second)memcpy(prior.vreg[8].data(),input.data()+512,128);
 auto normal=prior;auto expected_mem=input;
 if(store)memcpy(expected_mem.data()+4032,prior.vreg[8].data(),128);
 else memcpy(normal.vreg[8].data(),input.data()+4032,128);
 apply_alu(normal,w[w.size()-2]);apply_alu(normal,w.back());
 jitabi::trampoline_to_jit(s,mmu::base,code.data());
 check(s->vec.vreg==normal.vreg && !s->vec.vstart && s->vec.vtype==16 && s->vec.vl==32 && s->gpr[6]==0x123,"normal full state including later overlapping destination");
 check(!memcmp(memory,expected_mem.data(),8192),"normal complete memory");
 check(!s->rvv_direct_fallbacks,"normal SIMD admission retained");
 if(!terminal)return;
 memcpy(memory,input.data(),8192);s->vec=before;s->gpr[6]=0;s->ip=pc;
 unsigned mi=second?4:3;u32 faultpc=pc+4*mi;
 pid_t child=fork();check(child>=0,"fresh terminal child");if(!child) {
  caught=0;struct sigaction sa{};sa.sa_sigaction=once;sa.sa_flags=SA_SIGINFO;sigfillset(&sa.sa_mask);sigaction(SIGSEGV,&sa,nullptr);
  if(::mprotect(mmu::g2h(data+4096),4096,PROT_NONE))_exit(92);
  if(!sigsetjmp(trap_unwind_env,0)){jitabi::trampoline_to_jit(s,mmu::base,code.data());_exit(93);}
  auto snap=ukernel::CaptureHelperMemoryFault(s);auto &ev=snap.event;auto want=prior;
  if(!store)memcpy(want.vreg[8].data(),input.data()+4032,64);
  check(caught==1 && snap.vreg==want.vreg && s->vec.vreg==want.vreg,"prior members complete, failed load prefix visible, later overlap uncommitted");
  check(s->gpr[6]==0x123 && s->vec.vstart==(whole && store?64u:16u) && s->vec.vl==32 && s->vec.vtype==16 && s->ip==faultpc,"precise PC/CSR/dirty scalar boundary");
  check(snap.gpr==expected_gpr,"saved scalar state and unrelated scalar registers preserved");
  for(unsigned r=0;r<32;++r)check(s->gpr[r]==expected_gpr[r],"live unrelated scalar registers preserved");
  check(ev.access==(store?MemoryFaultEvent::Access::Store:MemoryFaultEvent::Access::Load) && ev.reason==MemoryFaultEvent::Reason::HostFault,"explicit internal access fault cause");
  check(ev.pc==faultpc && ev.raw==w[mi] && ev.address==data+4096 && ev.element==(whole && store?64u:16u) && ev.eew_bytes==(whole && store?1u:4u) && ev.nf==1 && !ev.field && ev.host_signal==SIGSEGV && ev.origin==MemoryFaultEvent::Origin::NativeUnit,"exact owned SIMD event");
  auto wantmem=input;if(store)memcpy(wantmem.data()+4032,prior.vreg[8].data(),64);
  check(!memcmp(memory,wantmem.data(),4096),"completed store prefix and earlier memory preserved");
  auto out=[&](std::string name,void const *p,size_t n){FILE *f=fopen(name.c_str(),"wb");check(f,"state receipt");fwrite(p,1,n,f);fclose(f);};
  out("snapshot-"+std::to_string(id)+".bin",&snap,sizeof snap);
  out("expected-vregs-"+std::to_string(id)+".bin",&want.vreg,sizeof want.vreg);
  out("memory-"+std::to_string(id)+".bin",memory,4096);
  out("expected-memory-"+std::to_string(id)+".bin",wantmem.data(),4096);
  printf("GROUPED_TERMINAL id=%u whole=%d store=%d second=%d mode=%u pc=%08x element=%u prior_state=PASS later_overlap=UNCHANGED owned=1 no_retry=1\n",id,whole,store,second,mode,faultpc,ev.element);fflush(stdout);_exit(0);
 }
 int status;waitpid(child,&status,0);check(WIFEXITED(status)&&WEXITSTATUS(status)==0,"terminal dispatcher child");++cells;
}
static void legacy_group(CPUState *s,bool whole) {
 configure(0);
 StateReg regs[]={{(u16)offsetof(CPUState,gpr),VType::I32,"x0"}};StateInfo info{regs,1};
 SiteRuntime rt;MemArena arena(4u<<20);auto *region=arena.New<Region>(&arena,&info);Builder b(region->CreateBlock());
 RVVRunMember members[]={{pc,memword(whole,false),RuntimeStubId::id_rv32_vle},
                         {pc+4,memword(whole,true),RuntimeStubId::id_rv32_vse}};
 if(whole){members[0].stub=RuntimeStubId::id_rv32_vlNre;members[1].stub=RuntimeStubId::id_rv32_vsNr;}
 auto *begin=b.Create_rvvtypedchunkbegin(16,32,members,2,8,InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartBaseMask,1u<<5,0u-128,true);
 static_cast<InstRVVTypedChunkBegin *>(begin)->native_memory_pc=pc;
 static_cast<InstRVVTypedChunkBegin *>(begin)->body_component_major=true;
 for(unsigned c=0;c<2;++c) {
  auto v=VOperand::MakeVVPR(VType::V512,b.CreateVGPR(VType::V512));
  u32 off=offsetof(CPUState,vec)+offsetof(dbt::rv32::VectorState,vreg)+8*512+c*64;
  b.Create_vchunkload(v,offsetof(CPUState,gpr)+20,c*64);b.Create_vstatechunkstore(off,v);
  b.Create_vstatechunkload(v,off);b.Create_vchunkstore(offsetof(CPUState,gpr)+20,c*64,v);
 }
 b.Create_rvvtypedchunkend(members,2);auto code=qcg::GenerateCode(&rt,nullptr,region,pc);
 check(rt.sites.empty(),"multi-member annotation cannot arm singleton exit");
 auto *bytes=code.data();size_t end=code.size();check(bytes[0]==0x51,"nonleaf prologue");bytes[end++]=0x59;bytes[end]=0xc3;
 clear(s);s->vec.Reset(1024);s->vec.vtype=16;s->vec.vl=32;s->gpr[5]=data;
 auto *memory=(u8*)mmu::g2h(data);for(unsigned i=0;i<128;++i)memory[i]=(u8)(i*3);
 auto fallbacks=s->rvv_direct_fallbacks;Enter(s,mmu::base,code.data());
 printf("LEGACY_STATE whole=%d fallbacks=%llu prior=%llu ip=%08x\n",whole,(unsigned long long)s->rvv_direct_fallbacks,(unsigned long long)fallbacks,s->ip);
 check(s->rvv_direct_fallbacks==fallbacks+1 && s->ip==pc+8,"actual legacy grouped route selects ordered checked members");
 for(unsigned i=0;i<128;++i)check(s->vec.vreg[8][i]==(u8)(i*3) && memory[i]==(u8)(i*3),"legacy grouped checked complete state");
 printf("LEGACY_GROUP whole=%d component_major=1 annotation_ignored=1 checked=1\n",whole);
}
int main(int argc,char **argv) {
 bool baseline=argc==2 && !strcmp(argv[1],"--baseline-trace");bool terminal=argc==2 && !strcmp(argv[1],"--terminal");
 check(argc==2 && (baseline||terminal||!strcmp(argv[1],"--normal-only")),"bounded explicit mode");
 check(__builtin_cpu_supports("avx512f")&&__builtin_cpu_supports("bmi2"),"actual host512");
 config::trace=false;config::fast_boot=true;tcache::Init();mmu::Init();ukernel::process.main_thread=std::make_unique<uthread>();auto *s=CPUState::Current();
 check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE)!=MAP_FAILED,"anonymous test mapping");
 unsigned id=0;
 for(unsigned mode=0;mode<5;++mode)for(bool whole:{true,false})for(bool store:{false,true})for(bool second:{false,true}) {
  // Terminal selection: ten distinct instruction/state scenarios, each once.
  if(terminal && !(mode==0 || (mode==2 && whole && !second)))continue;
  cell(s,whole,store,second,mode,terminal,baseline,id++);
 }
 if(!baseline && !terminal){legacy_group(s,false);legacy_group(s,true);}
 tcache::Destroy();printf("GROUPED_MEMORY_PASS checks=%u terminal_cells=%u trace_only=%d restart_NOT_verified\n",checks,cells,baseline);
}
