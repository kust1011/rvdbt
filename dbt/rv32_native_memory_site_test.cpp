// Bounded production-emitter inspection. Fault children exit from the callback;
// no signal return, guest operation retry, mapping repair or dispatcher claim.
#define main previous_unit_main
#include "dbt/rv32_unit_memory_fault_test.cpp"
#undef main
#include <sys/wait.h>

struct SiteRuntime final : CompilerRuntime {
 std::vector<NativeMemorySite> sites;
 bool relocate{true};
 unsigned allocated_pins{};
 void *AllocateCode(size_t size, uint align) override { return tcache::AllocateCode(size + 16, align); }
 bool AllowsRelocation() const override { return relocate; }
 void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
 void PublishNativeMemorySites(std::span<u8> code, std::span<NativeMemorySite const> values) override {
  sites.assign(values.begin(), values.end());
  tcache::RegisterNativeMemorySites(code, values);
 }
};
struct Capture {
 greg_t regs[NGREG];
 uptr address;
 int signal, code;
 u32 ip, vstart, vl, gpr6;
 u8 destination[128], prefix[64], in_chunk_prefix[8];
};
static Capture *capture;
static CPUState *capture_state;
static NativeMemorySite capture_site;
static uptr capture_pc;
static u8 *capture_prefix;
static u32 capture_inside;
static void inspect_once(int sig, siginfo_t *info, void *frame)
{
 auto *uc = static_cast<ucontext_t *>(frame);
 // Only the single expected guest-program access may produce an inspection.
 if ((uptr)uc->uc_mcontext.gregs[REG_RIP] != capture_pc ||
     !((sig == SIGSEGV && info->si_code == SEGV_ACCERR) ||
       (sig == SIGBUS && info->si_code == BUS_ADRERR))) _exit(90);
 uptr const base = (uptr)uc->uc_mcontext.gregs[REG_RAX] + capture_site.displacement +
                   (config::zero_membase ? 0 : (uptr)uc->uc_mcontext.gregs[REG_RBP]);
 if ((uptr)info->si_addr - base >= capture_site.bytes ||
     (uptr)uc->uc_mcontext.gregs[REG_R13] != (uptr)capture_state) _exit(91);
 for (unsigned i=0; i<NGREG; ++i) capture->regs[i] = uc->uc_mcontext.gregs[i];
 capture->address = (uptr)info->si_addr; capture->signal = sig; capture->code = info->si_code;
 capture->ip = capture_state->ip; capture->vstart = capture_state->vec.vstart;
 capture->vl = capture_state->vec.vl; capture->gpr6 = capture_state->gpr[6];
 for (unsigned i=0; i<128; ++i) capture->destination[i] = capture_state->vec.vreg[8][i];
 for (unsigned i=0; i<64; ++i) capture->prefix[i] = capture_prefix[i];
 for (unsigned i=0; i<capture_inside; ++i) capture->in_chunk_prefix[i] = capture_prefix[64+i];
 _exit(0); // terminal inspection only, never resume the emitted operation
}
static std::span<u8> emit(SiteRuntime &runtime, MemArena &arena, bool store, u32 eew, bool partial)
{
 config::vlen_bits=1024; config::rvv_qcg_partial_vl=partial;
 config::rvv_qcg_typed_chunk_vle=true; config::rvv_qcg_typed_chunk_vse=true;
 config::rvv_qcg_typed_chunk_mem_e64=true;
 config::rvv_qcg_typed_chunk_vle_force_emit=false; config::rvv_qcg_typed_chunk_vse_force_emit=false;
 config::aot_use_llvm=false; config::rvv_verify=false; config::rvv_direct=true; config::rvv_lowering=1;
 u32 words[] = {0x12300313, word(eew,store)}; // addi x6,x0,0x123, then ordinary vle/vse
 CompilerJob job(&runtime, (uptr)words-pc, CodeSegment(pc,4096), {{pc,pc+8}},
                 RvvEntryHint{eew==4?16u:24u,true});
 auto *region=CompilerGenRegionIR(&arena,job);
 unsigned loads=0, publications=0;
 for (auto &block : region->GetBlocks()) {
  for (auto it=block.ilist.begin(); it!=block.ilist.end();) {
   auto *ins=&*it++;
   if (runtime.relocate && ins->GetOpcode()==Op::_gbr) IListBase::remove(ins); // standalone return harness only
   if (ins->GetOpcode()==Op::_vchunkload) { check(loads==publications,"load publishes before next guest load"); ++loads; }
   if (ins->GetOpcode()==Op::_vstatechunkstore) ++publications;
  }
 }
 check(store || (loads==(partial?4u:2u) && loads==publications),"production QCG publication order in both arms");
 auto code=qcg::GenerateCode(&runtime,&job.segment,region,pc);
 runtime.allocated_pins=region->n_pins;
 check(runtime.sites.size()==(partial?4u:2u),"exact full/partial access count, state accesses excluded");
 char filename[96];
 snprintf(filename,sizeof(filename),"emitted-%s-eew%u-partial%d.bin",store?"store":"load",eew,partial);
 FILE *out=fopen(filename,"wb");check(out && fwrite(code.data(),1,code.size(),out)==code.size(),"retain actual emitted bytes");fclose(out);
 snprintf(filename,sizeof(filename),"sites-%s-eew%u-partial%d.txt",store?"store":"load",eew,partial);
 out=fopen(filename,"w");check(out,"retain final site records");
 for(auto const &site:runtime.sites) fprintf(out,"offset=%u guest_pc=%08x raw=%08x disp=%u base_state=%u bytes=%u eew=%u addr_reg=%u data_reg=%u mask=%u store=%d cold=%u\n",
  site.code_offset,site.guest_pc,site.raw,site.displacement,site.base_state_offs,site.bytes,site.eew_bytes,site.address_reg,site.data_reg,site.mask_reg,site.store,site.cold_offset);
 fclose(out);
 auto *bytes=code.data();size_t end=code.size();
 check(bytes[0]==0x51,"normal nonleaf frame prologue");
 bytes[end++]=0x59;bytes[end]=0xc3; // undo nonleaf alignment push, return to Enter
 for (auto const &site : runtime.sites) {
  NativeMemorySite found;
  check(site.guest_pc==pc+4 && site.raw==words[1] && site.bytes==64 && site.eew_bytes==eew &&
        site.base_state_offs==offsetof(CPUState,gpr)+20 && site.address_reg==qcg::ArchTraits::AX &&
        site.data_reg<32 && site.store==store,"exact static guest/access/register metadata");
  check(bytes[site.code_offset]==0x62,"final site starts at EVEX guest instruction");
  check(tcache::InspectNativeMemorySite((uptr)bytes+site.code_offset,found) && found.raw==site.raw,
        "runtime copied exact finalized PC metadata");
  check(!tcache::InspectNativeMemorySite((uptr)bytes+site.code_offset+1,found),"interior instruction PC rejected");
 }
 // A revocation removes guest lookup/link ownership, not the underlying bytes.
 tcache::RevokeTarget(pc);
 NativeMemorySite found;
 check(tcache::InspectNativeMemorySite((uptr)bytes+runtime.sites[0].code_offset,found),"metadata lives with code allocation after revocation");
 return code;
}
static void cell(CPUState *s, bool store, u32 eew, bool partial, u32 inside)
{
 SiteRuntime runtime; MemArena arena(4u<<20); auto code=emit(runtime,arena,store,eew,partial);
 mmu::mprotect(data,8192,PROT_READ|PROT_WRITE);
 clear(s);s->vec.Reset(1024);s->vec.vtype=eew==4?16:24;
 s->vec.vl=partial?96/eew:128/eew;s->gpr[5]=data+4096-64-inside;s->gpr[6]=0;
 auto *memory=(u8*)mmu::g2h(data);
 for(unsigned i=0;i<8192;++i)memory[i]=(u8)(i*5+3);
 s->vec.vreg[8].fill(0x67);
 std::array<u8,128> before;memcpy(before.data(),s->vec.vreg[8].data(),128);
 std::array<u8,128> input;memcpy(input.data(),mmu::g2h(s->gpr[5]),128);
 // Normal emitted execution of this same shape, on a separate initialized state.
 Enter(s,mmu::base,code.data());
 check(s->gpr[6]==0x123 && s->vec.vstart==0 && s->trapno==rv32::TrapCode::NONE,"native normal earlier scalar effects and return");
 for(unsigned i=0;i<128;++i) {
  check(s->vec.vreg[8][i]==(!store && i<s->vec.vl*eew?input[i]:before[i]),"native normal complete destination/tail");
 }
 // Reset before fork; this is a distinct test invocation, not a fault retry.
 memcpy(mmu::g2h(s->gpr[5]),input.data(),128);memcpy(s->vec.vreg[8].data(),before.data(),128);
 s->gpr[6]=0;s->ip=pc;
 memset(capture,0,sizeof(*capture));capture_inside=inside;
 capture_state=s;capture_prefix=(u8*)mmu::g2h(s->gpr[5]);
 capture_site=runtime.sites[partial?3:1];capture_pc=(uptr)code.data()+capture_site.code_offset;
 check(capture_site.displacement==64 && capture_site.mask_reg==(partial?7:0xff),"exact second access/mask selected");
 check(qcgstub_rv32_unit_memory_safe(s,word(eew,store))==1,"MMU permission preflight admits fixture");
 auto epoch=mmu::MappingEpoch();
 pid_t child=fork();check(child>=0,"fault inspection fork");
 if(child==0) {
  struct sigaction sa{};sa.sa_sigaction=inspect_once;sa.sa_flags=SA_SIGINFO;sigfillset(&sa.sa_mask);
  sigaction(SIGSEGV,&sa,nullptr);sigaction(SIGBUS,&sa,nullptr);
  if(::mprotect(mmu::g2h(data+4096),4096,PROT_NONE) || mmu::MappingEpoch()!=epoch ||
     qcgstub_rv32_unit_memory_safe(s,word(eew,store))!=1) _exit(92);
  Enter(s,mmu::base,code.data());_exit(93); // fixture must fault once
 }
 int status;waitpid(child,&status,0);check(WIFEXITED(status)&&WEXITSTATUS(status)==0,"one exact owned PC captured then process exited");
 check(capture->signal==SIGSEGV && capture->code==SEGV_ACCERR && capture->address==(uptr)mmu::g2h(data+4096),"actual host fault identity");
 check(capture->ip==pc+4 && capture->gpr6==0x123 && capture->vl==s->vec.vl && capture->vstart==0,
       "PC and earlier scalar effects retained; vstart remains unrecovered");
 for(unsigned i=0;i<128;++i)
  check(capture->destination[i]==(!store && i<64?input[i]:before[i]),"completed load chunk published, faulting chunk unchanged");
 for(unsigned i=0;i<64;++i)
  check(capture->prefix[i]==(store?before[i]:input[i]),"earlier guest-memory effects retained");
 char filename[96];snprintf(filename,sizeof(filename),"capture-%s-eew%u-partial%d-inside%u.bin",store?"store":"load",eew,partial,inside);
 FILE *out=fopen(filename,"wb");check(out && fwrite(capture,1,sizeof(*capture),out)==sizeof(*capture),"retain complete local capture");fclose(out);
 if(inside) {
  printf("FAULT_CHUNK_OBSERVED store=%d eew=%u partial=%d valid_prefix=",store,eew,partial);
  for(u32 i=0;i<inside;++i)printf("%02x",capture->in_chunk_prefix[i]);
  printf(" (observed bytes only, no completed-lane claim)\n");
 }
 printf("NATIVE_SITE_CAPTURE store=%d eew=%u partial=%d fault_within_chunk=%u host_offset=%u data_reg=%u mask=%u published_load_bytes=%u observed_vstart=%u (NO recovery/retry)\n",
        store,eew,partial,inside,capture_site.code_offset,capture_site.data_reg,capture_site.mask_reg,store?0:64,capture->vstart);
 ++cells;
}
#ifndef RVV_NATIVE_FAULT_FIXTURE
int main()
{
 check(__builtin_cpu_supports("avx512f")&&__builtin_cpu_supports("bmi2"),"actual host features, no force emission");
 config::fast_boot=true;tcache::Init();mmu::Init();ukernel::process.main_thread=std::make_unique<uthread>();
 auto *s=CPUState::Current();check(mmu::mmap(data,8192,PROT_READ|PROT_WRITE)!=MAP_FAILED,"guest program mapping");
 capture=(Capture*)::mmap(nullptr,sizeof(Capture),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANON,-1,0);
 check(capture!=MAP_FAILED,"shared local capture");
 for(bool store:{false,true})for(u32 eew:{4u,8u})for(bool partial:{false,true})for(u32 inside:{0u})
  cell(s,store,eew,partial,inside);
 SiteRuntime runtime;MemArena arena(4u<<20);auto code=emit(runtime,arena,false,4,false);
 auto old=(uptr)code.data()+runtime.sites[0].code_offset;NativeMemorySite found;
 tcache::Invalidate();check(!tcache::InspectNativeMemorySite(old,found),"pool reset retires all exact PC metadata");
 tcache::Destroy();check(!tcache::InspectNativeMemorySite(old,found),"pool destroy has no stale ownership");
 printf("LOCAL_NATIVE_MEMORY_SITE_PASS checks=%u cells=%u ABI=%016llx (inspection and publication only)\n",checks,cells,(unsigned long long)rv32::CPUStateAbiSignature());
}

#endif
