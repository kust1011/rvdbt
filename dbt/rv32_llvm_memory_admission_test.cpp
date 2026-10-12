// Bounded engineering check. Reuse translation and host fault scaffolds; no guest retry.
#define main UnitHostMain
#include "dbt/rv32_unit_memory_fault_test.cpp"
#undef main
#define main WholeIRMain
#include "dbt/qmc/llvmgen/rvv_llvm_wholereg_mem_test.cpp"
#undef main
#include "llvm/ExecutionEngine/MCJIT.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/Verifier.h"
#include "llvm/TargetParser/Host.h"

extern "C" u32 qcgstub_rv32_special_memory_safe(CPUState *, u32);
extern "C" void qcgstub_rv32_vlNre(CPUState *, u32);
extern "C" void qcgstub_rv32_vsNr(CPUState *, u32);
static u32 target_raw, latest_base, prior_reg, bytes;
static unsigned safe_calls, fallback_calls;
static bool force_fallback;
static std::array<u8, dbt::rv32::VLEN_MAX_BYTES> prior_bytes;
static void observe(CPUState *s, u32 raw)
{
 if (raw != target_raw) return;
 check(s->gpr[10] == latest_base, "latest scalar definition published");
 check(s->ip == 8, "original target PC before call");
 check(s->vec.vreg[prior_reg] == prior_bytes, "preceding SSA vector load published");
}
static u32 safe_observer(CPUState *s, u32 raw)
{
 observe(s, raw);
 if (raw == target_raw) ++safe_calls;
 u32 result=qcgstub_rv32_special_memory_safe(s, raw);
 return raw==target_raw && force_fallback ? 0 : result;
}
static void load_observer(CPUState *s, u32 raw)
{
 observe(s, raw);
 if (raw == target_raw) ++fallback_calls;
 qcgstub_rv32_vlNre(s, raw);
}
static void store_observer(CPUState *s, u32 raw)
{
 observe(s, raw);
 if (raw == target_raw) ++fallback_calls;
 qcgstub_rv32_vsNr(s, raw);
}
int main()
{
 llvm::InitializeNativeTarget(); llvm::InitializeNativeTargetAsmPrinter();
 mmu::Init(); ukernel::process.main_thread = std::make_unique<uthread>();
 auto *s = CPUState::Current();
 unsigned normal_count=0, denied_count=0, restart_count=0;
 for (u32 vlen : {512u,1024u}) for (bool store : {false,true}) {
  Configure(vlen); config::rvv_vector_ssa_counters=true;
  prior_reg=store?8:12; bytes=vlen/8;
  target_raw=store?VsNr(1,10,8):VlNre(1,kW32,10,8);
  // A checked whole load, scalar base update, then the target memory instruction.
  Built b({VlNre(1,kW32,11,prior_reg), (64u<<20)|(10u<<15)|(10u<<7)|0x13u,
           target_raw,kJalr});
  Translate(b,true);
  auto module=llvm::CloneModule(b.module);
  auto *fn=module->getFunction(b.fn->getName());
  // Bound the region at its dispatcher exit. Preserve every translated guest/state
  // operation; adapt only GHC entry ABI and terminal dispatch for a host C caller.
  unsigned exits=0;
  for(auto &bb:*fn) for(auto it=bb.begin();it!=bb.end();++it)
   if(auto *call=llvm::dyn_cast<llvm::CallInst>(&*it);
      call && call->getCallingConv()==llvm::CallingConv::GHC) {
    while(&bb.back()!=call) bb.back().eraseFromParent();
    call->eraseFromParent();
    llvm::IRBuilder<> ib(&bb); ib.CreateRetVoid(); ++exits; break;
   }
  check(exits==1,"exactly one terminal dispatcher exit adapted");
  // Observe the real production stub calls through same-signature host shims.
  for(auto &bb:*fn)for(auto &ins:bb)if(auto *call=llvm::dyn_cast<llvm::CallInst>(&ins)) {
   if(call->arg_size()!=2)continue;
   auto *raw=llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(1));
   if(!raw || (raw->getZExtValue()!=target_raw && raw->getZExtValue()!=b.words[0]))continue;
   uptr shim=call->getType()->isIntegerTy(32)?(uptr)safe_observer:
    ((raw->getZExtValue()&0x7f)==0x27?(uptr)store_observer:(uptr)load_observer);
   call->setCalledOperand(llvm::ConstantExpr::getIntToPtr(
    llvm::ConstantInt::get(llvm::Type::getInt64Ty(g_ctx),shim),call->getCalledOperand()->getType()));
  }
  fn->setCallingConv(llvm::CallingConv::C);
  module->setTargetTriple(llvm::Triple(llvm::sys::getDefaultTargetTriple()));
  std::string error;
  auto *engine=llvm::EngineBuilder(std::move(module)).setEngineKind(llvm::EngineKind::JIT)
   .setErrorStr(&error).setOptLevel(llvm::CodeGenOptLevel::Aggressive).create();
  check(engine!=nullptr,error.c_str());
  auto *m=fn->getParent(); m->setDataLayout(engine->getDataLayout());
  llvm::LoopAnalysisManager lam; llvm::FunctionAnalysisManager fam;
  llvm::CGSCCAnalysisManager cgam; llvm::ModuleAnalysisManager mam; llvm::PassBuilder pb;
  pb.registerModuleAnalyses(mam); pb.registerCGSCCAnalyses(cgam);
  pb.registerFunctionAnalyses(fam); pb.registerLoopAnalyses(lam);
  pb.crossRegisterProxies(lam,fam,cgam,mam);
  auto passes=pb.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O3); passes.run(*m,mam);
  check(!llvm::verifyModule(*m,&llvm::errs()),"optimized module verifies");
  auto code=(void(*)(CPUState*,void*))engine->getFunctionAddress(fn->getName().str());
  check(code!=nullptr,"LLVM native code exists");
  for(unsigned mode=0;mode<4;++mode) {
   check(mmu::mmap(data,16384,PROT_READ|PROT_WRITE)!=MAP_FAILED,"map test pages");
   auto *mem=(u8*)mmu::g2h(data); std::array<u8,16384> expected_mem;
   for(u32 i=0;i<16384;++i)mem[i]=expected_mem[i]=(u8)(i*13+5);
   clear(s); s->ip=0; s->vec.Reset(vlen); s->vec.vtype=dbt::rv32::VTYPE_VILL_BIT; s->vec.vl=0;
   for(u32 r=0;r<32;++r)for(u32 i=0;i<dbt::rv32::VLEN_MAX_BYTES;++i)s->vec.vreg[r][i]=(u8)(r*17+i*3);
   s->gpr[11]=data+8192;
   latest_base=data+(mode==1?4096-8:mode==2?4096+32:256);
   s->gpr[10]=latest_base-64;
   auto expected=s->vec;
   memcpy(expected.vreg[prior_reg].data(),mem+8192,bytes);
   prior_bytes=expected.vreg[prior_reg];
   // Mode3 forces a guard miss at the target after checking real admission.
   unsigned transferred=mode==1?8:bytes;
   if(store)memcpy(expected_mem.data()+latest_base-data,expected.vreg[8].data(),transferred);
   else memcpy(expected.vreg[8].data(),expected_mem.data()+latest_base-data,transferred);
   if(mode==1)check(mmu::mprotect(data+4096,4096,PROT_NONE)==0,"deny latest range");
   if(mode==2)check(mmu::mprotect(data,4096,PROT_NONE)==0,"deny stale range only");
   force_fallback=mode==3;
   safe_calls=fallback_calls=0; s->rvv_direct_hits=s->rvv_direct_fallbacks=0;
   if(sigsetjmp(trap_unwind_env,0)==0)code(s,mmu::base);
   check(safe_calls==1,"one target admission call");
   check(fallback_calls==1,"executed target fallback count");
   check(s->vec.vreg==expected.vreg,"complete vector state after native/fallback/fault");
   check(s->gpr[10]==latest_base,"updated scalar remains architectural");
   if(mode==1) {
    auto const &ev=s->GetUThread()->memory_fault;
    check(s->trapno==dbt::rv32::TrapCode::MEMORY_FAULT && s->GetUThread()->memory_fault_pending,"fault pending");
    check(s->ip==8 && ev.pc==8 && ev.raw==target_raw && ev.address==data+4096,"fault original PC/raw/address");
    check(ev.element==(store?8:2) && ev.eew_bytes==(store?1:4),"fault effective unit");
    auto snap=ukernel::CaptureHelperMemoryFault(s);
    check(snap.vreg==expected.vreg && snap.pc==8 && snap.csrs[3]==ev.element,"fault snapshot once");
    ++denied_count;
   } else {check(!s->GetUThread()->memory_fault_pending,"normal completion"); if(mode==3)++restart_count;else ++normal_count;}
   check(s->rvv_direct_hits==0,"actual LLVM native hit counter");
   check(s->rvv_direct_fallbacks==2,"actual LLVM fallback counter");
   check(s->vec.vtype==dbt::rv32::VTYPE_VILL_BIT && s->vec.vl==0,"whole independent geometry");
   // Read-only inspection cleanup, after execution ended; never reenter this state.
   mmu::mprotect(data,8192,PROT_READ|PROT_WRITE);
   check(!memcmp(mem,expected_mem.data(),16384),"complete memory prefix and denied bytes");
   printf("LLVM_CELL vlen=%u store=%d mode=%u safe=%u fallback=%u hits=%llu misses=%llu PASS\n",
    vlen,store,mode,safe_calls,fallback_calls,(unsigned long long)s->rvv_direct_hits,(unsigned long long)s->rvv_direct_fallbacks);
  }
  delete engine;
 }
 printf("LLVM_EXECUTE_PASS normal=%u denied=%u forced_fallback=%u checks=%u (no guest retry)\n",normal_count,denied_count,restart_count,checks);
}
