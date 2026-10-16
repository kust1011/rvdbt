// Execute the real QCG FP opener at its incoming-run join and observe setup
// before the epilogue. Expected flags and rounding fields are fixture bit maps,
// independent of the DUT conversion helpers. No floating-point arithmetic runs
// in the observer, including cases with nondefault exception masks.
#include "dbt/arena.h"
#include "dbt/execute.h"
#include "dbt/guest/rv32_runtime.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir_builder.h"
#include <cstdio>
#include <cstdlib>
#include <sys/mman.h>
#include <immintrin.h>
using namespace dbt;
using namespace dbt::rv32;
using namespace dbt::qir;
static unsigned checks;
#define REQUIRE(x) do { ++checks; if (!(x)) { std::fprintf(stderr,"line %d: %s\n",__LINE__,#x); std::exit(1); } } while(0)
namespace {
StateReg regs[] = {{(u16)offsetof(CPUState, gpr), qir::VType::I32, "x0"}};
StateInfo info{regs, 1};
struct Runtime final : CompilerRuntime {
  void *mem{};
  size_t bytes{};
  ~Runtime()
  {
    if (mem)
      munmap(mem, bytes);
  }
  void *AllocateCode(size_t n, uint) override
  {
    bytes = (n + 64 + 4095) & ~size_t(4095);
    mem = mmap(nullptr, bytes, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED)
      Panic("FP environment mmap");
    return mem;
  }
  bool AllowsRelocation() const override { return false; }
  void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
};
// Same QCG ABI entry used by ccrf_sequential_microkernel_test.
extern "C" __attribute__((noinline, naked)) void EnterEnv(void *, void *, void *);
extern "C" __attribute__((noinline, naked)) void EnterEnv(void *, void *, void *)
{
  asm("pushq %rbp\n\tpushq %rbx\n\tpushq %r12\n\tpushq %r13\n\tpushq %r14\n\tpushq %r15\n\t"
      "movq %rdi,%r13\n\tmovq %rsi,%rbp\n\t");
  asm("sub $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
  asm("callq *%rdx\n\t");
  asm("add $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
  asm("popq %r15\n\tpopq %r14\n\tpopq %r13\n\tpopq %r12\n\tpopq %rbx\n\tpopq %rbp\n\tretq\n\t");
}

u32 flags(u32 h) {
  return ((h & 1) ? 16 : 0) | ((h & 4) ? 8 : 0) |
         ((h & 8) ? 4 : 0) | ((h & 16) ? 2 : 0) | ((h & 32) ? 1 : 0);
}
std::span<u8> build(Runtime &rt, MemArena &arena, unsigned kind) {
  auto *region=arena.New<Region>(&arena,&info);
  Builder b(region->CreateBlock());
  if (kind != 1) b.Create_rvvqcgfpbegin();
  if (kind != 0) b.Create_rvvqcgfpend();
  if (kind == 2) { b.Create_rvvqcgfpbegin(); b.Create_rvvqcgfpend(); }
  auto code=qcg::GenerateCode(&rt,nullptr,region,0);
  REQUIRE(!code.empty());
  size_t end=code.size();
  if(code.data()[0]==0x51) code.data()[end++]=0x59;
  code.data()[end]=0xc3;
  return code;
}
}
int main(int argc,char **argv) {
  qcg::ArchTraits::init();
  MemArena a0(1u<<20),a1(1u<<20),a2(1u<<20);
  Runtime r0,r1,r2;
  auto begin=build(r0,a0,0),close=build(r1,a1,1),adjacent=build(r2,a2,2);
  if(argc==2) {
    FILE *f=std::fopen(argv[1],"wb"); REQUIRE(f);
    REQUIRE(std::fwrite(adjacent.data(),1,adjacent.size(),f)==adjacent.size());
    REQUIRE(std::fclose(f)==0);
  } else REQUIRE(argc==1);
  u32 original=_mm_getcsr();
  constexpr u32 rc[]={0,0x6000,0x2000,0x4000,0,0,0,0};
  unsigned cells=0;
  for(bool open:{false,true})
    for(u32 incoming=0;incoming<4;++incoming)
      for(u32 frm=0;frm<8;++frm)
        for(u32 hostflags=0;hostflags<64;++hostflags)
          for(u32 initial:{0u,1u,16u,31u})
            for(u32 controls:{0u,0x40u,0x8000u,0x8040u}) {
              CPUState state(nullptr);
              // Saved and current control fields deliberately differ. The
              // original host flags are restored, never accrued as guest flags.
              u32 saved=0x1f80u | controls | (((incoming+1)%4)<<13) | 0x24u;
              u32 current=0x1d80u | controls | (incoming<<13) | hostflags;
              state.fpu.fcsr=(frm<<5)|initial;
              state.fpu.fround_run_open=open;
              state.fpu.fround_run_saved_mxcsr=saved;
              state.fpu.fround_run_rc=0x6000u; // stale mirror: test actual ownership
              _mm_setcsr(current);
              EnterEnv(&state,nullptr,begin.data());
              u32 expected_saved=open?saved:current;
              u32 expected_flags=initial|(open?flags(hostflags):0u);
              REQUIRE(state.fpu.fround_run_open);
              REQUIRE(state.fpu.fround_run_saved_mxcsr==expected_saved);
              REQUIRE(state.fpu.fcsr==((frm<<5)|expected_flags));
              REQUIRE(state.fpu.fround_run_rc==rc[frm]);
              REQUIRE(_mm_getcsr()==((expected_saved & ~0xe07fu)|rc[frm]));
              // Publish new flags after the opener, then take the real close.
              // Denormal status is intentionally unrepresented in RVV fflags.
              u32 newer=(hostflags*17u+3u)&63u;
              _mm_setcsr(_mm_getcsr()|newer);
              state.vec.vstart=7;
              EnterEnv(&state,nullptr,close.data());
              REQUIRE(!state.fpu.fround_run_open);
              REQUIRE(_mm_getcsr()==expected_saved);
              REQUIRE(state.fpu.fcsr==((frm<<5)|(expected_flags|flags(newer))));
              REQUIRE(state.vec.vstart==0);
              // Two complete adjacent brackets, both paths through the opener.
              state.fpu.fcsr=(frm<<5)|initial;
              state.fpu.fround_run_open=open;
              state.fpu.fround_run_saved_mxcsr=saved;
              _mm_setcsr(current);
              EnterEnv(&state,nullptr,adjacent.data());
              REQUIRE(!state.fpu.fround_run_open);
              REQUIRE(_mm_getcsr()==expected_saved);
              REQUIRE(state.fpu.fcsr==((frm<<5)|expected_flags));
              // The normal epilogue is bypassed by helper-fault unwind.
              // Exercise it with state opened by actual generated code rather
              // than a manually seeded open-run marker.
              state.fpu.fcsr=(frm<<5)|initial;
              state.fpu.fround_run_open=open;
              state.fpu.fround_run_saved_mxcsr=saved;
              _mm_setcsr(current);
              EnterEnv(&state,nullptr,begin.data());
              _mm_setcsr(_mm_getcsr()|newer);
              state.vec.vstart=7;
              state.trapno=TrapCode::MEMORY_FAULT;
              if(sigsetjmp(trap_unwind_env,0)==0) {
                FinishHelperMemoryFault(&state);
                REQUIRE(false);
              }
              REQUIRE(!state.fpu.fround_run_open);
              REQUIRE(_mm_getcsr()==expected_saved);
              REQUIRE(state.fpu.fcsr==((frm<<5)|(expected_flags|flags(newer))));
              REQUIRE(state.vec.vstart==7);
              ++cells;
            }
  _mm_setcsr(original);
  std::printf("FP_ENVIRONMENT_ADJACENCY_PASS checks=%u cells=%u incoming_open_closed_all_rc_frm_flags_daz_ftz=executed\n",checks,cells);
}
