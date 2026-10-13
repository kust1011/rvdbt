// Execute the production scalar insertion emitter and interpreter helpers.
#include "dbt/arena.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector_cascade.h"
#include "dbt/guest/rv32_vector_fast.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir_builder.h"
#include <cstdio>
#include <cstdlib>
#include <sys/mman.h>

using namespace dbt;
using namespace dbt::rv32;
using namespace dbt::rv32::rvv_ref;
extern "C" unsigned rvv_run_unroll2;
static unsigned checks;
#define REQUIRE(x)                                                                                                     \
  do {                                                                                                                 \
    ++checks;                                                                                                          \
    if (!(x)) {                                                                                                        \
      std::fprintf(stderr, "line %d: %s\n", __LINE__, #x);                                                             \
      std::exit(1);                                                                                                    \
    }                                                                                                                  \
  } while (0)

using namespace dbt::qir;
namespace
{
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
      Panic("FMA regression mmap");
    return mem;
  }
  bool AllowsRelocation() const override { return false; }
  void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
};
// Same QCG ABI entry used by ccrf_sequential_microkernel_test.
extern "C" __attribute__((noinline, naked)) void EnterFma(void *, void *, void *);
extern "C" __attribute__((noinline, naked)) void EnterFma(void *, void *, void *)
{
  asm("pushq %rbp\n\tpushq %rbx\n\tpushq %r12\n\tpushq %r13\n\tpushq %r14\n\tpushq %r15\n\t"
      "movq %rdi,%r13\n\tmovq %rsi,%rbp\n\t");
  asm("sub $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
  asm("callq *%rdx\n\t");
  asm("add $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
  asm("popq %r15\n\tpopq %r14\n\tpopq %r13\n\tpopq %r12\n\tpopq %rbx\n\tpopq %rbp\n\tretq\n\t");
}
} // namespace
extern "C" void qcgstub_rv32_vmvsx(CPUState *, u32);
extern "C" void qcgstub_rv32_vfmvsf(CPUState *, u32);
int main()
{
  qcg::ArchTraits::init();
  for (bool fp : {false, true})
    for (u32 sew : {1u, 2u, 4u, 8u}) {
      if (fp && sew < 4) continue;
      config::vlen_bits = 128;
      MemArena arena(1u << 20);
      auto *region = arena.New<Region>(&arena, &info);
      Builder b(region->CreateBlock());
      b.Create_vscalarmove(8, 24, sew, true, fp);
      Runtime rt;
      auto code = qcg::GenerateCode(&rt, nullptr, region, 0);
      REQUIRE(!code.empty());
      size_t end = code.size();
      if (code.data()[0] == 0x51) code.data()[end++] = 0x59;
      code.data()[end] = 0xc3;
      for (bool helper : {false, true})
        for (bool ta : {false, true})
          for (u32 vl : {0u, 1u, 2u})
            for (u32 start : {0u, 1u, 2u, 3u})
              for (u64 payload : {0xffffffff81234567ull, 0x0000000081234567ull,
                                  0xffffffff7f800001ull, 0xffffffff80000000ull}) {
                CPUState state(nullptr);
                state.vec.Reset(128);
                state.vec.vtype = (__builtin_ctz(sew) << 3) | (ta ? 64 : 0);
                state.vec.vl = vl; state.vec.vstart = start;
                for (u32 r = 0; r < 32; ++r) state.vec.vreg[r].fill(0x5a + r);
                state.gpr[24] = 0x81234567;
                state.fpu.f[24] = payload;
                state.fpu.fcsr = 0x9f;
                auto before = state.vec;
                auto fp_before = state.fpu;
                auto mxcsr = _mm_getcsr();
                if (helper) {
                  u32 raw = (16u << 26) | (1u << 25) | (24u << 15) |
                            ((fp ? 5u : 6u) << 12) | (8u << 7) | 0x57;
                  if (fp) qcgstub_rv32_vfmvsf(&state, raw);
                  else qcgstub_rv32_vmvsx(&state, raw);
                } else EnterFma(&state, nullptr, code.data());
                REQUIRE(_mm_getcsr() == mxcsr);
                REQUIRE(state.vec.vstart == 0);
                REQUIRE(state.vec.vl == vl && state.vec.vtype == before.vtype);
                REQUIRE(state.fpu.fcsr == fp_before.fcsr);
                REQUIRE(std::memcmp(state.fpu.f, fp_before.f, sizeof(state.fpu.f)) == 0);
                // Independent active-element oracle; all other bytes, including tails,
                // stay undisturbed for this implementation's allowed ta choice.
                u64 expected = fp ? (sew == 4 && (payload >> 32) != 0xffffffffu ?
                                      0x7fc00000ull : payload) : 0xffffffff81234567ull;
                auto image = before;
                if (start == 0 && vl > 0) {
                  for (u32 byte = 0; byte < sew; ++byte)
                    image.vreg[8][byte] = (expected >> (8 * byte)) & 255;
                }
                REQUIRE(state.vec.vreg == image.vreg);
              }
    }
  std::printf("PASS %u checks scalar insertion direct/helper\n", checks);
}
