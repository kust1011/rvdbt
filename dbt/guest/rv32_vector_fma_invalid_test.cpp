// Focused executable regression for RVV's 0*infinity + qNaN invalid rule.
// The frozen directed guests separately exercise QCG's emitted FMA path.
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
void fast_dispatch()
{
  config::rvv_fround_batch = false;
  config::rvv_fast_classes = 4;
  for (u32 policy : {0u, 1u})
    for (u32 sew : {4u, 8u})
      for (u32 f6 = 40; f6 < 48; ++f6)
        for (bool scalar : {false, true})
          for (u32 rm = 0; rm < 4; ++rm)
            for (bool residue : {false, true})
              for (bool invalid : {false, true}) {
                config::rvv_width_policy = policy;
                VectorState vs{};
                vs.Reset(1024);
                FPUState fs{};
                fs.fcsr = (rm << 5) | 1;
                u32 n = 64 / sew + 1, bad = residue ? n - 1 : 0;
                u64 inf = sew == 4 ? 0x7f800000ull : 0x7ff0000000000000ull;
                u64 nan = sew == 4 ? 0x7fc00007ull : 0x7ff8000000000007ull;
                u64 canon = sew == 4 ? 0x7fc00000ull : 0x7ff8000000000000ull;
                // Scalar multiplier stays infinity; a finite
                // nonzero product is a control against
                // treating any infinity or any NaN as
                // invalid.
                u64 one = sew == 4 ? 0x3f800000ull : 0x3ff0000000000000ull;
                fs.f[24] = sew == 4 ? 0xffffffff00000000ull | inf : inf;
                for (u32 e = 0; e < n; ++e) {
                  u64 x = invalid && e == bad ? 0 : one;
                  vs.elem_put(16, e, sew, 1024, f6 < 44 ? nan : x);
                  vs.elem_put(24, e, sew, 1024, inf);
                  vs.elem_put(8, e, sew, 1024, f6 < 44 ? x : nan);
                }
                u8 next[8]{};
                auto saved = _mm_getcsr();
                REQUIRE(rvv_fast::try_fma(vs, fs, f6, scalar, 8, 16, 24, true, 1024, n, sew, 0, 0, next));
                REQUIRE(fs.fflags() == (invalid ? 17 : 1));
                REQUIRE(_mm_getcsr() == saved);
                for (u32 e = 0; e < n; ++e)
                  REQUIRE(vs.elem_u(8, e, sew, 1024) == canon);
              }
}
void emitted()
{
  qcg::ArchTraits::init();
  config::rvv_qcg_hit_counter = true;
  for (u32 width : {16u, 32u, 64u})
    for (u32 sew : {4u, 8u})
      for (u32 f6 = 40; f6 < 48; ++f6)
        for (bool shared : {false, true})
          for (bool masked : {false, true})
            for (bool full : {false, true})
              for (bool scalar : {false, true}) {
                u32 lanes = width / sew, vtype = sew == 4 ? 0xd0 : 0xd8;
                config::vlen_bits = width * 8;
                MemArena arena(1u << 20);
                auto *region = arena.New<Region>(&arena, &info);
                Builder b(region->CreateBlock());
                using G = InstRVVTypedChunkBegin::GuardKind;
                // Both full-VL and runtime active masks enter the
                // real production frame.
                if (full)
                  b.Create_rvvtypedchunkbegin(vtype, lanes, 0u, RuntimeStubId::id_rv32_vfma, shared ? 8 : 7);
                else
                  b.Create_rvvtypedchunkbegin(vtype, lanes, 0u, RuntimeStubId::id_rv32_vfma, shared ? 8 : 7,
                                              G::VTypeFpAnyRM);
                b.Create_rvvqcgfpbegin();
                if (shared)
                  b.Create_vchunkmaskset(0, lanes);
                qir::VType ty = width == 16 ? qir::VType::V128 : width == 32 ? qir::VType::V256 : qir::VType::V512;
                auto value = [&]() { return VOperand::MakeVVPR(ty, b.CreateVGPR(ty)); };
                auto a = value(), y = value(), d = value(), out = value();
                auto off = [](u32 r) {
                  return offsetof(CPUState, vec) + offsetof(VectorState, vreg) + r * VLEN_MAX_BYTES;
                };
                b.Create_vstatechunkload(a, off(16));
                if (scalar)
                  b.Create_vchunkfbroadcast(y, offsetof(CPUState, fpu) + offsetof(FPUState, f) + 24 * sizeof(u64), sew);
                else
                  b.Create_vstatechunkload(y, off(24));
                b.Create_vstatechunkload(d, off(8));
                b.Create_vchunkfma(out, d, y, a, sew, f6, 0, shared ? 1 : 0, masked);
                b.Create_vstatechunkstore(off(8), out);
                b.Create_rvvqcgfpend();
                b.Create_rvvtypedchunkend(0u, RuntimeStubId::id_rv32_vfma);
                Runtime rt;
                auto code = qcg::GenerateCode(&rt, nullptr, region, 0);
                REQUIRE(!code.empty());
                size_t end = code.size();
                if (code.data()[0] == 0x51)
                  code.data()[end++] = 0x59;
                code.data()[end] = 0xc3;
                // A hand-built region has no guest exit. Its
                // successful frame jumps to the end of the
                // instruction stream, before AsmJit's literal pool.
                // Redirect that join to the test-only return appended
                // after the pool. Identify it by the enabled
                // frame-hit counter, leaving all arithmetic and
                // fallback bytes intact.
                unsigned exits = 0;
                for (size_t i = 0; i + 12 <= code.size(); ++i) {
                  u32 offset = 0;
                  std::memcpy(&offset, code.data() + i + 3, 4);
                  if (code.data()[i] == 0x49 && code.data()[i + 1] == 0xff && code.data()[i + 2] == 0x85 &&
                      offset == offsetof(CPUState, rvv_direct_hits) && code.data()[i + 7] == 0xe9) {
                    i32 delta = (i32)code.size() - (i32)(i + 12);
                    std::memcpy(code.data() + i + 8, &delta, 4);
                    ++exits;
                  }
                }
                REQUIRE(exits == 1);
                for (u32 rm = 0; rm < 4; ++rm)
                  for (bool reverse : {false, true})
                    for (bool suppress : {false, true})
                      for (bool prestart : {false, true})
                        for (bool invalid : {false, true})
                          for (bool unboxed : {false, true})
                            for (u32 initial : {0u, 1u, 16u, 31u}) {
                              CPUState state(nullptr);
                              state.vec.Reset(width * 8);
                              state.vec.vtype = vtype;
                              state.vec.vl = full ? lanes : suppress ? 0 : lanes - 1;
                              state.fpu.fcsr = (rm << 5) | initial;
                              u32 start = prestart && !full ? 1 : 0;
                              state.vec.vstart = start;
                              u64 inf = sew == 4 ? 0x7f800000ull : 0x7ff0000000000000ull;
                              u64 nan = sew == 4 ? 0x7fc00007ull : 0x7ff8000000000007ull;
                              u64 canon = sew == 4 ? 0x7fc00000ull : 0x7ff8000000000000ull;
                              u64 x = reverse ? inf : 0, yb = reverse ? 0 : inf;
                              // Only the selected lane has an invalid product. Other
                              // active lanes still produce qNaN, without invalid.
                              u32 bad = (!full && suppress) ? lanes - 1 : 0;
                              for (u32 e = 0; e < lanes; ++e) {
                                u64 one = sew == 4 ? 0x3f800000ull : 0x3ff0000000000000ull;
                                u64 px = e == bad && invalid ? x : one, py = scalar || e == bad ? yb : 0;
                                state.vec.elem_put(16, e, sew, width * 8, f6 < 44 ? nan : px);
                                state.vec.elem_put(24, e, sew, width * 8, py);
                                state.vec.elem_put(8, e, sew, width * 8, f6 < 44 ? px : nan);
                              }
                              state.fpu.f[24] = sew == 4 && !unboxed ? 0xffffffff00000000ull | yb : yb;
                              state.vec.vreg[0].fill(masked && suppress ? 0 : 0xff);
                              auto before = state.vec;
                              auto saved = _mm_getcsr();
                              EnterFma(&state, nullptr, code.data());
                              REQUIRE(_mm_getcsr() == saved);
                              REQUIRE(state.rvv_direct_fallbacks == 0);
                              REQUIRE(state.rvv_direct_hits == 1);
                              bool active = bad >= start && bad < state.vec.vl && !(masked && suppress);
                              REQUIRE(state.fpu.fflags() ==
                                      (initial | (active && invalid && !(scalar && sew == 4 && unboxed) ? 16 : 0)));
                              REQUIRE(state.fpu.frm() == rm);
                              for (u32 e = 0; e < lanes; ++e) {
                                bool on = e >= start && e < state.vec.vl && !(masked && suppress);
                                REQUIRE(state.vec.elem_u(8, e, sew, width * 8) ==
                                        (on ? canon : before.elem_u(8, e, sew, width * 8)));
                              }
                            }
              }
}
} // namespace
int main(int argc, char **argv)
{
  if (argc == 2 && std::strcmp(argv[1], "--full-vl-mask-fusion") == 0)
    config::rvv_qcg_active_vl_mask_fusion = true;
  else
    REQUIRE(argc == 1);
  for (u32 sew : {4u, 8u})
    for (u32 f6 = 40; f6 < 48; ++f6)
      for (bool scalar : {false, true})
        for (bool reverse : {false, true})
          for (u32 rm = 0; rm < 5; ++rm)
            for (u32 initial : {0u, 1u, 16u, 31u})
              for (u32 suppression = 0; suppression < 4; ++suppression) {
                VectorState vs{};
                FPUState fs{};
                u64 inf = sew == 4 ? 0x7f800000ull : 0x7ff0000000000000ull;
                u64 nan = sew == 4 ? 0x7fc00007ull : 0x7ff8000000000007ull;
                u64 canon = sew == 4 ? 0x7fc00000ull : 0x7ff8000000000000ull;
                u64 x = reverse ? inf : 0, y = reverse ? 0 : inf;
                u64 a = f6 < 44 ? nan : x, d = f6 < 44 ? x : nan;
                vs.elem_put(16, 0, sew, 512, a);
                vs.elem_put(24, 0, sew, 512, y);
                vs.elem_put(8, 0, sew, 512, d);
                fs.f[24] = sew == 4 ? 0xffffffff00000000ull | y : y;
                fs.fcsr = (rm << 5) | initial;
                // The invalid triple lives exclusively at
                // element 0. Mask, tail and prestart must
                // each suppress its flags and preserve its
                // destination.
                u32 vl = suppression == 2 ? 0 : 1, start = suppression == 3 ? 1 : 0;
                vfma(vs, fs, f6, scalar, 8, 16, 24, suppression != 1, 512, vl, sew, start);
                REQUIRE(fs.fflags() == (initial | (suppression == 0 ? 16 : 0)));
                REQUIRE(vs.elem_u(8, 0, sew, 512) == (suppression == 0 ? canon : d));
                REQUIRE(fs.frm() == rm);
              }
  // Adjacent widening FMA uses host double FMA after exact f32 widening.
  for (u32 f6 = 60; f6 < 64; ++f6)
    for (bool scalar : {false, true})
      for (u32 rm = 0; rm < 5; ++rm)
        for (u32 suppression = 0; suppression < 4; ++suppression) {
          VectorState vs{};
          FPUState fs{};
          fs.fcsr = (rm << 5) | 1;
          vs.elem_put(16, 0, 4, 512, 0);
          vs.elem_put(24, 0, 4, 512, 0x7f800000);
          vs.elem_put(8, 0, 8, 512, 0x7ff8000000000007ull);
          fs.f[24] = 0xffffffff7f800000ull;
          vfwarith(vs, fs, f6, scalar, 8, 16, 24, suppression != 1, 512, suppression == 2 ? 0 : 1, 4,
                   suppression == 3 ? 1 : 0);
          REQUIRE(fs.fflags() == (suppression == 0 ? 17 : 1));
          REQUIRE(vs.elem_u(8, 0, 8, 512) == (suppression == 0 ? 0x7ff8000000000000ull : 0x7ff8000000000007ull));
        }
  // Execute every multiversioned FMA kernel and scalar-operand entry at
  // 16/32/64 bytes. Return-byte counts prove a real kernel consumed the data.
  using VV = u32 (*)(void *, void const *, void const *, u32, u32, u32);
  using VF = u32 (*)(void *, void const *, u64, u32, u32, u32);
  VV vv[] = {rvv_run_fma16v, rvv_run_fma32, rvv_run_fma64};
  VF vf[] = {rvv_run_fma_vs16v, rvv_run_fma_vs32, rvv_run_fma_vs64};
  for (unsigned tier = 0; tier < 3; ++tier)
    for (u32 sew : {4u, 8u})
      for (u32 f6 = 40; f6 < 48; ++f6)
        for (bool scalar : {false, true})
          for (bool reverse : {false, true})
            for (bool unroll : {false, true}) {
              rvv_run_unroll2 = unroll;
              alignas(64) unsigned char a[128]{}, b[128]{}, d[128]{};
              u64 inf = sew == 4 ? 0x7f800000ull : 0x7ff0000000000000ull;
              u64 nan = sew == 4 ? 0x7fc00007ull : 0x7ff8000000000007ull;
              u64 canon = sew == 4 ? 0x7fc00000ull : 0x7ff8000000000000ull;
              u64 x = reverse ? inf : 0, y = reverse ? 0 : inf;
              u32 bytes = 2 * (16u << tier);
              for (u32 off = 0; off < bytes; off += sew) {
                u64 av = f6 < 44 ? nan : x, dv = f6 < 44 ? x : nan;
                std::memcpy(a + off, &av, sew);
                std::memcpy(b + off, &y, sew);
                std::memcpy(d + off, &dv, sew);
              }
              FPUState fs{};
              fs.raise(1);
              FRound round(fs, fp_mode(fs, FRM_DYN));
              REQUIRE((scalar ? vf[tier](d, a, y, bytes, f6, sew) : vv[tier](d, a, b, bytes, f6, sew)) == bytes);
              round.finish(fs);
              REQUIRE(fs.fflags() == 17);
              for (u32 off = 0; off < bytes; off += sew) {
                u64 z = 0;
                std::memcpy(&z, d + off, sew);
                REQUIRE(z == canon);
              }
            }
  fast_dispatch();
  emitted();
  std::printf("RVV_FMA_INVALID_PASS checks=%u helper_run_kernels_and_QCG=executed full_vl_mask_fusion=%u\n", checks, (unsigned)config::rvv_qcg_active_vl_mask_fusion);
}
