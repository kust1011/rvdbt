// Executable regression for RVV FP64->FP32 precision-rounding tininess.
#include "dbt/guest/rv32_vector_lower.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
using namespace dbt;
using namespace dbt::rv32;
static unsigned checks;
#define REQUIRE(x) do { ++checks; if (!(x)) { std::fprintf(stderr,"line %d: %s\n",__LINE__,#x); std::exit(1); } } while (0)
struct Row { u64 bits; u32 result[5]; u32 flags[5]; u32 odd; u32 oddflags; };
static Row const rows[] = {
 {0x380fffffe0000000ull,{0x800000,0x7fffff,0x7fffff,0x800000,0x800000},{3,3,3,3,3},0x7fffff,3},
 {0x380fffffe0000001ull,{0x800000,0x7fffff,0x7fffff,0x800000,0x800000},{3,3,3,1,3},0x7fffff,3},
 {0x380ffffff0000000ull,{0x800000,0x7fffff,0x7fffff,0x800000,0x800000},{1,3,3,1,1},0x7fffff,3},
 {0x380fffffefffffffull,{0x800000,0x7fffff,0x7fffff,0x800000,0x800000},{3,3,3,1,3},0x7fffff,3},
 {0x3810000000000000ull,{0x800000,0x800000,0x800000,0x800000,0x800000},{0,0,0,0,0},0x800000,0},
 {0x380fffffffffffffull,{0x800000,0x7fffff,0x7fffff,0x800000,0x800000},{1,3,3,1,1},0x7fffff,3},
 {0x380fffffc0000000ull,{0x7fffff,0x7fffff,0x7fffff,0x7fffff,0x7fffff},{0,0,0,0,0},0x7fffff,0},
 {0x3690000000000000ull,{0,0,0,1,1},{3,3,3,3,3},1,3},
 {0x36a0000000000000ull,{1,1,1,1,1},{0,0,0,0,0},1,0},
 {0x3ff0000010000000ull,{0x3f800000,0x3f800000,0x3f800000,0x3f800001,0x3f800001},{1,1,1,1,1},0x3f800001,1},
 {0x0000000000000000ull,{0,0,0,0,0},{0,0,0,0,0},0,0},
 {0x7ff0000000000000ull,{0x7f800000,0x7f800000,0x7f800000,0x7f800000,0x7f800000},{0,0,0,0,0},0x7f800000,0},
};
int main()
{
 for (auto const &row:rows) for (u32 sign: {0u,1u}) for(u32 rm:{0u,1u,2u,3u,4u,8u}) {
  u32 directed = sign && (rm==2 || rm==3) ? 5-rm : rm;
  u32 const want=(rm==8 ? row.odd : row.result[directed]) | (sign<<31);
  u32 const raised=rm==8 ? row.oddflags : row.flags[directed];
  for(u32 initial:{0u,9u,16u,31u}) {
   u32 flags=initial;
   REQUIRE(rvv_fpconvert::cvt_fmt(row.bits|((u64)sign<<63),softfp::FMT64,softfp::FMT32,rm,flags)==want);
   REQUIRE(flags==(initial|raised));
  }
 }
 for(u64 nan:{0x7ff8000000000007ull,0x7ff0000000000001ull}) for(u32 rm:{0u,1u,2u,3u,4u,8u}) {
  u32 fl=1;REQUIRE(rvv_fpconvert::cvt_fmt(nan,softfp::FMT64,softfp::FMT32,rm,fl)==0x7fc00000);
  REQUIRE(fl==(nan==0x7ff8000000000007ull ? 1u : 17u));
 }
 // Actual vector helper: sticky UF, inactive sNaN suppression, prestart, masks,
 // tail preservation and host MXCSR restoration. Guest matrices test the QCG
 // guard/fallback and all four execution arms independently.
 for(u32 frm=0;frm<5;++frm) for(bool odd:{false,true}) for(bool vm:{false,true})
  for(u32 start:{0u,1u}) for(u32 vl:{0u,1u,2u,4u}) for(u32 initial:{0u,9u,16u,31u}) {
   VectorState vs{};vs.Reset(128);FPUState fs{};fs.fcsr=frm<<5|initial;vs.vstart=start;
   for(u32 i=0;i<4;++i) {vs.elem_put(16,i,8,128,(!vm && i%2) ? 0x7ff0000000000001ull : rows[0].bits);vs.elem_put(8,i,4,128,0x11223344);vs.mask_set(0,i,i%2==0);}
   u32 const mxcsr=_mm_getcsr();rvv_ref::vfcvt(vs,fs,odd?21:20,8,16,vm,128,vl,8,4);REQUIRE(_mm_getcsr()==mxcsr);
   bool any=false;
   for(u32 i=0;i<4;++i) {
    bool active=i>=start && i<vl && (vm || i%2==0);any|=active;
    u32 value=odd ? rows[0].odd : rows[0].result[frm];
    REQUIRE(vs.elem_u(8,i,4,128)==(active ? value : 0x11223344));
   }
   REQUIRE((fs.fcsr&31)==(initial|(any?3u:0u)));
  }
 std::printf("PASS %u checks\n",checks);
}
