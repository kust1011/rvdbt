#include <cpuid.h>
#include <cstdio>
#include <immintrin.h>
int main(){unsigned a,b,c,d;__cpuid(1,a,b,c,d);unsigned lo,hi;asm volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0));printf("CPUID1_ECX=%08x XCR0=%08x%08x\n",c,hi,lo);if(!(c&(1u<<27))||(lo&0xe6)!=0xe6)return 1;__cpuid_count(7,0,a,b,c,d);printf("CPUID7_EBX=%08x avx512f=%u bw=%u dq=%u vl=%u\n",b,(b>>16)&1,(b>>30)&1,(b>>17)&1,(b>>31)&1);if((b&0xc0030000)!=0xc0030000)return 2;alignas(64) volatile unsigned lanes[16];asm volatile("vpxord %%zmm0, %%zmm0, %%zmm0\n\tvmovdqa64 %%zmm0, %0":"=m"(lanes)::"zmm0");for(auto x:lanes)if(x)return 3;puts("AVX512 instruction execution PASS");}
