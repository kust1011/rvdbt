#include "gmini.h"

typedef unsigned u32;
typedef unsigned long long u64;
static u32 input32[4][32] __attribute__((aligned(64)));
static u64 input64[4][16] __attribute__((aligned(64)));
static u32 output32[32] __attribute__((aligned(64)));
static u64 output64[16] __attribute__((aligned(64)));

#ifdef FRAME_FMA_SINGLE
#ifdef FRAME_FMA_RESIDENCY
#define FRAME_OPERATIONS \
        "vfadd.vv v12, v12, v10\n" \
        "addi t0, zero, 1\n" \
        "vfmacc.vf v12, fa0, v8\n"
#else
#define FRAME_OPERATIONS "vfmacc.vf v12, fa0, v8\n"
#endif
#define SCALAR_LOAD_32 "flw fa0, (%[b])\n"
#define SCALAR_LOAD_64 "fld fa0, (%[b])\n"
#else
#define SCALAR_LOAD_32 ""
#define SCALAR_LOAD_64 ""
#ifdef FRAME_FMA
#define FRAME_OPERATIONS \
        "vfmacc.vv v8, v9, v10\n" \
        "vfnmsub.vv v8, v9, v13\n" \
        "vfmadd.vv v12, v8, v13\n"
#else
#define FRAME_OPERATIONS \
        "vfadd.vv v8, v8, v9\n" \
        "vfmul.vv v8, v8, v10\n" \
        "vfsub.vv v12, v8, v13\n"
#endif
#endif

#define CHAIN(SEW, INPUT, OUTPUT) \
    u32 actual; \
    __asm__ volatile( \
        "vsetvli zero, %[full], e" #SEW ", m1, ta, ma\n" \
        "vle" #SEW ".v v8, (%[a])\n" \
        "vle" #SEW ".v v9, (%[b])\n" \
        "vle" #SEW ".v v10, (%[c])\n" \
        "vle" #SEW ".v v13, (%[d])\n" \
        "vle" #SEW ".v v12, (%[a])\n" \
        SCALAR_LOAD_##SEW \
        "vsetvli %[actual], %[request], e" #SEW ", m1, ta, ma\n" \
        FRAME_OPERATIONS \
        "vse" #SEW ".v v12, (%[out])\n" \
        : [actual] "=&r"(actual) \
        : [full] "r"(full), [request] "r"(request), \
          [a] "r"(INPUT[0]), [b] "r"(INPUT[1]), [c] "r"(INPUT[2]), \
          [d] "r"(INPUT[3]), [out] "r"(OUTPUT) \
        : "v8", "v9", "v10", "v12", "v13", "fa0", "t0", "memory"); \
    return actual

__attribute__((noinline)) static u32 chain32(u32 full, u32 request)
{
    CHAIN(32, input32, output32);
}

__attribute__((noinline)) static u32 chain64(u32 full, u32 request)
{
    CHAIN(64, input64, output64);
}

void _start(void)
{
    static const u32 cases32[] = {0x40c00000, 0x3f800000, 0x7f800001, 0x7fc00123,
        0x7f800000, 0x80000000, 0x00000001, 0x7f7fffff};
    static const u64 cases64[] = {0x4018000000000000ull, 0x3ff0000000000000ull,
        0x7ff0000000000001ull, 0x7ff8000000000123ull, 0x7ff0000000000000ull,
        0x8000000000000000ull, 0x0000000000000001ull, 0x7fefffffffffffffull};
    u32 bytes;
    __asm__ volatile("csrr %0, vlenb" : "=r"(bytes));
    for (u32 j = 0; j < 4; ++j) {
        for (u32 i = 0; i < 32; ++i) input32[j][i] = cases32[(i + j) % 8];
        for (u32 i = 0; i < 16; ++i) input64[j][i] = cases64[(i + j) % 8];
    }
    for (u32 frm = 0; frm <= 4; ++frm)
        for (u32 partial = 0; partial < 3; ++partial) {
            __asm__ volatile("csrw frm, %0\ncsrw fflags, zero" : : "r"(frm) : "memory");
            u32 full = bytes / 4;
            u32 n = chain32(full, partial == 0 ? full : partial == 1 ? full - 1 : 0);
            u32 flags;
            __asm__ volatile("csrr %0, fflags" : "=r"(flags));
            puthex32(frm); puthex32(n); puthex32(flags);
            for (u32 i = 0; i < n; ++i) puthex32(output32[i]);
            __asm__ volatile("csrw fflags, zero" : : : "memory");
            full = bytes / 8;
            n = chain64(full, partial == 0 ? full : partial == 1 ? full - 1 : 0);
            __asm__ volatile("csrr %0, fflags" : "=r"(flags));
            puthex32(frm); puthex32(n); puthex32(flags);
            for (u32 i = 0; i < n; ++i) {
                puthex32((u32)(output64[i] >> 32));
                puthex32((u32)output64[i]);
            }
        }
    gexit(0);
}
