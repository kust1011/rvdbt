typedef unsigned u32;
static u32 a[128] __attribute__((aligned(64)));
static u32 b[128] __attribute__((aligned(64)));
static u32 out[128] __attribute__((aligned(64)));

__attribute__((noinline)) static void chain(u32 full, u32 vl, u32 restart, int macc)
{
#define SETUP "vsetvli zero, %[full], e32, m1, tu, ma\n" \
 "vle32.v v8, (%[a])\nvle32.v v10, (%[b])\n" \
 "mv t2, %[vl]\nvsetvli zero, t2, e32, m1, tu, ma\ncsrw vstart, %[restart]\n"
#define FINISH "vadd.vv v8, v8, v10\n" \
 "vsetvli zero, %[full], e32, m1, tu, ma\nvse32.v v8, (%[out])\n"
#define ARGS : : [full] "r"(full), [vl] "r"(vl), \
 [restart] "r"(restart), [a] "r"(a), [b] "r"(b), [out] "r"(out), [factor] "r"(7) \
 : "t2", "memory", "v8", "v10"
 if (macc)
  __asm__ volatile(SETUP "vmacc.vx v8, %[factor], v10\n" FINISH ARGS);
 else
  __asm__ volatile(SETUP "vmul.vx v8, v8, %[factor]\n" FINISH ARGS);
}

__attribute__((noreturn)) void _start(void)
{
 u32 bytes;
 __asm__ volatile("csrr %0, vlenb" : "=r"(bytes));
 u32 full = bytes / 4, failures = 0;
 for (u32 i = 0; i < full; ++i) { a[i] = i * 17 + 3; b[i] = i * 13 + 5; }
 for (u32 vl = 0; vl <= full; ++vl)
  for (u32 macc = 0; macc < 2; ++macc)
   for (u32 restart = 0; restart <= 3 && restart <= vl; ++restart) {
    chain(full, vl, restart, macc);
    for (u32 i = 0; i < full; ++i) {
     u32 first = i >= restart && i < vl ? (macc ? a[i] + 7 * b[i] : 7 * a[i]) : a[i];
     u32 expected = i < vl ? first + b[i] : first;
     failures += out[i] != expected;
    }
   }
 register u32 status __asm__("a0") = failures != 0;
 register u32 syscall __asm__("a7") = 93;
 __asm__ volatile("ecall" : : "r"(status), "r"(syscall) : "memory");
 __builtin_unreachable();
}
