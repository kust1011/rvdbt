typedef unsigned u32;
typedef unsigned long long u64;

static u64 input[32] __attribute__((aligned(64)));
static u64 initial[32] __attribute__((aligned(64)));
static u64 output[32] __attribute__((aligned(64)));

__attribute__((noinline)) static void load_case(u32 full, u32 vl, u32 restart)
{
    __asm__ volatile(
        "vsetvli zero, %[full], e64, m1, tu, ma\n"
        "vle64.v v8, (%[initial])\n"
        "vsetvli zero, %[vl], e64, m1, tu, ma\n"
        "csrw vstart, %[restart]\n"
        "vle64.v v8, (%[input])\n"
        "vsetvli zero, %[full], e64, m1, tu, ma\n"
        "vse64.v v8, (%[output])\n"
        : : [full] "r"(full), [vl] "r"(vl), [restart] "r"(restart),
            [input] "r"(input), [initial] "r"(initial), [output] "r"(output)
        : "v8", "memory");
}

__attribute__((noinline)) static void store_case(u32 full, u32 vl, u32 restart)
{
    __asm__ volatile(
        "vsetvli zero, %[full], e64, m1, tu, ma\n"
        "vle64.v v8, (%[input])\n"
        "vsetvli zero, %[vl], e64, m1, tu, ma\n"
        "csrw vstart, %[restart]\n"
        "vse64.v v8, (%[output])\n"
        : : [full] "r"(full), [vl] "r"(vl), [restart] "r"(restart),
            [input] "r"(input), [output] "r"(output)
        : "v8", "memory");
}

__attribute__((noreturn)) void _start(void)
{
    u32 bytes;
    __asm__ volatile("csrr %0, vlenb" : "=r"(bytes));
    u32 full = bytes / 8, failures = 0;
    for (u32 i = 0; i < full; ++i) {
        input[i] = 0x1234567800000000ull + i * 71;
        initial[i] = 0xfedcba9800000000ull + i * 19;
    }
    for (u32 vl = 0; vl <= full; ++vl)
        for (u32 restart = 0; restart <= 3 && restart <= vl; ++restart) {
            load_case(full, vl, restart);
            for (u32 i = 0; i < full; ++i)
                failures += output[i] != (i >= restart && i < vl ? input[i] : initial[i]);
            for (u32 i = 0; i < full; ++i)
                output[i] = initial[i];
            store_case(full, vl, restart);
            for (u32 i = 0; i < full; ++i)
                failures += output[i] != (i >= restart && i < vl ? input[i] : initial[i]);
        }
    register u32 status __asm__("a0") = failures != 0;
    register u32 syscall __asm__("a7") = 93;
    __asm__ volatile("ecall" : : "r"(status), "r"(syscall) : "memory");
    __builtin_unreachable();
}
