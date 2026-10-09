/* Local Linux-user reporting adapter; upstream instructions/checkers are unchanged. */
#include CHIPS_ENV_HEADER

#undef RVTEST_PASS
#define RVTEST_PASS \
  fence; \
  .pushsection .rodata; 991: .ascii "CHIPS_PASS\n"; .popsection; \
  li a0, 1; la a1, 991b; li a2, 11; li a7, 64; ecall; \
  li a0, 0;

#undef RVTEST_FAIL
#define RVTEST_FAIL \
  fence; \
  .pushsection .rodata; 992: .ascii "CHIPS_FAIL\n"; .popsection; \
  li a0, 1; la a1, 992b; li a2, 11; li a7, 64; ecall; \
  li a0, 1; RVTEST_CODE_END
