.option norvc
.option norelax
.text
.global _start
_start:
  la sp, stack_top
  call main
  call ara_finish
.bss
.balign 16
stack:
  .space 65536
stack_top:
