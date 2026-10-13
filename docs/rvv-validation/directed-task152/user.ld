OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS {
  . = 0x10000;
  .text : { *(.text .text.*) }
  . = ALIGN(4096);
  .rodata : { *(.rodata .rodata.*) }
  . = ALIGN(4096);
  .data : { *(.data .data.* .sdata .sdata.*) }
  .bss : { *(.bss .bss.* .sbss .sbss.*) *(COMMON) }
}
