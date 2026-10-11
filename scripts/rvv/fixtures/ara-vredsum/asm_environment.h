/* Keep compiler-generated C/runtime code scalar. The original inline assembly
 * still uses RVV; this changes assembler availability, not the test sequence. */
__asm__(".option arch, +v\n.option norvc\n");
