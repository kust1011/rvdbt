#if !defined(__linux__) || !defined(__x86_64__)
#error RVV host copy boundary requires Linux x86-64
#endif
.text
.globl rvv_copy_read_byte
.hidden rvv_copy_read_byte
.type rvv_copy_read_byte,@function
rvv_copy_read_byte:
    endbr64
.globl rvv_copy_read_pc
.hidden rvv_copy_read_pc
rvv_copy_read_pc:
    movb (%rdi), %al
    movb %al, (%rsi)
    movl $1, %eax
    ret
.size rvv_copy_read_byte,.-rvv_copy_read_byte
.globl rvv_copy_write_byte
.hidden rvv_copy_write_byte
.type rvv_copy_write_byte,@function
rvv_copy_write_byte:
    endbr64
    movb (%rsi), %al
.globl rvv_copy_write_pc
.hidden rvv_copy_write_pc
rvv_copy_write_pc:
    movb %al, (%rdi)
    movl $1, %eax
    ret
.size rvv_copy_write_byte,.-rvv_copy_write_byte
// Both leaves are frameless: fault return consumes the original call's return address.
.globl rvv_copy_failed
.hidden rvv_copy_failed
.type rvv_copy_failed,@function
rvv_copy_failed:
    xorl %eax, %eax
    ret
.size rvv_copy_failed,.-rvv_copy_failed
.section .note.GNU-stack,"",@progbits
