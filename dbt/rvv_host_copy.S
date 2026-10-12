#if !defined(__linux__) || !defined(__x86_64__)
#error RVV host copy boundary requires Linux x86-64
#endif
.text
// RDI is guest memory, RSI is staging/source. Only the labeled RDI access
// is recoverable; source/publication faults remain unrelated host faults.
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
.globl rvv_copy_read_word
.hidden rvv_copy_read_word
.type rvv_copy_read_word,@function
rvv_copy_read_word:
    endbr64
.globl rvv_copy_read_pc_word
.hidden rvv_copy_read_pc_word
rvv_copy_read_pc_word:
    movw (%rdi), %ax
    movw %ax, (%rsi)
    movl $1, %eax
    ret
.size rvv_copy_read_word,.-rvv_copy_read_word
.globl rvv_copy_write_word
.hidden rvv_copy_write_word
.type rvv_copy_write_word,@function
rvv_copy_write_word:
    endbr64
    movw (%rsi), %ax
.globl rvv_copy_write_pc_word
.hidden rvv_copy_write_pc_word
rvv_copy_write_pc_word:
    movw %ax, (%rdi)
    movl $1, %eax
    ret
.size rvv_copy_write_word,.-rvv_copy_write_word
.globl rvv_copy_read_dword
.hidden rvv_copy_read_dword
.type rvv_copy_read_dword,@function
rvv_copy_read_dword:
    endbr64
.globl rvv_copy_read_pc_dword
.hidden rvv_copy_read_pc_dword
rvv_copy_read_pc_dword:
    movl (%rdi), %eax
    movl %eax, (%rsi)
    movl $1, %eax
    ret
.size rvv_copy_read_dword,.-rvv_copy_read_dword
.globl rvv_copy_write_dword
.hidden rvv_copy_write_dword
.type rvv_copy_write_dword,@function
rvv_copy_write_dword:
    endbr64
    movl (%rsi), %eax
.globl rvv_copy_write_pc_dword
.hidden rvv_copy_write_pc_dword
rvv_copy_write_pc_dword:
    movl %eax, (%rdi)
    movl $1, %eax
    ret
.size rvv_copy_write_dword,.-rvv_copy_write_dword
.globl rvv_copy_read_qword
.hidden rvv_copy_read_qword
.type rvv_copy_read_qword,@function
rvv_copy_read_qword:
    endbr64
.globl rvv_copy_read_pc_qword
.hidden rvv_copy_read_pc_qword
rvv_copy_read_pc_qword:
    movq (%rdi), %rax
    movq %rax, (%rsi)
    movl $1, %eax
    ret
.size rvv_copy_read_qword,.-rvv_copy_read_qword
.globl rvv_copy_write_qword
.hidden rvv_copy_write_qword
.type rvv_copy_write_qword,@function
rvv_copy_write_qword:
    endbr64
    movq (%rsi), %rax
.globl rvv_copy_write_pc_qword
.hidden rvv_copy_write_pc_qword
rvv_copy_write_pc_qword:
    movq %rax, (%rdi)
    movl $1, %eax
    ret
.size rvv_copy_write_qword,.-rvv_copy_write_qword
// Frameless leaves return through the original call, never a C++ unwind.
.globl rvv_copy_failed
.hidden rvv_copy_failed
.type rvv_copy_failed,@function
rvv_copy_failed:
    xorl %eax, %eax
    ret
.size rvv_copy_failed,.-rvv_copy_failed
.section .note.GNU-stack,"",@progbits
