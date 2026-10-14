# Bounded integration witness: anonymous mmap, distinct and equal-register gathers,
# unrelated unit-load/add/store SIMD, and an independent scalar byte/value oracle.
.section .text
.globl _start
_start:
 li a0,0
 li a1,4096
 li a2,3
 li a3,0x22
 li a4,-1
 li a5,0
 li a7,222
 ecall
 li t0,-4096
 bgeu a0,t0,fail
 mv s1,a0
 li t0,0
init:
 slli t1,t0,2
 add t1,s1,t1
 li t2,17
 mul t2,t0,t2
 addi t2,t2,3
 sw t2,0(t1)
 addi t0,t0,1
 li t2,16
 bltu t0,t2,init
 li t0,16
 vsetvli t0,t0,e32,m1,tu,mu
 li t1,15
 vid.v v8
 vrsub.vx v8,v8,t1
 vsll.vi v8,v8,2
 vmv.v.v v16,v8
 vluxei32.v v24,(s1),v16
 addi s2,s1,512
 vse32.v v24,(s2)
 vluxei32.v v8,(s1),v8
 addi s3,s1,640
 vse32.v v8,(s3)
 # This independent unit-memory/arithmetic sequence must keep its native route.
 vle32.v v16,(s1)
 vadd.vv v24,v16,v16
 addi s4,s1,768
 vse32.v v24,(s4)
 li t0,0
check:
 li t1,15
 sub t1,t1,t0
 li t2,17
 mul t1,t1,t2
 addi t1,t1,3
 slli t2,t0,2
 add t3,s2,t2
 lw t4,0(t3)
 bne t4,t1,fail
 add t3,s3,t2
 lw t4,0(t3)
 bne t4,t1,fail
 li t1,17
 mul t1,t0,t1
 addi t1,t1,3
 slli t1,t1,1
 add t3,s4,t2
 lw t4,0(t3)
 bne t4,t1,fail
 addi t0,t0,1
 li t1,16
 bltu t0,t1,check
 li a0,0
 j exit
fail:
 li a0,1
exit:
 li a7,93
 ecall
