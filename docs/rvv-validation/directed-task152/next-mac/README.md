Eight single-width destructive multiply-add forms are prepared, not executed.

The captured old destination supplies the third operand for vmacc/vnmsac and the multiplicand for vmadd/vnmsub. Operands use assembler order vd,vs1/rs1,vs2. Predicates compute the low SEW bits; signedness has no effect on low-width modular multiplication. RV32 scalar sign extension is tested at SEW64. Legal same-width overlaps read the complete captured prestate.

Finite manifest includes shared VLEN128–4096, SEW8–64, legal LMUL geometry, mask/policy/partial/zero VL, nonzero and reserved starts, destination/source/both-source overlap, wraparound and distinct operand witnesses. Independent Spike/Sail admission remains required. Run prepare_mac152.py to reproduce local checks; reject_mac152_next.py is ready for actual-packet controls after shared routing and pilot. No guest PASS or method admission is claimed.

Task154 execution and source-review continuation is recorded in
[SEMANTIC_REVIEW.md](../../directed-task154/SEMANTIC_REVIEW.md). The Task152
preparation above predates that QEMU read; no historical source borrowing is
claimed. Task154 keeps its prepared full denominator and separately declares
new QEMU-inspired MAC scenarios and widening preparation/pilot snapshots.

Task154 first read pinned QEMU `tests/riscv/vector/case/{vmacc,vnmsac,vmadd,vnmsub}_{vv,vx}.c`,
`rvv_ch12.inc` (64 matching width/masked wrappers), `rvv_insn.S` and
`rvv_insn.h` at commit `7a35c902707087c8e1b77a3c82c54b73ffa17703`.
Its separate 96-case `mac154qemu` pilot borrows identifiable 0x11 old destination,
VLMAX−1 and complementary even/odd-mask scenarios, with scalar low word
0x55667788. RVV1.0 uses packed mask bits, explicit tu/mu policy predicates,
RV32 scalar sign extension and independent Spike/Sail packets; old expected
arrays and tail-zero semantics are not adopted. The prepared full manifest
above is not retrospectively attributed to QEMU, and this pilot is not an
unchanged external suite. Exact source hashes, adaptations and outcomes are
in Task154's linked semantic note and source-inspired evidence.
