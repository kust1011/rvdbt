Eight single-width destructive multiply-add forms are prepared, not executed.

The captured old destination supplies the third operand for vmacc/vnmsac and the multiplicand for vmadd/vnmsub. Operands use assembler order vd,vs1/rs1,vs2. Predicates compute the low SEW bits; signedness has no effect on low-width modular multiplication. RV32 scalar sign extension is tested at SEW64. Legal same-width overlaps read the complete captured prestate.

Finite manifest includes shared VLEN128–4096, SEW8–64, legal LMUL geometry, mask/policy/partial/zero VL, nonzero and reserved starts, destination/source/both-source overlap, wraparound and distinct operand witnesses. Independent Spike/Sail admission remains required. Run prepare_mac152.py to reproduce local checks; reject_mac152_next.py is ready for actual-packet controls after shared routing and pilot. No guest PASS or method admission is claimed.
