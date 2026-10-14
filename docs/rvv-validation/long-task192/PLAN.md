# Task192 pre-execution boundary selection

Baseline ba1c252; current191 executable 37a25624. No historical accepted batch
will be rerun. No production rebuild initially. Compile workers 2, correctness
workers 2, nice10, inherited affinity, reserve >=10GiB on xbd.

Existing single-operation162/163/154/155/172/174/175 and final181 cover all six
VLENs and legal fractional/integer LMULs, cross-chunk masks, permutation indices,
reduction aliases and widening/narrowing overlap. Those are not new blanket gaps.
Task177 sequences use integer e16/e32/e64 m1 and e32 m2; FP e32/e64 m1/m2 and
e32 mf2, with up to five arithmetic members (cache visits separately). Existing
value fixtures cover bounded FP at long m1 and 2048/m2. Missing composition:
long m4/m8 and minimum fractional groups with definitions live across a 64-insn
TB cut, masked barrier, partial physical register, and more than eight chunks.

Source checks before execution: VLEN_MAX_BITS=4096, VLEN_MAX_BYTES=512;
VectorState masks index byte i/8 and support maximum 4096 e8/m8 elements;
elem_u/elem_put and group_chunk_state_offset use runtime register division and
fixed512 storage stride. kMaxChunks=8, kMaxRunMembers=64 are statically joined
to QIR and TB bounds at rv32_qir.cpp:35-64. FP single frames use bounded arrays
in loads/ops/stores batches (7774-7836), equal-EMUL groups coincide or are
disjoint; run admission separately caps chunk count (8163-8166). Widening
high-source overlap loads before stores (8842-8853); narrowing low-destination
overlap is addressed by ascending source windows (9097-9117). FP compare mask
deposit reads sources before low mask-byte writes (8723-8728). These checks
establish hypotheses, not acceptance or a confirmed defect.

New finite generator long192.py reuses177 capture and scalar/exact-rational
semantics, plus original pinned Spike/pk for independent answers at2048/4096.
Six geometries at each width: integer e8/mf8, e16/m4, e8/m8; FP e32/mf2,
e32/m4, e64/m8. Four VL values (deduplicated where equal), 65 dependent ops.
No new special-value FP category;190 already supplies inexact reductions.
Integer operation32 is masked, forcing an SSA publication barrier. Remaining
members require previous values across TB boundaries. Pilot:4096 e8/m8 and
4096 FP e32/m4, then only disjoint remaining units if predicates pass.

Spec: pinned v1.0 3570f998903f00352552b670f1f7b7334f0a144a,
local directed-task174/v-spec.adoc:3.2/3.4 (LMUL/tail),4 (mapping),5.2/5.4
(groups/active elements). Full pre/post vector image, CSRs and saved scalar
predicate applies to every packet; actual paths require PC-specific helper
census, dynamic frame entries and emitted-code audit, not flag names.

P4-04 and equivalents excluded. No fault recovery, Linux/scalar/LLVM expansion,
performance campaign, push/email/reset, or Session3 worktree writes.

Adaptive addition after the46 cases: actual path audits show no multi-member
frames in the selected large/fractional groups. Before further execution add
only two eight-chunk controls,4096/e32/m1 and2048/e32/m2, four lengths each,
with the same65-operation dependency graph. This targets the previously untested
long-member boundary under actual M1/BOTH admission. It does not repeat177's
accepted five-op cases. Retain the singleton results with zero multi-run credit.
