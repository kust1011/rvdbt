# Task198: existing dimensions against RV32 application V / ELEN64

Read-only reconciliation at `4ad13da`; reuse Tasks181,186–193 and195. Main owns
final-build replay and delivery prose. This does not replay any matrix or transfer
179 execution credit to fixed192. The normative source is the official20240411
manual's V1.0 chapter, immutable
[6ee57d8997021aaa8025e208164763fe12e03c19](https://raw.githubusercontent.com/riscv/riscv-isa-manual/6ee57d8997021aaa8025e208164763fe12e03c19/src/v-st-ext.adoc),
SHA256 `f114464f32de3825863df04ff903137685a94a89973a8b38df3c4e804adf116f`.
Task193's older-public-review-pin qualification remains in force.

The existing inventory has627 forms:595 applicable and32 ei64 indexed forms
excluded by §18.3's explicit XLEN32 exception. This does not exclude data e64,
FP64, e64 high-product or fixed-point arithmetic. Optional FP16/128, system-mode
FS/VS management, device access histories, RV64 and other host widths are not
new obligations of this declared user execution profile. The22 minimum legal
SEW/LMUL pairs and admitted VLEN128–4096 are unchanged.

## Reconciliation of existing per-form/family dimensions

This table answers the historical G/S dimensions in `obligations.md`, using the
later accepted directed predicates and specific supplements. It does not change
the original external checker scope or any original failed receipt. A finite
matrix is evidence for its cases, without an obligation to exhaust inputs.

| Existing dimension / forms | Applicable accepted evidence | Actual remaining disposition |
|---|---|---|
| G01 integer active result and preserved state, `vadd` and other single-width forms |145/146 predicates check32 vector registers,10 CSRs, scalar operand, prestart/no-body and tail/mask allowed values;181 actual packets retained | Historical word-only external checker limitation remains historical. No additional missing arithmetic category established. |
| G02/S07 widening/narrowing/extension group geometry, source extension and legal overlaps |154/161/162/172/173/175 and193 exact source-selection audit | Legal aliases, fractional LMUL, source/destination EMUL and source scalar sign extension have evidence. Different-source-EEW reserved rows remain excluded. No demand to execute all aliases. |
| G03/S01 fixed-point rounding, saturation and sticky suppression |159 scaling/narrowing and155 rounding; `fixedpoint155.rounded/result/check_isa` | The old external-source even-retained `vsmul.vx` tie gap is filled by accepted181 b159-016 indices233863/233880: same e8/mf8/VL1 input1×64, rnu→1 and rne→0. Original28-file/32-seed search stays source-blocked; no rescan. |
| FP32/64 arithmetic, conversions, estimates, FMA; S02/S03 flags |160/167/170/171/172/173/176 and full-state predicates; repaired original FMA/narrowing ancestry retained | Five valid frm modes, specials/boxing, newly raised/sticky/suppressed flags have finite evidence. `vfrsqrt7` need not overflow: even the smallest positive subnormal's reciprocal square root is far below max finite; do not invent that selector requirement. |
| Integer reductions and S04 FP reductions, seed/scalar slots/VL0/mask/tails |163/174 plus190's360 inexact cases/1440 DUT checks |190 closes the specific inexact/cancellation/OF/NX category missing from181. Newly raised UF is unreachable for the selected same-format addition tree; sticky UF and exact subnormals are covered. General legal-tree variability is not a demand to enumerate every tree. Mandatory nonzero-start trap checks remain absent, below. |
| Mask logic/pop/first and prefix/iota, S05 mask tail allowed sets |159 mask,169 prefix; mask158 checks individual bits through VLEN and permits the appropriate mask-tail set | Accepted b159-015 index906 is `vmand` VL9 with checked nonbyte tail. Historical ACT last-writer/prefix freshness remains a limit of those original receipts, not a missing directed allowed-set mechanism. Nonzero-start trap obligation remains absent for pop/first/prefix/iota. |
| Gather/slide/compress, G08/S05 boundary and source-tail |162/175 checked active source-tail, mask/tail, overlap and chunk boundaries | Existing source-tail/boundary witnesses are not reopened. Compress has zero-start positive evidence but lacks the required nonzero-start trap observation. |
| G05–G07 data/segmented/indexed memory result/footprint/access suppression and overlap winners |165/166 allowed whole-EEW winner sets and unchanged footprint; guard165/166;168 FOF/startmask;186 terminal/family/native/bulk checks | Masked access suppression has fault/access evidence beyond historical endpoint equality. Aligned unordered winners are allowed sets, not forced reference order. Byte-misaligned successes are not universally required; a permitted misalignment exception is legal. No new ordinary-memory category established. |
| Whole-register memory/moves and mask memory, S06 EVL/vill/VL0/nonzero-start/nonbyte storage |168/181 focused vill/whole and186;169 whole moves | Accepted b169-055 indices65/69 execute `vmv1r` with vstart1/VL0; b168-039 index1289 stores `vsm` VL9 as exactly2 bytes. Original S06 Spike refusal is not PASS, but cannot reopen the later independent-reference/specified-state dimension. Unused final bits of a mask-store byte are stored source bits, not protected by VL bit count. |
| Configuration S08: vtype upper bits/vill, aliases, AVL choice, VL/VLMAX and vstart reset |147/148,177/180/191 reuse sequences,193 source audit | Concrete configuration mechanisms already have evidence. Ratio-changing x0/x0 transitions and invalid frm/reserved vtype encodings do not create mandatory successful cases. |
| M01–M06 method composition, register-pressure and intermediate publication |177/180 sequence evidence;191/192/195 affected long-region evidence | Arm switches alone never prove per-target native admission. Old intermediate-state or route limits remain limits of those records. They do not define an additional ISA form or require every form in every optimization route. |
| E01 / P4-04 precise recovery and forward progress |186 terminal/frontier and independently initialized suffix tests;188 exact denial adjudication | Handler return/repair/same-PC completion remains **NOT EXECUTED / NOT VERIFIED**. No recovery or equivalent workflow is attempted. |

The four narrow manifest joins above authenticate original manifest hashes against
the frozen181 plan and require each selected index to be accepted. Six selected
declarations are joined; no retained positive packet matrix is reaudited. Exact
cases, hashes and original source/receipt adjudications are in
[CLOSURE198_EVIDENCE.json](../directed-task181/CLOSURE198_EVIDENCE.json).

## Concrete non-recovery obligation absent from the accepted matrices

**Required nonzero-vstart illegal-instruction behavior for23 forms has zero
accepted181 architectural trap cases.** This is distinct from572 forms with
successful initialized nonzero-start execution. Reuse187's exact23-form list:
10 integer reductions,6 FP reductions, `vcpop.m`, `vfirst.m`, `vmsbf.m`,
`vmsif.m`, `vmsof.m`, `viota.m`, and `vcompress.vm`.

The original predicates enforce zero start for these forms. `mask158.restrictions`,
`prefix169.restrictions`, `reduction163.restrictions` and
`permute162.restrictions` explicitly retain `NOT_RUN` trap declarations;
`fpreduce174.validate` requires vstart0.181's592 denials are memory-fault cases,
and CHIPS'212 controls are original fail/wrong-answer controls. Neither supplies
the missing instruction-specific illegal exception. The reviewed QCG integer
fixture explicitly skips nonzero-start iota (`rvv_integer_family_test.cpp:444`);
encoding/admission tests are not architectural execution of these traps.

This establishes a testing gap, **not a DUT failure**. The interpreter's
`RVV_REQUIRE_RUNNABLE_VTYPE` guards the affected handlers before state mutation
(`rv32_interp.cpp:418,1761–1828`); source consistency cannot replace a terminal
execution observation. No new guest/test is authored here.

Smallest handoff to main: VLEN128/e8/m1, valid vtype, VL0, incoming vstart1;
`vcompress.vm v8,v16,v17`, raw `0x5f08a457`, disjoint legal groups/selector.
Observe the original target PC/raw, `ILLEGAL_INSN`, and unchanged vector/GPR/CSR
state. §3.7 explicitly preserves vstart on illegal-instruction exceptions; the
compress section's zero restart position describes traps during its execution,
and does not authorize a successful nonzero-start operation. A terminal observer
can check this without returning a handler, repairing memory or retrying a PC.
One such case decides the common guard mechanism; it would not automatically
credit all23 forms. Main should preserve original predicates and choose the
smallest affected validation, with independent/specification expectations.

188's56 unobserved store memories and592 missing full scalar pre-fault baselines
remain exact limitations of those guest receipts. They are not a fresh absence of
the store-prefix or scalar-preservation mechanism:186's selected fixtures and
grouped-memory terminal source explicitly compare both. Their exact historical
receipts still cannot earn full architectural fault-state PASS. Do not requeue
them all or relabel separate fixture results as observations of those592 calls.
