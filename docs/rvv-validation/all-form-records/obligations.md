# Applicable obligations after the retained cases

The [family table](families.md) groups all 16 instruction families. Selecting any
form returns its original Task90 checked-output/CSR scope and remaining findings.
The table below reconciles those historical findings with the already accepted
scoped supplements in the existing `REMAINING_OBLIGATIONS.md` (29 J/G/S/M/E rows).
It does not classify an obligation as missing merely because a source has no
obvious CSR instruction. Original source setup, guest comparisons, stored runtime
observations and later scoped supplements remain distinct.

| Families / concrete cases | Available source and actual checked evidence | Applicable remaining mechanism / disposition |
|---|---|---|
| integer_single_width: `vadd.vv` | CHIPS `elen64_vadd128/stage2/vadd_vv-0.S`: target line64, TEST_CASE line72 onward; original destination words. G01 adds e64/m8 masked 1024/128 provenance and scoped state observers. | Source/v0/other-register/CSR preservation is outside the original word checker. Nonzero-vstart execution cannot be inferred from initialization. G01 is scoped closed, not a new missing-source search. |
| integer_widening, integer_narrowing: `vwadd.vv`, `vnclip.wv` | CHIPS geometry2048 widened words; G02/S07 original RVVTS seed20264500/case241 `vwadd.vv v8,v9,v5`, VLEN256/e32/m1/VL8, fullVL/unmasked, two references/four clean961; narrow low-overlap also accepted. | Legal high/low overlap evidence exists. Other mask/tail/geometry combinations remain unverified scope, not a finite Cartesian execution obligation. No native admission follows from these endpoint checks. |
| fixed_point: `vsmul.vx`, `vnclip.wv` | G03 saturation0→1, pre-vxsat1 sticky, VL0 and positive-VL all-masked scoped witnesses are accepted. S01 inspected 28 original CHIPS files/112 historical receipts and original API32 seeds. | S01 even-retained half-tie with same input, explicit rnu/rne and differing checked answers is SOURCE_BLOCKED: existing inspected ties do not discriminate those modes. Do not rescan the same28 files or change input/expected. |
| floating_point: `vfadd.vv`, conversion, estimate, FP reduction | ACT original BASE/LEN/FFLAGS macros; Ara `vfadd.c` constants and parser bindings. S02 directed reciprocal overflow and S03 conversion pre-FFLAGS16 sticky scopes accepted; S04 CHIPS full64-bit wide-reduction words joined. | Other distinct flags mechanisms need a matching source/checker join; startup CSR clearing is not evidence. Unordered reduction legal tree/NaN result sets remain CHECKER_BLOCKED beyond the specific accepted constants. ACT low-word BASE does not become a full64-bit comparison because CHIPS has one. |
| integer_reduction: `vredsum.vs` | CHIPS long1024 `vredsum_vs-0.S`, target64 and original TEST_CASE72; original reduction destination words; S04 retains concrete VL0 reduction evidence. | Original destination comparisons do not check all source/tail state or every reduction restart. Do not reclassify the already accepted VL0 case as absent or apply FP legal-tree obligations to integer addition. |
| mask_bits, mask_to_integer, mask_memory: `vmand.mm`, `vcpop.m`, `vsm.v` | CHIPS mask1024 literal TEST_CASE63; ACT mask destination and LEN policy macros. S05 five original prefixes plus full16-byte snapshots cover suffix[4,16). | Mask-producing tail/ma allowed sets and nonbyte final-bit protection require the original MASKPROD history gate; reuse of one prefix does not establish every store's freshness. S05 VERIFY/CHECKER_BLOCKED, not a generic data-tail rule. |
| permutation: gather, compress, slide | G08 VLEN128/VL8/lane0/index8 and256/VL16/lane3/index28, e64/m8 masked source-tail checks plus fullstate accepted; S05/PERMUTATION_BOUNDARIES joins compress/slide boundary evidence. | Alternate alias/policy/nonzero-vstart scope remains unverified. The active source-tail witness is already present; do not search or rerun it again. Compress/mask-tail legality needs its own checker rule. |
| integer_extension: `vsext.vf8` | G04 original RVVTS seed20264700/case9, VLEN128/e64/m1/VL2, v28/v16/v0.t with active and inactive lanes; unused14 sourcebytes and31 other vector registers/10CSR checked. | Other overlap/policy and cross-instruction source interaction are beyond this endpoint scope. CHIPS all-inactive masks are not counted as masked-active witnesses; the later original API case supplies that witness. |
| data_memory, indexed_memory: `vle32.v`, NF8 loads/stores | Original CHIPS/Ara selected output comparisons; G05/G06 NF8 active fields/index suffix; G07 seed2026101037/case4 VLEN128/VL2/tu-mu/vstart0/stride−72, enabled64 bytes and disabled/untouched footprint checked. | Masked-off access suppression needs an independent access/fault oracle; unchanged memory is not proof of no access. Overlapping store winner/constituent oracle remains CHECKER_BLOCKED; unordered stores cannot be required to pick an unpromised winner. E01 general precise fault/restart remains open after Task113 helper delivery. |
| whole_register_memory, whole_register_move | S06 NF1 load/store incoming-vstart127/128/129, two Spike/eight clean961 endpoint results, vstart reset and unwritten bytes checked. | Whole-memory nonzero-vstart has evidence. Whole-move nonzero-vstart was rejected by Spike before DUT and is REFERENCE_BLOCKED. Neither result proves general fault repair/sigreturn/retry or allNF/EEW. |
| configuration: `vsetvl`, `vsetvli`, `vsetivli` | S08 original CHIPS zero/x0 cases, 72 assertion executions plus explicitly local pre-vstart1/reset observations; middle-AVL and same-VLMAX retain cases accepted. | Other ratios/vill and privileged state require exact original encoding/profile and allowed-set adjudication. CSR reset evidence is scoped; unrelated vector initialization cannot fill it. |

Cross-family method obligations M01/M05 still lack a matching production pressure
cut followed by an actual multi-member arithmetic consumer with an independent
oracle. M04 intermediate fflags/vstart is unobserved despite accepted final
publication. M06 has accepted4096 fullVL batching, with partial-VL/restart and actual
M2-bound paths separately unverified. These are method scopes, not missing ISA
forms. Task113's helper signal delivery does not close E01 native precise state or
restore/retry. P4-04 stays blocked and is excluded from execution work.

# Finite next source-bound queue

This is a gate queue, not permission to alter tests or a claim that all rows are
ready to execute. **Zero new ISA executions were scheduled or performed here.**
No source qualifies as ready solely from its form name. Existing completed ACT
and CHIPS cases are not requeued to increase coverage.

| Existing source / revision | Required original comparison | Current gate and next action |
|---|---|---|
| ACT db2 `Vf32-vfmv.f.s`, `Vf64-vfmv.f.s`, `db2b9fd7aa71a6e669417f711379988541f1464c`; exact2 case selectors in ACT-db2 | Original FS-state `csrrc`/`csrrs mstatus` and signature predicates, retained unmodified | REFERENCE_PLATFORM_BLOCKED: QEMU SIGILL before DUT, zero DUT calls. Requires a compatible reference/user platform; do not remove CSR checks. |
| ACT db2 EFFEW32 `vfwcvt.f.f.v` original marked input/testplan | Original generated signature and widening-conversion result/flags | SOURCE_BLOCKED: upstream input/output absent in this profile; obtain that exact original source before any execution. Existing same-named forms do not replace it. |
| QEMU `f9587d4045c67cd0d8d8bdcd5d0bb5b6b395b63c`, `tests/tcg/riscv64/test-vle32ff.S` | First-element fault cause and unchanged VL; retain original trap checks | IMPLEMENTATION/PLATFORM_GATE: M-mode/MMIO harness differs from user delivery. Use the existing fault contract to establish observability; no guest rerun for this index and no P4-04 retry. |
| Original whole-move lineage in S06 `whole-vstart-state-continuation`, incoming nonzero-vstart | Original transfer result, unwritten state and vstart reset where legal | REFERENCE_BLOCKED: Spike rejects before DUT. Verify legality and acquire a supporting independent reference before execution. Accepted memory cases are not requeued. |
| ACT original MASKPROD/VCOMPRESS macros and the existing S05 prefixes | Last-writer history, mask tail/ma allowed set and final-byte bits | CHECKER_GATE_ONLY: adjudicate one existing unanswered history; do not synthesize expected values or execute a template policy matrix. |
| S01 original CHIPS `vsmul.vx` / original RVVTS API lineage | Same-input even-retained active half-tie checked differently under rnu/rne | SOURCE_BLOCKED: no qualifying input in the inspected28 files/32 seeds. Needs a different original upstream fixture; no execution or further seed generation is queued. |

Machine details preserve Task90's exact per-binding `remaining` text, including
historical findings that later scoped supplements resolved. This reconciliation
prevents an old OPEN label from overriding accepted evidence. The authoritative
local source is `artifacts/rvv_validation_delivery_20261009/REMAINING_OBLIGATIONS.md`;
its hash and the fixed upstream review hash are retained in CHECKS.json. Readers
without that local research tree can follow the existing package selectors and
this bounded table; not every supplemental raw artifact is publicly packaged.
