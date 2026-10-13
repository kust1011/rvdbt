# Task146 oracle and checker review

Project-authored directed tests for 13 new forms and the three vadd forms.
The shared generator, capture body, runner, and auditor extend Task145; the default
`cases()` and old packet format, ordinals, initialization and assembly are preserved.
Task145's manifest/raw remain unchanged. No DUT algorithm or result supplies answers.
This is agent source review, awaiting the main review; no formal proof is claimed.

Independent answers use the same executable pins as Task145: Spike20feb9c2/RV32 pk
for vstart=0 (identical user ELF as DUT); Sail0.14.1/e4b243f for initialized nonzero
vstart (shared assembly with entry/exit-only machine adaptation). All reference
packets must separately pass ISA predicates. DUT active elements must also agree
with the independent packet. `check_isa` and `check_reference` are separate;
agnostic choices are validated against allowed old/all-ones sets, not bit-equaled
to a reference's choice. Offline reapplication uses the same checker and is not an
additional independent ISA model.

Reviewed sources:

* [Frozen RVV1.0](https://github.com/riscv/riscv-v-spec/blob/v1.0/v-spec.adoc):
  sections 3.7 (vstart), 5.4 (prestart/body/tail), 10 (arithmetic formats),
  11.1 (addition/subtraction) and 11.5 (bitwise logical).
* [Pinned Spike instruction definitions](https://github.com/riscv-software-src/riscv-isa-sim/tree/20feb9c2bf2a7deab964d8190b0cbd4b4131bec3/riscv/insns):
  all 13 new headers plus `v_ext_macros.h`, `decode_macros.h`, `vector_unit.cc`.
  The misleading prose comment in `vsub_vx.h` is not the definition: the body
  implements `vs2 - rs1`. `vrsub` implements `rs1/simm5 - vs2`.
* [Sail arithmetic](https://github.com/riscv/sail-riscv/blob/0.14.1/model/extensions/V/vext_arith_insts.sail):
  VV/VX/VI definitions and exact opcode mappings. VI sign-extends `simm`.
* [Sail utilities](https://github.com/riscv/sail-riscv/blob/0.14.1/model/extensions/V/vext_utils_insts.sail):
  `get_scalar`, `illegal_vstart`, `init_masked_result`.
  [Sail CSR writes](https://github.com/riscv/sail-riscv/blob/0.14.1/model/extensions/V/vext_regs.sail)
  mask vstart to VLEN-1. Actual fixed executable's emitted default config was read.

The specification predicates are modular add, `vs2-operand`, `operand-vs2`,
AND, OR and XOR, truncated to SEW bits. RV32 vx uses low SEW bits for SEW<=32
and sign-extends XLEN32 for SEW64; it never zero-extends a negative XLEN operand.
All applicable vi forms use simm5 -16..15, including bitwise operations.
Tests include -16/-1/0/15 and 0/0x7fffffff/0x80000000/0xffffffff; source patterns
include zero/ones, signed edges, unequal operands, low32 carry/borrow boundaries,
distinct high64, and alternating bit patterns. The emitted target label, not
initialization/configuration/dump instructions, earns form credit. Every target's
funct6, form, mask, source/destination and scalar/immediate encoding is audited.

vstart cases are ordinary initialized arithmetic, with no guest exception,
handler, return, mapping repair or retry. Every requested start is below VLEN,
the implemented CSR range. Full-VL equality is unavailable for e8/m8, whose
VLMAX equals VLEN; equality/greater-than tests use partial VL there. Each form and
geometry includes VL=0/start1 and VL=0/start(VLEN-1), partial equality and greater
starts, VL1/start2, and partial active cases when partial VL has at least two elements.
Chunk-adjacent nonzero starts with partial VL, overlap, masking and ta/ma are
included when geometrically possible. When start>=VL, no destination element,
including agnostic tails, may change; successful completion clears vstart.

Sail's default rejects nonzero arithmetic starts. Per invocation, the existing
supported `extensions.V.vstart.zero_required.arith=false` enables those cases.
The spec marks starts >=VLMAX reserved, even when CSR-representable. Such extra
profile cases use supported `extensions.V.reserved_behavior.vstart_out_of_bounds`
=`Vstart_Ignore`, matching the DUT's no-body behavior. These are reported separately
from `0<start<VLMAX` ISA cases and do not claim a universal requirement for reserved
values. No reference binary, algorithm, or global setting changes. A separate
finite pilot checks all 16 forms at SEW16/64, VLEN128/m1, including the new states;
its results earn no formal manifest credit.

The post-target CSRs are captured before resetting vstart or dumping registers.
All 32 vector registers, ten CSRs and scalar s0 have observed pre/post state.
Prestart, undisturbed, no-body destination and all non-destination registers are
bit-exact. tu/ta and mu/ma preserve the Task145 allowed-set rule.
Aligned same-width groups allow equal or disjoint overlap; a misaligned partial
group is reserved, so no such instruction is counted as legal target coverage.
The Sail adapter audit verifies shared source body, identical `.data` and exact
compiled targets for every adapted batch.

Actual-packet rejection controls cover each operation/form, reversed subtraction
or a different bitwise operator, vi/vx erroneous zero extension at SEW64, reference
comparison independently of the ISA predicate, and prestart/no-body preservation
for zero/equal/greater/partial VL. Existing CSR, source, missing-output, crash and
timeout controls remain. Corruptions are saved separately from unmodified raw.

Finite gaps: other host widths/RV64, illegal encodings, exhaustive cross-products,
multi-instruction live-out/early-exit sequences, and per-target M1/M2 admission.
No external full rerun, production change, performance or publication claim.

[80 retained source/state examples](ORACLE_EXAMPLES.json.gz) cover every form's
SEW64 arithmetic/operand case plus zero VL, maximum representable vstart,
partial-VL equality and partial active nonzero-start behavior. Each gives the
compiled user target PC/bytes, target label/source, exact input case, raw offsets,
pre/post CSRs, all-register hashes and observed destination/source elements on
reference and all four DUT arms. They are pilot review evidence, not extra formal
case credit; the complete formal audit remains the denominator check.
