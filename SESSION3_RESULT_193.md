# Task193 — independent RVV legality/profile audit

Reviewed **ba1c252**, parent thesis AGENTS/current state/active plan, actual
predicates and187–191 results. **No new mandatory RVV1.0 correctness defect
established. No production edit, production rebuild, guest/reference execution,
full595 replay, or recovery experiment.** Session0 owns192 fixes and long-width
execution. This is bounded review evidence, not unrestricted conformance proof.

## Specification qualification and actual findings

The inherited pin `3570f998903f00352552b670f1f7b7334f0a144a`, SHA256
`bfe42bd33dc6abeef5362f475605dda3d229e722257a613b0691cee760f04a19`, says
**frozen for public review** and lacks the different-source-EEW restriction.
The [official20240411 ISA manual](https://docs.riscv.org/reference/isa/v20240411/_attachments/riscv-unprivileged.pdf),
§31.5.2, reserves a register supplying multiple source EEWs, including a mask
source at EEW1. Its Version1.0 chapter is retained from immutable revision
`6ee57d8997021aaa8025e208164763fe12e03c19`; [source identities](docs/rvv-validation/legality-task193/SPEC_SOURCE.json).
The source file retains stale introductory “1.1-draft” prose; the published PDF
independently contains the clause. Do not remove existing masked-source-v0,
mixed-width source/source, widening-MAC/addend restrictions merely to match the
older pin. Main should qualify/update the normative citation without rewriting
historical receipts. This is a documentation-baseline mismatch, not a new ISA bug.

The other concrete observation is **reserved memory admission**, not a mandatory
trap defect. `rv32_vector.h:238–258` and
`rv32_vector_lower.h:1089–1125` admit masked stores sourcing v0, masked indexed
loads sourcing indices from v0, and differently sized overlapping indexed-store
sources. Their QCG/scalar-memory callers inherit these decisions. The shared
predicates do not consistently implement the source-EEW restrictions enforced
by arithmetic. The new18-row source probe observes **seven reserved admissions,
11 legal admissions, zero legal refusals**. It includes fractional LMUL, a
second-field-only source alias and legal low/high indexed-load overlaps.

This does **not** prove a mandatory illegal-instruction defect: manual§2.2 makes
reserved-decoding behavior UNSPECIFIED. Unsupported memory EEW and explicitly
required nonzero-vstart exceptions are separate mandatory-trap clauses. A policy
to refuse every reserved encoding could justify a future consistency fix, but
the current profile does not turn that policy into an ISA requirement.

Crucially, these scenarios are not absent from historical tests. Actual final181
selection already excludes the reserved source combinations. A bounded read-only
join of three authenticated original manifests and final181 accepted indices
checks **86 excluded declarations and86 included legal neighbours at VLEN128**:
64 unit/strided/segmented store forms and22 compress geometries, each paired
with a legal neighbour. Existing `memory165.validate`/`permute162.validate` accept
their old declaration shapes; the final selector supplies the needed exclusion.
Thus a suspected ordinary-credit gap was disproved. No per-form totals change.
[Declarations](docs/rvv-validation/legality-task193/DECLARATIONS-fixed.json),
[classification](docs/rvv-validation/legality-task193/CLASSIFICATION.json).

## Existing obligations checked and retained

| Topic | Source/evidence conclusion |
|---|---|
| Advertised vector profile | RV32 application V, ELEN64, SEW8/16/32/64, FP32/64; not an embedded Zve profile. `rv32_vector.h:54–159`,179 build profile and191 actual build retain this scope. Full V includes e64 high-product/fixed-point forms; Zve64 omissions cannot excuse those. |
| Fractional LMUL and widths |22 minimum SEW/LMUL pairs:16 integral plus6 fractional; mf8/e8, mf4/e8–16, mf2/e8–32. Rejecting e64/mf2 and larger unsupported fractional combinations is legal. VLEN128–4096 powers of two are the implementation's admitted widths; V does not require supporting every allowed VLEN through65536. Long-width execution remains192's scope. |
| Configuration and reuse | `rv32_interp.cpp:310–413,973`, `qemit.cpp:5973–6095` consume dynamic vtype operands before destination publication, inspect all upper RV32 bits before table lookup, clear vstart and choose legal min(AVL,VLMAX).147's48,630 and148's7,008 existing cases include vill/upper bits, operand aliases, zero/max AVL, equal-ratio policy/SEW changes and deterministic choices.177/191 cache-reuse sequences are existing evidence. x0/x0 ratio-changing transitions remain reserved observations even when current VL fits; stale source comments calling them legal are not a new required behavior. |
| Groups/overlap/EMUL | Shared integer/FP widening, narrowing, conversion and reduction predicates distinguish vector groups from scalar slots; source EMUL>=1 is required for a wider destination's high-part overlap. Indexed memory derives data/index EMUL separately; segment destinations cannot overlap indices.154/156/162/166/172–175 already have legal aliases and fractional/EMUL cases. New probe neighbours confirm selected low/high/fractional memory admissions; no unrestricted enumeration claim. |
| Special encodings/forms | `rv32_decode.h` and existing reserved-decode rows check fixed unary fields, absent forms, carry vm, whole NF/width and mask-memory vm/NF/width. Whole memory EVL uses encoded EEW/NF; mask memory uses ceil(VL/8) bytes; whole moves use SEW for vstart byte offset. `rv32_vector_lower.h:2693–2707,3113–3134` matches these distinctions. Existing168/181 vill/whole/mask cases and186 FOF clauses are retained, not relabelled missing. |

187's bounded inexact-reduction category is addressed by190; optional gather and
NativeUnit formatter fixes have189/191 evidence.188 already exactly adjudicated
the592 original denials; their stronger diagnostic evidence does not supply
missing full architectural observations or resumed completion.191's stale
description of the old weak predicate must not reopen completed188 work.

## Tests, resources and exact remaining work

**12 new local tests PASS**, including actual172-declaration selection and four
semantic corruptions (flipped acceptance, mask/data alias changed to legal).
The independent classifier treats fractional groups as architectural-register
occupants and distinguishes source restrictions from destination overlap.
Reproduce: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/rvv/directed -p test_legality193.py -v`.

One standalone C++ source probe compiled/executed once on xbd against three
hash-matched reviewed ba1c252 headers/config; no production library was linked
or modified. [Commands/results](docs/rvv-validation/legality-task193/EXECUTION.json),
[probe output](docs/rvv-validation/legality-task193/1.stdout),
[identities](docs/rvv-validation/legality-task193/IDENTITIES.json).
All xbd work was serial at nice10, with no affinity assignment; zero guests,
one compiler/probe at most, >=10GiB sampled RAM/disk reserve. Minimum initial
resource samples:38,595,919,872 available RAM bytes and22,229,958,656 disk bytes;
final capture separately gates both reserves. These are sampled gates.

Two capture-controller expectation errors are retained/explained in
[ATTEMPTS.md](docs/rvv-validation/legality-task193/ATTEMPTS.md): an empty accepted
reserved selection and an incorrect expected86 assertion. They earned no audit
credit; no guest or successful source probe was repeated. Final capture is bound
to its corrected source/data hashes and the auditor requires172 rows.

**Remaining mandatory behavior:** previously service-blocked187-01/P4-04
handler return, permission repair, same-PC recovery/resumed progress remains
unverified. Not executed, renamed, substituted or bypassed here. No additional
mandatory legality/profile fix is handed to session0. Main owns normative-pin
qualification; reserved admission is an optional contract-consistency decision.
No speculative privileged/device/system/Linux expansion, push, email or reset.
Owned tests/evidence/report committed locally; requested completion signals are
`rvv-compliance193` and `rvv-review-parallel-20261013`.
