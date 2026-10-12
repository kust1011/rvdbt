# vadd.vv — retained external case review, issue #2 increment 1

The concrete example is CHIPS `elen64_vadd128/vadd_vv-0`, at upstream revision
`f76bff121dce91b6b23e1d37be77a5e44af914c3`, with the retained ELEN64 generator adaptation.
Four existing B/M1/M2/BOTH program receipts report exit 0 and exactly `CHIPS_PASS\n`;
selected offline checks pass the original runner predicate. No guest was executed
for this record. This is one inspected case of the existing form bindings, not
completion of `vadd.vv` semantic obligations or the issue.

## Follow the actual inputs, answer and checker

The [complete stage2 source](retained/sources/chips/elen64_vadd128/stage2/vadd_vv-0.S)
contains the original inputs, bodies, expected words and stores. Its SHA256 is
`b5fa9028e3474b8371d9e62f492f08a2502f54830eca910ca1173e83c13b9457`.
The bound ELF SHA256 is
`5d0533ff513832c0f399469ba4c8fe7cda5e08155af1c2ce77e3ca8485543d61`.
The ELF is outside this inspection extract; these are retained identities, not a rebuild.

For the first block, source lines 20–75 set up literal AVL 0 / e8 / mf8, then
`vadd.vv v20, v1, v31` at line 64. `testdata` begins at line 11028:
v0 reads offset 0, initial v20 offset 16, v31 offset 32 and v1 offset 48.
The two v31 input quads are `0x7f7f7ff8f8030100`, `0x7ff8f8030100ffff`;
the two v1 quads are `0x1070008000f0200`, `0x8000f0200ff00`.
Lines 69–70 set e8/m1 and store v20. TEST_CASE 2–5 at lines 72–75 compare four
sequential 32-bit words from `resultdata`: `0x32808aa4`, `0x30ac75dc`,
`0x5b761295`, `0x8344c0aa`. The next block requests AVL 7 (lines 120–122);
TEST_CASE 6–9 at lines 131–134 instead starts with `0x32800300` and retains
the other three words. These are literal archived answers; this report computes
no expected arithmetic results.

Original answer production is visible in the [stage1 source](retained/sources/chips/elen64_vadd128/stage1/vadd_vv-0.S)
(first capture marker `.word 0x2a000b` at line 72),
[pspike oracle stdout](retained/sources/chips/elen64_vadd128/logs/vadd_vv-0-oracle.stdout),
and [captured patch](retained/sources/chips/elen64_vadd128/patches/vadd_vv-0.patch).
The patch and oracle stdout carry the first expected words above. The original
[build-command records](retained/sources/chips/elen64_vadd128/build_commands.json)
record generation at ordinal 1, stage1 compilation at 2, pspike capture at 3,
merger at 8, machine compilation at 9, Spike self-check at 10 and user compilation
at 11, all returncode 0. The oracle command is original `pspike --isa=rv32gcv_zvl128b`
on the stage1 program; merge consumes the retained stage1/patch directories.
[Generator metadata](retained/sources/chips/elen64_vadd128/generator_metadata.json)
records XLEN32 / ELEN64 / VLEN128. Tool hashes and historical build locators are
internal provenance in [the machine record](internal/vadd-record.json), under
`internal_build_provenance`, and the original records. Expected values are
Spike/pspike-derived and can share reference errors; they are not DUT-generated.

The actual guest checker is [upstream TEST_CASE](retained/upstream/chips/macros/general/test_macros.h)
(lines 25–42): run the load code, load the embedded XLEN expected value, compare
with `beq`, branch to fail on mismatch. The [terminal adapter](retained/sources/chips/user_env/riscv_test.h)
changes PASS/FAIL reporting. [Original runner classify](retained/tools/runner.original.py)
checks the exact registered stdout and exit status, plus errors/timeouts. The
new per-form option calls only that predicate on retained bytes. It does not
recompute ISA results or rerun the guest checker.

## Exact source tuples and checked ranges

The [186-row tuple table](vadd.vv-tuples.csv) keeps each original geometry row,
its source line, requested AVL, SEW, LMUL, mask, actual target/setup/store lines
and contiguous TEST_CASE range. Each row belongs to this one source at VLEN128;
it is never multiplied by independently collected field sets. Repeated tuples
and repeated AVL zero values stay repeated. The machine record also preserves
each of the four full canonical binding rows with UNKNOWN fields unchanged.

| Source header / target line | VLEN | Literal SEW / LMUL / AVL / mask | Tail / mask policy | vstart / observed VL | Compared physical destination elements / source assertion lines |
|---|---|---|---|---|---|
| 20 / 64 | 128 | e8 / mf8 / 0 / false | tu / mu | UNKNOWN / UNKNOWN | v20 elements 0–15 / 72–75 |
| 78 / 122 | 128 | e8 / mf8 / 7 / false | tu / mu | UNKNOWN / UNKNOWN | v20 elements 0–15 / 131–134 |
| 550 / 594 | 128 | e8 / mf8 / 0 / true (`v0.t`) | tu / mu | UNKNOWN / UNKNOWN | v20 elements 0–15 / 603–606 |
| 609 / 653 | 128 | e8 / mf8 / 7 / true (`v0.t`) | tu / mu | UNKNOWN / UNKNOWN | v20 elements 0–15 / 662–665 |
| 9577 / 9621 | 128 | e64 / m1 / 0 / false | tu / mu | UNKNOWN / UNKNOWN | v20 elements 0–1 / 9630–9633 |
| 10639 / 10683 | 128 | e8 / m2 / 0 / false | tu / mu | UNKNOWN / UNKNOWN | v4:v5 elements 0–31 / 10692–10699 |

The source contains 186 target instructions and 768 `lw` word comparisons,
TEST_CASE IDs 2–769, source lines 72–11014. The first 180 blocks compare bytes
0–15 of their stored physical v20 register (four words); the final six compare
bytes 0–31 of v4:v5 (eight words). At the source SEW, a 16-byte store corresponds
to element indices 0–15/e8, 0–7/e16, 0–3/e32 or 0–1/e64. The CSV records the
range for every block. Fractional LMUL cases also compare initialized physical
bytes outside the fractional logical destination group. These ranges describe
the original store/checker, not a promise that every compared element was active.

Only `csrwi vxrm, 0` initialization is present, once per block. **No CSR is compared**:
VL, vtype, vstart, vxrm and vxsat have no post-target assertion here. No explicit
vstart setup appears. Literal AVL 7 with e8/mf8 is not measured VL7; neither
architectural clipping nor vstart zero is promoted to observed coverage.
Tail/mask policies are literal `tu,mu`, not runtime counters. Mask bits come from
the original per-block `testdata` offset loaded into v0, not a newly invented mask.
Destinations and sources are distinct in the 180 `v20,v1,v31` targets and six
`v4,v24,v26` targets; this example establishes no destination/source overlap case.

## Actual receipts

Each link opens the original result. Its sibling `stdout`, `stderr`, `case.json`
and `command.json` are retained byte for byte at the same package-relative path.
The machine record joins full ledger/cell IDs, original flags, commands, result
objects and raw hashes. All four show exit0, error=null, status PASS and 11-byte
stdout `CHIPS_PASS\n`; the selected offline original predicate returns PASS.
Historical elapsed fields are preserved solely as timeout diagnostics.

| Arm | Cell ID | Original raw result | Stderr bytes |
|---|---|---|---|
| B | `8d17e461889163e646cd9f36d4ba15bb0dcf88903adce4e3b3a37f61dae5cf2d` | [result.json](retained/records/clean961/receipts/positive-B-elen64_vadd128-000/8d17e461889163e646cd9f36d4ba15bb0dcf88903adce4e3b3a37f61dae5cf2d/result.json) | 582 |
| BOTH | `f91b405a19771f2e4e06b385626322ba1d9309aa302b2b6b8aa7b6b2bb4d8c11` | [result.json](retained/records/clean961/receipts/positive-BOTH-elen64_vadd128-000/f91b405a19771f2e4e06b385626322ba1d9309aa302b2b6b8aa7b6b2bb4d8c11/result.json) | 636 |
| M1 | `2034a074b3a8c18c143a3afa07ab9defabff0e46da4ccf8dfdb760678fb16ebd` | [result.json](retained/records/clean961/receipts/positive-M1-elen64_vadd128-000/2034a074b3a8c18c143a3afa07ab9defabff0e46da4ccf8dfdb760678fb16ebd/result.json) | 636 |
| M2 | `7b7abc384dbc3495ec060b28b0287b9dce0f52dfe69fef9d493b4781279dfff9` | [result.json](retained/records/clean961/receipts/positive-M2-elen64_vadd128-000/7b7abc384dbc3495ec060b28b0287b9dce0f52dfe69fef9d493b4781279dfff9/result.json) | 582 |

The stderr route counters report zero handler calls, including `vadd.vv`.
They provide no positive opcode execution, result-influence or independent
M1/M2 admission witness. PASS applies to the registered self-checking program.
The existing `intbasic128/vadd_vv-0` alias shares this source/ELF and these cells;
selecting both navigation aliases does not create eight independent receipts.
The frozen primary index has 192 `vadd.vv` navigation rows across 24 source/case
locators and two candidates. That is an inventory, not 192 distinct ISA cases.

## Select a form through the existing tooling

Obtain the retained CHIPS inspection using the [CHIPS reader](../chips-review-task93/README.md).
Use the updated verifier from this checkout against that extracted root:

```sh
INSPECTION=/path/to/chips-inspection
PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify_rvv_chips_inspection.py "$INSPECTION" \
  --form vadd.vv --candidate clean961 --batch elen64_vadd128 --case vadd_vv-0 --record
PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify_rvv_chips_inspection.py "$INSPECTION" \
  --form vadc.vim --candidate clean961 --batch carrymove128 --case vadc_vim-0 --arm B --record
```

Both selections were exercised on retained evidence. `--record` authenticates
selected payloads, follows their original source/build/capture bindings, lists
literal targets/assertions/CSR/setup/memory lines, and rechecks retained raw
receipts. It validates selected evidence only. Existing `--contexts` and plain
`--form` queries retain their output. Omit case/batch/arm filters to navigate all
available witnesses for the selected form. A missing form exits1. Full package
verification remains a separate command in the CHIPS reader.

The canonical per-form stage/binding export also uses the existing interface:

```sh
CANONICAL=/path/to/task90
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv_scope_report.py \
  --forms "$CANONICAL/forms.csv" --summary "$CANONICAL/ACTUAL_FORM_VALIDATION_SUMMARY.json" \
  --bindings "$CANONICAL/ACTUAL_FORM_VALIDATION_BINDINGS.csv" --form vadd.vv \
  --output /path/to/unused-vadd-scope
```

It now accepts the delivered `applicability` column as well as the historical
`rv32_elen64_applicability` header, retaining the values and rejecting conflicts.
The [compressed original stage export](internal/canonical-scope.json.gz) and
[909 exact selected binding rows](internal/canonical-bindings.csv.gz) are frozen
Task90 records across suites, not 909 new checks. The input binding CSV for this
local export was a field-preserving `vadd.vv` selection from Task90; the four
concrete CHIPS rows were compared field for field with Task90 and are identical.
Read the [Ara](../ara-review-task91/README.md), [ACT primary](../act-primary-task99/README.md)
and [ACT db2](../act-db2-task110/README.md) reader interfaces for their existing
source/checker/raw navigation. Their concrete per-form presentation is remaining
work in this increment; membership in this stage export supplies no added depth.

## Boundaries and remaining review

Original sources, inputs, answers and results are preserved. The 48 retained
payloads have their original sealed hashes in [PAYLOAD_IDENTITIES.json](internal/PAYLOAD_IDENTITIES.json).
This is a selected extract, not a complete CHIPS inspection package; the record
command needs the original package metadata. Historical build commands can name
other batch cases whose payloads are outside this extract. Source licenses are
retained under `retained/upstream/chips/`, `retained/licenses/` and original file
headers; no blanket relicensing applies.

Still to do under issue #2: review the other `vadd.vv` sources/suites; expose
applicable family obligations and exact unfulfilled tuples; independently assess
active/tail/masked element attribution, overlap, nonzero vstart, alternate tail
policies and optimized-method admission. This case has no full32v, CSR or final
memory oracle and shares reference/checker limitations. Required missing cases
must remain work items until external evidence and authorized executions exist.
Fault/restart work, P4-04, production changes, suite reruns and thesis updates are
outside this increment. The reporting regressions are host tests, not ISA tests.
