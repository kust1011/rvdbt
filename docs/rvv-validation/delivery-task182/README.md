# Review and replay the finite RVV matrices

Use `python3 scripts/rvv_verify.py` from a checkout. This entry navigates the
existing directed manifests and delegates bounded execution/checking to
`vadd.execute`, `check_isa` and `check_reference`, with each family's existing
`install(vadd)` adapter. It does not introduce a suite runner. Full final179
execution and queue scripts belong exclusively to Task181.

[forms.json.gz](forms.json.gz) contains exactly 595 applicable forms. Each row
has the historical batch/build/receipt, selected case count, exact manifest
SEW/LMUL/VLEN/mask/VL/VLMAX/vstart/policy/EMUL/rounding values, missing-field
counts, zero/partial/full length counts, checked endpoint scope, oracle scope,
source entries/examples and replay/original-case reader commands. Entry records
pin the manifest, build records, generator module and retained tool sources.
Marginal values are **not a Cartesian product**, and requested manifest values
are not runtime observations. Missing fields are explicit; no absent dimension,
output, source-only external record or pending run earns PASS.

The [historical receipt map](../directed-task175/PER_FORM_BATCH_BUILD_RESULT.json)
retains mixed build pins and 595 finite accepted forms. `receipt_read_command`
uses exact Git revisions for committed session3 receipts that are not copied
here. Task155's accepted raw receipt remains an external locator pending its
owner's commit. The independent [full P3 trace0 receipt](../directed-task180/FINAL_TOTALS.json)
has 2,418 cases/arm and 9,672 DUT checks on179. Full trace1 is not accepted.
The index deliberately says `PENDING_TASK181_NOT_IMPORTED` for final179
all-form/external results; no historical174 or older PASS is relabeled179.
The 3,017,262 selected manifest rows describe the frozen queue inputs, not a new
execution total or extra form credit.

## Select and inspect

```sh
python3 scripts/rvv_verify.py list
python3 scripts/rvv_verify.py show --form vadd.vv
```

The external side reuses the [existing original-case entry](../all-form-records/README.md),
which joins CHIPS, ACT and Ara sources/checkers and their existing package
readers. Follow those readers for original offline acceptance; this entry does
not replace their predicates:

```sh
python3 scripts/rvv_scope_report.py \
  --navigation docs/rvv-validation/all-form-records/navigation.json.gz \
  --form vadd.vv --output /tmp/vadd-original-new
```

Directed tests are project-authored, agent-generated assembly and predicates.
They are not upstream original cases. Batch reviews identify borrowed
QEMU RVV0.7.1 case/wrapper structure and adapted inputs from
`7a35c902707087c8e1b77a3c82c54b73ffa17703`; its old expected arrays are not
RVV1.0 goldens. The project uses RVV1.0 encodings/policies and independent,
pinned executed Spike/Sail references plus specification predicates. Refer to
the particular batch review for input reuse, ISA-version changes, absent
upstream cases and source licenses; do not claim a QEMU upstream suite PASS.

## Relocated command and one bounded smoke

Keep raw inputs outside the repository. `--raw-root` replaces the index's
original `/home/vick` prefix: e.g. `RAW/rvv-directed-task145/corpus`. Existing
extractions with another layout can be arranged using directory symlinks in a
staging root. Original inputs remain read-only. `--entry` selects another
accepted batch entry for the form; `--unit` selects an exact existing unit.
`--sew`, `--lmul`, `--vlen`, `--mask`, `--vstart`, `--vl` and
`--length zero|partial|full` filter real rows. No match fails.

```sh
RAW=/path/to/retained-input-root
DUT=/path/to/immutable179/build/bin/elfrun
OUT=/path/to/new-smoke-output
python3 scripts/rvv_verify.py command --form vadd.vv \
  --sew 32 --lmul m1 --vlen 128 --mask none --vstart 0 --length partial \
  --raw-root "$RAW" --dut "$DUT" --output "$OUT"
nice -n 10 python3 scripts/rvv_verify.py smoke --form vadd.vv \
  --sew 32 --lmul m1 --vlen 128 --mask none --vstart 0 --length partial \
  --raw-root "$RAW" --dut "$DUT" --output "$OUT" \
  --library-path /path/to/additional/runtime/libraries
```

`command` prints the selected row, complete unit, relocated recorded DUT flags,
existing build/reference recipes and input locations without running a guest.
Historical build/reference recipes retain source/output locators: relocate those
arguments before invoking the existing family build/driver entry. Optional
`--compiler`, `--link`, `--spike`, `--pk`, `--sail` substitute tool paths in
these inspection recipes. The smoke reuses inputs and needs none of these
executables. `--checkout`, `--index`, `--tools`, `--dut`, `--dut-lib`,
`--library-path`, `--raw-root`, `--output` and `--timeout` are configurable.
No compiler or reference binary is bundled.

Smoke runs one complete existing unit, at most128 cases, one chosen
`B|M1|M2|BOTH` arm, timeout1–120 seconds (default60). Selecting a partial-VL row
still executes its unit's existing zero/full/mask/alias cases, not a fabricated
one-case ELF. It checks immutable179 executable/library hashes, manifest and
build records, guest hash, successful accepted reference rows, packet extent,
independent reference predicates and DUT/reference agreement. It checks
executable identities again afterwards. It requires nice10, preserves inherited
affinity, reserves10GiB disk, and refuses admission above8 other guests or2
other offline workers. It uses Task181's existing shared guest admission lock
and reserves its two online/offline predicate slots even when process names
do not expose online checking. Its own usage is one guest/one predicate process, within
own8/2 and shared16/4 limits; capacity failure is explicit, never a silent skip.
Do not launch multiple copies to bypass admission.

Use the entry's pinned accepted raw `tools` snapshot with `--tools` for families
whose current shared checkout dispatcher differs. Supplied `--tools` Python snapshots must match the entry's exact source pins.
Legacy `check` snapshots use
the same existing check API through a compatibility call. The default checkout
is demonstrated for vadd. [INTEGRATION.json](INTEGRATION.json) lists the precise
committed files imported from session3 `481bfb56362952551be7367fc12d48abb198074b`.
The current shared `vadd.py`/`audit.py` remain at9b768b6; older session3 versions
must not replace them. Task155's final `fixedpoint155.py`, `scaling155_next.py`,
`narrowing155_next.py` and shared dispatcher changes, and Task181's queue/tools,
are still dirty owner work: they are not copied or committed here. Until their
owner delivers commits, use the retained pinned raw tools for those families.
Missing modules/data fail explicitly.

## Demonstration and rejection protocol

Clean staging: `xbd:/tmp/rvv-delivery-entry182`, with only this entry and the
existing vadd/storage Python modules plus index. Final smoke raw remains at
`xbd:/home/vick/rvv-task182-smoke-admission`; no binary/raw stream was added to Git.
[command.json](command.json) records the actual dry-run selection. The final
[result.json](result.json) records17 checked cases, one new179 DUT call, zero
reference calls/rebuilds, exact guest/reference/output/checker hashes. B at
SEW32/LMULm1/VLEN128 passed; this is not four-arm or all-form acceptance.
[REJECTION_CHECKS.json](REJECTION_CHECKS.json) records five rejected invalid
outputs: missing, truncated, nonzero exit, timeout, corrupted CSR. Repeat with:

```sh
nice -n 10 python3 scripts/test_rvv_verify.py --checkout /path/to/checkout \
  --raw "$RAW/rvv-directed-task145/corpus" --output /path/to/new-rejections.json
```

Missing raw prerequisites and an unmatched configuration were also demonstrated
as exit1; an existing output directory is rejected. No PASS result is written
when execution/checking fails. Partial diagnostic directories may remain.

Regenerate the index from the retained Task181 frozen **selection plan**, not
its evolving results, and the accepted historical map. The generator verifies
all manifest identities and per-entry selector counts. This is offline metadata
extraction, not another ISA suite:

```sh
nice -n 10 python3 scripts/rvv_verify.py generate \
  --plan /path/to/DIRECTED_PLAN.json \
  --historical docs/rvv-validation/directed-task175/PER_FORM_BATCH_BUILD_RESULT.json \
  --original-root /home/vick --raw-root "$RAW" --output /path/to/forms.json.gz
```

The plan hash is in the index; the plan is an owner-managed raw prerequisite,
not a copied48MiB dump. The gzip encoding is deterministic. Listed Git receipt
reads need the exact dependency commit available locally.

## Exception and semantic limits

Endpoint predicates cover initialized and final vector registers, applicable
CSR/scalar results/preservation, body lanes and permitted agnostic outcomes;
transfer predicates also check all32 floating registers;
memory predicates also check the finite captured buffer and allowed store
winner sets. They do not prove all intermediate state, arbitrary operand/mask/
overlap combinations, access history, per-target optimization admission, or
complete RVV conformance. Checked state is distinguished from mere capture.
Unordered FP sums retain tree-invariant exact subsets and restricted specials;
arbitrary inexact trees remain outside the accepted oracle. Reserved/source-
illegal cases and applicable nonzero-vstart reduction traps remain separate
from normal completion. RV32/ELEN64 excludes32 ei64-indexed forms.

Existing checked-helper/native terminal fault publication and Linux signal
interface witnesses have their recorded build scopes. Terminal capture is not
handler-return/restart proof. Element0 FOF trap VL/vstart/partial-segment state
is blocked for exit-only observers; interrupts/watchpoints and general precise
restart remain unproved. Guest handler return, mapping repair, same-PC retry
and P4-04 execution remain prohibited. Retain the two ACT reference blockers
and Ara's16 scoped MAC calls with original TEST_CASE3/4 failures; no whole-file
PASS or completed fullRVV proof follows from595 finite forms.

P5 still needs Task155/181 committed integration and reviewed final179 directed,
external, focused-fault and resource receipts; then main-owned thesis/PDF,
author guide and reply draft updates. This local code/test delivery does not
publish, email, or close those dependencies.
