# Review and replay the finite RVV matrices

## Current allocator integration

A legal VLEN-4096, SEW-32, LMUL-4 sequence exposed the fixed 2,048-entry
virtual-register tracking limit. The allocator now sizes stable tracking storage
from the completed QIR region. Independent source review accepted this change
for ordinary QCG translation; physical-register and spill-frame budgets remain
unchanged. [Task195](../../../SESSION0_RESULT_195.md) records 54 long-vector cases
and 216 checks on the fixed executable, plus ten integration fixtures and forty
unchanged ACT/CHIPS test executions. Two stale fixtures were repaired without
changing production code; their three failed attempts remain in the records.

These are changed-build regressions, not a rerun of the complete form matrix.
The historical matrices below retain their original executable identities.
Fault-handler return and same-PC resumption remain unverified; component tests
do not establish that complete recovery sequence.

## Specification baseline

Current legality review uses the published 20240411 Unprivileged ISA Manual,
Chapter 31 (V version 1.0). The earlier `3570f998` vector-spec source is a frozen
public-review text; historical references to that revision remain unchanged.
The published manual additionally reserves reading one vector register with
different source EEWs within an instruction, counting a mask source as EEW 1.
[Task193](../../../SESSION3_RESULT_193.md) checks this difference against actual
source predicates and retained final181 selections: 86 reserved declarations
are already excluded, with 86 legal neighbours included. It does not change
the accepted form totals. Reserved decoding is not a universal requirement to
raise an illegal-instruction exception. The independent classifier has 12
passing tests; this source/selection audit is not a new ISA execution campaign.

## Latest exception-related update

The integrated code now includes the optional-gather backing-admission fix and
correct NativeUnit fault-origin formatting. [Production integration](../integration-task191/README.md)
records executable `37a25624345214d97e3691cfd9f951166abfe92419ce2bbeca9c786b68227c14`
and 50 bounded accepted invocations, including 24 original external calls and
16 sequence calls checking 68 packets. Anonymous SIMD admission remains active;
file-backed optional gather uses the existing checked memory path. The default
gather-off path has no added executed admission work; enabled-path timing has
not been measured. This is not a fresh full-form matrix on that executable.

[Exact denial adjudication](../denial-task188/README.md) checks all 592 retained
179 controls against target/setup and captured fault state, rather than keywords.
[Inexact reductions](../../../SESSION3_RESULT_190.md) add 360 cases and 1,440 DUT
checks on immutable179, using independent rational rounding and legal-tree
witnesses. Both remain separately identified from the original full matrix.
The complete fault-to-resumed-execution composition remains unverified because
the previously service-blocked restart experiment cannot be retried or renamed.
These results do not establish complete RVV 1.0 conformance. Existing thesis/PDF
delivery185 predates these additions; do not describe that PDF as updated here.

## Frozen full-matrix entry

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
here. Task155's historical accepted raw receipt remains an external locator;
final179 results have committed entry and per-form receipts. The independent [full P3 trace0 receipt](../directed-task180/FINAL_TOTALS.json)
has 2,418 cases/arm and 9,672 DUT checks on 179. Full trace1 is not accepted.
The index joins the amended [final plan](../directed-task181/DIRECTED_PLAN.json.gz)
to actual [per-form results](../directed-task181/evidence/PER_FORM_RESULTS.json)
and all 102 independently audited entry receipts. Frozen179 checks 3,017,262
ordinary cases/arm,12,069,048 ordinary positive DUT packets, plus 2,256 focused
positives (combined 12,071,304); 592 focused denial controls remain separate.
Each row retains its ordinary/focused split, original case/manifest index,
source and oracle pins, checked state, result and executable identity.
The same build completes 21,316 external commands: CHIPS 11,532 positives +212
controls, ACT 7,668,Ara 1,888 whole-file +16 TEST_CASE1/2 scoped results.
Two ACT reference blockers and original Ara TEST_CASE3/4 failures remain retained.
No historical174/older PASS is relabeled179. P3 remains a separate denominator;
full all-form trace1 and returning guest-handler restart remain unverified.
[Build provenance](../directed-task181/BUILD_MANIFEST_179.json) pins Release,
host512 and run flags; rebuilding this checkout earns no frozen179 receipt credit.
These changes are local delivery work, not a claim that they are already published.

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
accepted batch entry for the form; `--unit` selects an exact existing unit. Compact accepted row ranges are persisted
in the index and verified against their original selector hashes. Rejected/reserved
rows cannot be selected; a unit containing any excluded row is refused. With no
`--entry`, selection searches later accepted entries if an earlier entry has no
matching complete unit. Missing retained entry directories are reported if no match exists.
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
Historical recipes are inspection records. The executable fresh vadd path below
uses current APIs and relocates all paths; other families use selected retained packages. Optional
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

Default execution uses the current checkout dispatcher and family adapters.
[INTEGRATION183.json](INTEGRATION183.json) records exact imports of finalized
`fixedpoint155.py`, `scaling155_next.py`, and `narrowing155_next.py`: the original
Task155 dirty files equal the accepted Task159 snapshots byte for byte. The
small delivery adapter routes retained fixed-point/averaging packets without
replacing shared `vadd.py` or `audit.py`. This is file provenance, not a fabricated
owner commit. Task181 queue modules remain owner work and are not imported.
The older Task173/176 tool directories are archival bundles with their original
relative data, not default dispatcher replacements. [INTEGRATION.json](INTEGRATION.json)
retains the original27 committed imports.

For another family's exact historical snapshot, use `--tools`; Python files
must match the entry pins. The export below includes pinned source/data paths
so those snapshots need no dirty worker checkout. A legacy `check` API is
adapted to existing ISA/reference calls. Missing modules/data fail explicitly.

## Fresh clean-checkout vadd demonstration

Python3 on Linux with the existing179-compatible x86 host/runtime, an installed
Clang RV32 assembler and LLD, and existing pinned Spike/pk executables are
required. No download/install, binary dependency bundling, or reference rebuild
is performed. Historical compilation used Clang20; the actual183 demonstration
uses installed `/usr/bin/clang-22` and records its distinct hash, with no
historical ELF identity claim. The generator and predicates remain the checkout's
existing `vadd.py`/`storage149.py` APIs. Linker input is committed and hash checked.
Spike source is pinned to `20feb9c2bf2a7deab964d8190b0cbd4b4131bec3`; pk source
is pinned to `9c61d29846d8521d9487a57739330f9682d5b542` in
[sources.lock.json](../../../scripts/rvv/sources.lock.json). Executable hashes
are enforced from [Task145 identities](../directed-task145/IDENTITIES.json),
with the179 DUT/library hashes enforced separately. These retained executables
must be supplied; the script does not attempt to recreate their build environments.

Actual xbd commands from the fresh source stage `/tmp/rvv-delivery-reproduce183`:

```sh
cd /tmp/rvv-delivery-reproduce183
# Replace these roots with existing installed tools on your host.
DUT=/home/vick/rvdbt-host512-task179-build/build/bin/elfrun
LIB=/home/vick/rvdbt-host512-task179-build/build/lib/libdbtjitshared.so
REF=/home/vick/rvv-directed-task145/deps
python3 scripts/rvv_reproduce.py preflight --compiler /usr/bin/clang-22 \
  --spike "$REF/spike" --pk "$REF/pk" --dut "$DUT" --dut-lib "$LIB" \
  --output /home/vick/rvv-task183-new-vadd
nice -n 10 python3 scripts/rvv_reproduce.py run --compiler /usr/bin/clang-22 \
  --spike "$REF/spike" --pk "$REF/pk" --dut "$DUT" --dut-lib "$LIB" \
  --output /home/vick/rvv-task183-new-vadd-final
```

The run uses `vadd.build(..., selected_units=[...], jobs=1)`, then existing
`execute` and independent `check_isa`/`check_reference` calls. It generates one
17-case `w128-e32-m1-vv-zero` unit, builds one ELF, executes one pinned Spike/pk
reference and one179 B DUT call. It covers the unit's existing masks/policies/
aliases and lengths without expanding the generator. Output must be new;
`--link`, `--library-path` and bounded `--timeout` are configurable. Both scripts
use Task181 shared guest admission and its predicate-slot locks; the fresh path
also checks the shared build pool. The fresh path waits at most30 seconds for
a predicate slot (`--admission-timeout 0..60`); other occupied capacity fails for later retry.
No full queue, all-form rebuild, or general portability is claimed.

## Compact retained packages for other families

General fresh regeneration is not exposed for other families: historical
snapshots have different dispatch/generator APIs, some require adjacent JSON/
spec data, and current dispatcher assembly routing is not universal. Required
input is one **complete accepted unit** with original manifest/build identity,
`test.S`, `test.elf`, chosen-arm command, successful Reference command/execution/
checks/packets, and the entry's pinned tool/data files. `preflight` verifies
those sources and prints file hashes/size; it runs no guest. `export` verifies
the large originals once, writes logical selected files, and derives a compact
one-unit index with original manifest/selector provenance in `EXPORT.json`.
The exported row retains historical marginal dimensions; it does not claim the
small package contains every indexed configuration. Use its explicit `export_provenance`
unit/case count for package contents; original row counts describe the source index. No unselected streams,
caches or installed compiler/reference/DUT binaries are copied.

```sh
nice -n 10 python3 scripts/rvv_verify.py preflight --form vsmul.vv \
  --unit vsmul-w128-e8-mf8-vv-zero --raw-root /home/vick \
  --output /home/vick/rvv-task183-vsmul-package
nice -n 10 python3 scripts/rvv_verify.py export --form vsmul.vv \
  --unit vsmul-w128-e8-mf8-vv-zero --raw-root /home/vick \
  --output /home/vick/rvv-task183-vsmul-package
PKG=/home/vick/rvv-task183-vsmul-package
nice -n 10 python3 scripts/rvv_verify.py smoke --form vsmul.vv \
  --index "$PKG/index.json.gz" --raw-root "$PKG/raw" --dut "$DUT" \
  --unit vsmul-w128-e8-mf8-vv-zero --output /home/vick/rvv-task183-vsmul
```

Transfer only that package to the reviewer. The shown smoke uses the checkout's
new adapter; `--tools` may instead point to the exported snapshot path printed
by `export` for families needing a historical dispatcher. Replace form/unit
for another selected package; units above128 cases need existing family APIs
and are refused by this bounded smoke. Selecting reserved/nonaccepted rows or
an incomplete accepted unit always fails. Retained package checks preserve
independent references and oracle semantics; export is not new ISA acceptance.

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

Regenerate the index from the retained amended Task181 plan, actual final results
and accepted historical map. The generator verifies all original manifest identities,
per-entry selectors, final per-form counts, focused splits and build joins. This is offline metadata
extraction, not another ISA suite:

```sh
nice -n 10 python3 scripts/rvv_verify.py generate \
  --plan docs/rvv-validation/directed-task181/DIRECTED_PLAN.json.gz \
  --historical docs/rvv-validation/directed-task175/PER_FORM_BATCH_BUILD_RESULT.json \
  --results docs/rvv-validation/directed-task181/evidence/PER_FORM_RESULTS.json \
  --receipts docs/rvv-validation/directed-task181/evidence/ENTRY_RECEIPTS.json \
  --build-manifest docs/rvv-validation/directed-task181/BUILD_MANIFEST_179.json \
  --final-result docs/rvv-validation/directed-task181/evidence/FINAL_RESULT.json \
  --original-root /home/vick --raw-root "$RAW" --output /path/to/forms.json.gz
```

The compressed plan and final evidence hashes are in the index; the compact
plan is committed here, while original manifests remain retained raw prerequisites. The gzip encoding is deterministic. Listed Git receipt
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

P5 still needs owner-reviewed Task155/181 integration and reviewed final179 directed,
external, focused-fault and resource receipts; then main-owned thesis/PDF,
author guide and reply draft updates. This local code/test delivery does not
publish, email, or close those dependencies.

Task183 actual bounded results and remaining gaps: [SESSION0_RESULT_183.md](../../../SESSION0_RESULT_183.md).

## Thesis and author handoff

Task184 updated the existing [author guide](../../rvv-author-guide.md) and the
local bilingual thesis §3.6/§5.7 plus appendix generator. The author guide answers
form indexing, compared state/oracles, original-case inspection/replay and the
three semantic defects actually found. P3 is completed on 179 trace0; full181
all-form/external totals remain pending. Historical142 external21316 calls and
performance records keep their original attribution. Exact prose replacements,
evidence paths and completed documentation checks are recorded in
`SESSION0_RESULT_184.md`; the thesis README holds the editor-side replacement list.
