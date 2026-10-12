# Navigate an original test for any instruction form

Start with the compact [627-row table](forms.md), [family grouping](families.md)
and [remaining obligations](obligations.md). The 595 applicable forms all have
original CHIPS cases. The 32 ei64 indexed forms are outside RV32/ELEN64.
The machine detail is [navigation.json.gz](navigation.json.gz): an index into
existing Task90 bindings and released package selectors, with original rows
preserved and shared bindings referenced once. It is not a new acceptance ledger.

From the repository root, select any form (including a nonapplicable form):

```sh
python3 scripts/rvv_scope_report.py \
  --navigation docs/rvv-validation/all-form-records/navigation.json.gz \
  --form vwadd.vv --output /tmp/vwadd-original-records
```

`record.json` lists concrete original cases, source/checker/raw locators, complete
flags, ELF/executable/library identities, checked output/CSR scope, original
remaining statements, and exact package row selectors. Paths in Task90 rows are
historical locators; package records provide portable paths where included.
No suite-name lookup or copied template page is required.

Download/extract the existing [CHIPS reader](../chips-review-task93/README.md),
[ACT c3e reader](../act-primary-task99/README.md),
[ACT db2 reader](../act-db2-task110/README.md), and
[Ara reader](../ara-review-task91/README.md). Use their unchanged offline
acceptance tools first. Supply any available package roots to inspect literal
source assertions and configuration setup, original commands/results and hashes:

```sh
python3 scripts/rvv_scope_report.py \
  --navigation docs/rvv-validation/all-form-records/navigation.json.gz \
  --form vfadd.vv --chips-package /path/to/chips-inspection \
  --act-package /path/to/act-primary-inspection \
  --act-db2-package /path/to/act-db2-inspection \
  --ara-package /path/to/ara-inspection --output /tmp/vfadd-detail
```

For a smaller CHIPS slice add `--case vfadd_vv-0 --candidate clean961 --arm B`.
Filters restrict package detail; the canonical form's bindings remain available.
CHIPS detail reuses Task112's original-predicate `form_record` reader and returns
exact source header tuples (VL request/SEW/LMUL/mask), literal fallback contexts,
all original TEST_CASE sites, CSR source sites, capture patches, build records and
original raw acceptance. ACT/Ara detail returns literal target/checker windows,
original case/checker scope, oracle/expected paths and receipt commands/results.
The package's original verifier supplies acceptance; displaying literal windows
does not execute guest assertions or independently reconstruct ISA answers.

Source setup is separate from runtime observation: requested VL is not observed
VL; unioned configuration values are not a Cartesian product. A CSR initialization
is not a CSR comparison. A program PASS does not prove every static branch ran,
all architectural state was checked, or M1/M2 optimization admission. Ara's package
has 126 overlay forms; the full historical Ara422 set is navigated through Task90,
with historical raw outside this review bundle. ACT package inventories contain
591 forms including blocked/source-only rows, not 591 checked forms. CHIPS includes
failure controls; its package-wide selector count is not a positive execution count.

Regenerate the index using the retained Task90 edition and packages:

```sh
python3 scripts/rvv_scope_report.py --all-records \
  --forms "$TASK90/forms.csv" \
  --summary "$TASK90/ACTUAL_FORM_VALIDATION_SUMMARY.json" \
  --bindings "$TASK90/ACTUAL_FORM_VALIDATION_BINDINGS.csv" \
  --canonical-manifest docs/rvv-validation/current-scope/TASK90_MANIFEST.json \
  --chips-package "$CHIPS" --act-package "$ACT" \
  --act-db2-package "$ACT_DB2" --ara-package "$ARA" --output /tmp/all-original-cases
```

Original build identities remain internal to the records. None of these historical
595-form results validate the newer Task113 build at `37823dd`. This delivery runs
reporters and offline readers only, with zero new guest executions or ISA coverage.
[Counts](COUNTS.json), [acceptance checks](CHECKS.json), and
[sampled original assertions](SAMPLES.json) document the actual retained inputs.

[Task121 current-production ACT db2 receipts](../current-production-task121/README.md)
join these same source selectors to 7,668 new original selfchecks, exact expected
signature words and literal destination/CSR checker calls. Its actual checked
union is 590; old records and broader 595-form claims remain separate.
