# Compact current scope inputs

Read the [generated 627-form table](../../rvv-current-scope.md) or [CSV](forms.csv).
The committed `compact-input.json` is a projection of the accepted Task76 index:
exact form/family/applicability, exact per-suite checked/endpoint sets, and literal
recorded static route classes. It omits other stages, candidate sets, configuration
contexts, checker locators and raw bindings. It is an index, not raw evidence or
new execution. Unknown route remains null; no semantic depth is assigned.

From a checkout, Python3.10+ reproduces all four generated files without access
to the research machine, canonical archives, binaries or third-party fixtures:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv_compact_scope.py \
  --input docs/rvv-validation/current-scope/compact-input.json \
  --output /tmp/new-rvv-compact-view
cmp docs/rvv-current-scope.md /tmp/new-rvv-compact-view/rvv-current-scope.md
cmp docs/rvv-validation/current-scope/forms.csv /tmp/new-rvv-compact-view/forms.csv
cmp docs/rvv-validation/current-scope/counts.json /tmp/new-rvv-compact-view/counts.json
cmp docs/rvv-validation/current-scope/compact-input.json /tmp/new-rvv-compact-view/compact-input.json
```

Use an unused output directory. `source-manifest.json` records canonical input
names, byte lengths and SHA256, plus the bundled projection and reproducer hashes. With permission
and access to those original files, reproduce the projection itself:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv_compact_scope.py \
  --forms "$CURRENT/FORM_VERIFICATION_EVIDENCE.csv" \
  --summary "$CURRENT/ACTUAL_FORM_VALIDATION_SUMMARY.json" \
  --routes "$ROUTES/tables/FORM_ROUTE_MATRIX.csv" \
  --output /tmp/new-rvv-canonical-projection
```

`CURRENT` is Task76's `artifacts/external_suite_coverage_20261007`; `ROUTES` is
the recorded `artifacts/rvv_route_matrix_20261007`. The existing
`rvv_scope_report.py` validates stage membership during projection. The route
matrix is saved static evidence, not a newly performed source/semantic audit.
Route/number in the table identifies exact saved body-class variants: some
operand forms sharing a decoder route have different classes. The CSV retains
the literal per-form class JSON and original runtime-unknown status.

The manifest identifies the 160MB binding CSV only as provenance; it is not
imported into Git or needed by this renderer. For exact original bindings of one
form, use `rvv_scope_report.py --forms ... --summary ... --bindings ... --form
vsmul.vv --output NEW_DIRECTORY` with those separately obtained canonical inputs.
The compact data cannot regenerate the full candidate/configuration/raw joins.

## Retrieval limits

Historical archives and the complete evidence tree are unpublished local review
artifacts with no assigned public download URL. Request them from the author;
availability and permission to redistribute are not guaranteed. Their existence
and hashes do not make them publicly reproducible. `scope-evidence.tar.gz` is
immutable Task71 (including RIF194); it cannot supply Task76's current RIF200 and
libriscv198 sets. Full join reconstruction requires the separately retained tree
and its source/ELF dependencies, and raw review requires the linked archives.
No full historical executions are reproduced by rendering this table.

The [small Task80 smoke records and reader workflow](../smoke-task80/README.md)
are included separately and do not extend the historical 595-form claim.
