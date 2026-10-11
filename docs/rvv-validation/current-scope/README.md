# Compact current scope inputs

Read the [generated 627-form table](../../rvv-current-scope.md) or [CSV](forms.csv).
The committed `compact-input.json` extends the accepted Task76 projection with the Task90 reviewed Ara89 overlay on immutable Task87:
exact form/family/applicability, exact per-suite checked/endpoint sets, and literal
recorded static route classes. For Ara, `ara_evidence` now retains scoped source/checker/configuration/build/raw bindings, content identities, the exact old/new form diff, and finite source-only dispositions. Other suites retain their Task76 membership. This is saved evidence integration with zero new executions. Unknown route remains null; no semantic depth is assigned.

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
and access to those original files, the following `--forms`/`--summary` command
rebuilds the original Task76 projection. It does not produce the current Ara422
edition; use the later Task87/90 overlay procedure for that edition:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv_compact_scope.py \
  --forms "$CURRENT/FORM_VERIFICATION_EVIDENCE.csv" \
  --summary "$CURRENT/ACTUAL_FORM_VALIDATION_SUMMARY.json" \
  --routes "$ROUTES/tables/FORM_ROUTE_MATRIX.csv" \
  --output /tmp/new-rvv-canonical-projection
```

`CURRENT` is the original `artifacts/external_suite_coverage_20261007`; `ROUTES` is
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

Task90's [readable suite counts and finite Ara dispositions](ara-accepted-evidence.md)
and [exact old/new set diff](ara-form-set-diff.json) accompany this table. Ara changes
396 → 422 checked forms (+26, −0) since Task87; cumulative Task76 change301 →422 (+121, −0); the union remains595, with627/595/32 fixed.
The frozen source assertion inventory remains424; a version87 mapping corrects
`vrgatherei16.vv` from setup to assertion target (source113/checker114), giving425
in the derived mapping. No frozen source inventory is rewritten.

The versioned edition of the existing canonical tables lives in
`xbd:/home/vick/rvv-task90/task90/`; the local canonical pointer records that remote location.
The immutable Task87 edition remains at `external_suite_coverage_20261007/task87/`. It extends the existing ledger and
binding schemas with explicit `SCOPED_ACCEPTANCE` rows; these rows are bindings,
not new guest calls. Original rows and other-suite fields are preserved. Historical
registration counts remain labeled separately from overlay bindings.

To rebuild the current Ara422 Task90 edition through the Task87/90 overlay
procedure (author archive access required), supply the immutable Task87 bundled projection as `--input` and Task87 canonical tables as `--canonical`:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv_compact_scope.py \
  --input "$CURRENT/task87/compact-input.json" \
  --accepted-evidence "$DELIVERY" --canonical "$CURRENT/task87" \
  --canonical-tables --output /path/to/new-task90-edition
PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify_rvv_ara_tables.py \
  --canonical "$CURRENT/task87" --derived /path/to/new-task90-edition
```

The verifier checks historical-row preservation, hashes, joins, duplicate identities,
other suites and byte-identical table regeneration. It writes only the derived
edition and its check report. `DELIVERY` is `rvv_validation_delivery_20261009`.
The bundled snapshot can render without archive access using the earlier `--input`
command; historical raw replay still requires the corresponding archive.
[Portable external replay](../portable-external.md) now provides a complete Ara
file and an external sequence with actual M1/Both admission; its
[fresh-build results](../portable-task88/README.md) retain a separate build
identity and do not recreate the entire historical form-coverage campaign.

Ara89:166 blocks in39 programs,830 block/arm bindings and195 valid receipts (156 DUT /39 reference). Eight failed preliminary Spike builds remain distinct; actual reference count47. Main reviewed166 blocks,195 receipts and390 rejection controls; Task90 reuses that review. Five remaining forms retain exact blockers; all81 incompatible blocks and inherited source limitations remain in the bundled evidence. Zero new executions, whole-file PASS, multi-member M1 or M2 fast admission credit.
