# Task142 final signal-copy build regression

[Result](../../../SESSION0_RESULT_142.md) · [counts](combined/SUMMARY.json) · [forms](combined/FORMS.md) · [original-predicate audit](AUDIT.json) · [partition](PARTITION.json) · [build pins](BUILD_SUCCESS.json) · [host checks](TEST_SUCCESS.json).

Task142 uses source `8111040faad84ded7f84fc5bd34d10461bfc50ca`, including reviewed signal-copy correction `ad5e3c8`. Actual build: `xbd:/home/vick/rvdbt-host512-task142-build/build/`, Clang22/LLVM22.1.6, Release, RV32/ELEN64, `RVV_HOST_CHUNK_BITS=512`. [Configuration match](CONFIGURATION_MATCH_137.json) checks 44 relevant options against Task137; [source](SOURCE_EQUALITY.json) and [dependencies](DEPENDENCY_EQUALITY.json) authenticate 297/442 files. The final executable is `e2559c5cd930e919503c79b44af219c243041e86f5b83a157bec860814e8336b`; library `79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af`.

Raw evidence is retained at `xbd:/home/vick/rvdbt-host512-task142/` and `/home/user/research/materials/task142-host512-raw-20261013/`. Build receipts are under `build-evidence/receipts/`; source/build/binaries remain in the separate remote build root. Task137/138 evidence was preserved.

Use the existing reader with Python 3.10+, assertions enabled, and an explicit extracted Task142 raw root. The raw archive and manifest identity are in [TRANSPORT.json](TRANSPORT.json); no asset was published. Each output directory must be new:

```sh
python3 scripts/rvv_scope_report.py \
  --host512-corpus docs/rvv-validation --host512-task142-build \
  --host512-raw /path/to/task142-raw --output /tmp/audit142
python3 scripts/rvv_scope_report.py \
  --host512-corpus docs/rvv-validation/host512-task142/combined/navigation.json.gz \
  --host512-raw /path/to/task142-raw --form vle32.v --arm B \
  --output /tmp/select142-vle32
```

To resolve original sources/checkers and reapply original ACT/Ara predicates offline, append the existing Task139 reader inputs to either command (acquisition/extraction recipe remains in [Task138 reader instructions](../host512-task138/README.md)):

```sh
  --host512-evidence /path/to/task139-current \
  --chips-package /path/to/chips94 --act-db2-package /path/to/act-db2 \
  --ara-package /path/to/ara91
```

Those packages supply unchanged source/checker/observer metadata; **only the explicitly supplied Task142 raw receives current credit**. No new packaging scheme or package is required. Read `record.json` for actual command/build/result/raw paths and literal source/checker bindings, or `PORTABLE_SOURCES.json.gz` after full generation. Historical nested results remain attributed to their original builds. `CONFIGURATION_DURING.json` and `CONFIGURATION_AFTER.json` contain actual cache/compile evidence; guest VLEN is in each command, ACT/Ara printed chunks in stderr, and missing runtime tuples remain UNKNOWN.

The same-build queue is exactly 11,532 CHIPS positives plus 212 controls, 7,668 ACT, 1,888 Ara whole-file and 16 TEST_CASE1/2-only scoped MAC calls. Three exact pilots plus 21,313 disjoint remaining calls receive credit once. Controls earn no positive form credit; scoped MAC keeps `whole_file_pass=false` and original failing TEST_CASE3/4 output. The [two original ACT reference blockers](ORIGINAL_ACT_REFERENCE_BLOCKERS.json) remain outside the accepted queue and accessible through navigation; they receive zero fresh DUT/reference calls. Prior-build execution credit is zero. Program acceptance and aggregate counters are not per-target native admission or complete architectural-state capture.

No guest handler return/restart, mapping repair/same-PC retry/P4-04 equivalent, new reference, performance campaign, LLVM expansion, publication or issue closure occurred. The launcher owns the completion signal.
