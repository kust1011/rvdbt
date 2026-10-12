# Current production CHIPS regression

Task120 reruns the retained sealed CHIPS fixtures after production memory/ABI
changes. Production source matches HEAD `4ae749fb63c09a53d8e158b51ab97064c4226b40`;
Task119 changed only a host test. The unchanged Task118 executable is identified
in [counts](COUNTS.json) and [source equality](PRODUCTION_EQUALITY.json).

All 11,744 calls passed: 11,532 positives and 212 separate controls. Each of
B/M1/M2/BOTH has 2,883 positives and 53 controls. Actual checked union is 595
applicable forms, also 595 in each arm. Failed/timed-out/unattempted: 0/0/0.
No blocked retry case was present or executed.

[scope.json.gz](scope.json.gz) retains all 627 inventory rows, each form's source
cases, actual arm/VLEN configurations, checker results and new raw locators.
[replay-receipts.csv.gz](replay-receipts.csv.gz) joins every original source
selector to its new receipt, full flags, executable/ELF identity and retained
target/checker bindings. Prior candidate/receipt fields remain explicitly
historical. There are 11,920 navigation rows, including 11,544 positive aliases
and 2,886 distinct positive source cases; these are not execution counts.
[FILES.json](FILES.json) pins these artifacts. Full details are in
[SESSION0_RESULT_120.md](../../../SESSION0_RESULT_120.md).

Raw remains at `xbd:/home/vick/chips-current120/raw`, with original fresh work
and cache directories. The local immutable raw copy and transport hash are
recorded in COUNTS.json and transport.attempt1.json. No original measurements
were overwritten. Four workers, nice10, cores28–31, original 120-second case
timeouts; no performance measurements or global CPU changes.

To audit downloaded new raw using the existing reporter and retained package:

```sh
python3 scripts/rvv_scope_report.py \
  --navigation docs/rvv-validation/all-form-records/navigation.json.gz \
  --chips-replay NEW_RAW \
  --original-manifest CHIPS_PACKAGE/records/historical/MANIFEST.json \
  --original-runner CHIPS_PACKAGE/tools/runner.original.py \
  --output NEW_AUDIT_DIRECTORY
```

To read one new-build form's record:

```sh
python3 - vadd.vv <<'PY'
import gzip, json, sys
p = 'docs/rvv-validation/current-production-task120/scope.json.gz'
x = json.loads(gzip.decompress(open(p, 'rb').read()))
print(json.dumps(next(r for r in x['per_form'] if r['form'] == sys.argv[1]), indent=2))
PY
```

The original checker compares selected destination words and, where recorded,
vxsat. Source SEW/LMUL/VL/mask/tail setup is retained as source context, not
invented runtime tuples. Passing switches do not prove per-PC native admission.
Full state, suppression/history, overlap, complete fault/handler/return/restart,
concurrent mapping changes and reordered CCRF faults remain separate obligations.
The 32 ei64 indexed forms remain outside this profile. This regression does not
close the semantic obligations or either issue.
