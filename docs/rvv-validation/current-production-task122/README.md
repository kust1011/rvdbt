# Current production original Ara regression — Task122

The accepted queue contains **1,904 calls: 476 per B/M1/M2/BOTH**, with the full
retained **422-form union**. Final results are 1,888 whole-file PASS and 16 MAC
scoped acceptances. All original TEST_CASE3/4 MAC failures remain failures.
No new eligible mismatch, crash, timeout, runner error or unattempted call.

[QUEUE.json.gz](QUEUE.json.gz) retains original CASES/GROUPS/CONFIGS/SELECTED
joins, literal metadata, full original commands, ELF/source/adapter hashes,
original raw and exact scopes. Three reduction B receipts originate in Task52;
their M1/M2/BOTH receipts originate in Task82. These are newly executed here.
The accepted union equals recorded422; source-only and excluded cases remain
outside it. [Original dispositions](ORIGINAL_DISPOSITIONS.json.gz) preserve the
original reserved-input, invalid-context, no-oracle and reference-failure records.

[QUEUE_CORRECTION.json](QUEUE_CORRECTION.json) records a launcher mapping error:
Task48's RAW_MAPPING stores vaadd and vaaddu under the vaadd output root. The first
queue incorrectly joined vaaddu to vaadd's CONFIGS and ELF. Four incorrect calls
remain retained without vaaddu credit; the four original vaaddu calls then passed.
There are **1,908 actual guest attempts / 1,904 eligible calls**. No test/source,
expected answer or production code was repaired. Both original queue versions,
all attempt streams and the affected-only dispatch are retained in the raw root.

[scope.json.gz](scope.json.gz) extends the existing 627-form reader with the actual
new command/result/source joins. [Receipt CSV](replay-receipts.csv.gz) has one row
per eligible call. [comparison.json.gz](comparison.json.gz) contains original
expected literals and complete retained original source and compiled adapter text,
including CSR/scalar checks and long-checker arrays. [observations.json.gz](observations.json.gz)
retains original parser outputs, observed VL/vtype/assertion completion, original
CSR/scalar actual/expected observations where emitted, exact Ara89 configuration/
initialization checks, and MAC function spans with preserved failures. Passing
vector equalities do not supply a separate snapshot of every actual element.
Source geometry is context; it does not establish runtime Cartesian coverage.

Select a form and follow a concrete source case's original comparisons:

```sh
python3 - vaaddu.vv <<'PY'
import gzip, json, sys
from pathlib import Path
r = Path('docs/rvv-validation/current-production-task122')
load = lambda n: json.loads(gzip.decompress((r/n).read_bytes()))
s = load('scope.json.gz')
f = next(f for f in s['per_form'] if f['form'] == sys.argv[1])
print(json.dumps(f, indent=2))
call = f['current_Ara'][0]
print(json.dumps(load('comparison.json.gz')[call['comparison'].split('#')[1]], indent=2))
print(json.dumps(load('observations.json.gz')[call['observation'].split('#')[1]], indent=2))
PY
```

Audit locally with the unchanged original retained evidence tree present:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv_scope_report.py \
  --navigation docs/rvv-validation/all-form-records/navigation.json.gz \
  --ara-replay /home/user/research/materials/ara-current122-raw-20261012 \
  --output /tmp/task122-new-audit
```

Full raw: `xbd:/home/vick/ara-current122/raw/<id>/`.
Local retained raw: `/home/user/research/materials/ara-current122-raw-20261012/`.
The archive preserves all 1,908 attempts; work/cache stay remote. Hash-verified
original observers were staged inside the fresh root because historical remote
runner copies differ in orchestration. Their acceptance code and ELFs remain
original. Four workers, nice10, cores28–31, original 120-second timeouts and flags
followed load/build/source-equality checks. Executable/library pins match Task118.

These finite original comparisons do not close full-state, suppression/history,
overlap/configuration completeness, per-PC optimized admission, fault/restart,
concurrent-mapping, native-host-fault or blocked P4-04 obligations. No reference
run, golden regeneration, performance/global changes, push or issue closure.
Launcher owns completion signaling. See [SESSION0_RESULT_122.md](../../../SESSION0_RESULT_122.md).
