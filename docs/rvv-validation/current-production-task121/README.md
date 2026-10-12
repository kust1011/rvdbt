# Current production ACT db2 regression — Task121

The full original accepted corpus passed on the production executable matching
HEAD `5952bf9`: 1,917 files × B/M1/M2/BOTH = **7,668 PASS**. Failed, crashed,
timeout, runner-error and eligible-unattempted calls: **0/0/0/0/0**.
The two original reference-platform blocked files remain blocked, with eight
withheld arm slots and zero new reference or DUT calls for those files.

[QUEUE.json.gz](QUEUE.json.gz) retains the original selection, sources, signatures,
ELFs, original complete commands and new candidate pins. The denominator includes
1,916 Task109 accepted outputs and the original Task104 accepted
`Vls32-vluxei32.v`; the full original inventory has 1,919 outputs.
Queue/configuration counts were printed before launch. Four workers, nice10,
cores28–31, original 300-second timeouts and isolated per-call FS/cache followed
the load check. No performance/global settings or blocked retry execution.

[scope.json.gz](scope.json.gz) joins all 627 navigation forms to actual source
cases, original selectors, arm/VLEN settings, comparisons and current receipts.
[replay-receipts.csv.gz](replay-receipts.csv.gz) has one row per call, including
source/checker/ELF/signature hashes, full actual flags, original receipt, stream
hashes and the new result. Actual checked union is **590**, also 590 in each arm;
the broader historical 595-form union is a separate claim. This corpus leaves
`vfmv.f.s`, `vfwcvt.f.f.v`, `vsetivli`, `vsetvl` and `vsetvli` unchecked.

Full raw: `xbd:/home/vick/act-current121/raw/<source-case>/<arm>/`.
Local retained copy: `/home/user/research/materials/act-current121-raw-20261012/`.
The downloaded archive preserves streams, commands, identities, results, TB maps,
comparison records and tooling; per-call work/cache and audit-control copies stay
remote. [transport.attempt1.json](transport.attempt1.json) binds the archive.
Original Task104/109/110/111 records and performance are unchanged.

The raw root's `comparison.json.gz` retains every original signature word and
original checker scope by source case. `comparison-sites.json.gz` retains the
literal original checker calls and line numbers, including destination register
arguments and CSR check sites. Their identities are in [COUNTS.json](COUNTS.json).
The 52,804,952 expected words in tested files include reserved/padding words;
word count and static macro-site count are not dynamic assertion counts.
No actual full-state snapshot or fresh reference signature is claimed.

Select a current form and then its exact original comparison:

```sh
python3 - vadd.vv Vx32-vadd.vv <<'PY'
import gzip, json, sys
from pathlib import Path
r = Path('docs/rvv-validation/current-production-task121')
s = json.loads(gzip.decompress((r/'scope.json.gz').read_bytes()))
print(json.dumps(next(f for f in s['per_form'] if f['form']==sys.argv[1]), indent=2))
raw = Path('/home/user/research/materials/act-current121-raw-20261012')
for filename in ('comparison.json.gz', 'comparison-sites.json.gz'):
    rows = json.loads(gzip.decompress((raw/filename).read_bytes()))
    row = next(c for c in rows if c['case']==sys.argv[2])
    if 'signature_words_hex' in row:
        print('expected word count', len(row['signature_words_hex']))
        print('first 16 exact expected words', row['signature_words_hex'][:16])
        row.pop('signature_words_hex')
    print(json.dumps(row, indent=2))
PY
```

Audit on xbd using the existing reporter and unchanged original retained roots:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv_scope_report.py \
  --navigation docs/rvv-validation/all-form-records/navigation.json.gz \
  --act-db2-replay /home/vick/act-current121 \
  --act-db2-package /home/vick/rvv-task110/inspection-final \
  --act-prior-root /home/vick/rvv-task104 --output /tmp/task121-new-audit
```

The auditor authenticates package/Task104 seals, original source/checker/oracle/
ELF identities and words, original predicates, complete commands, timeout,
before/after candidate pins and raw streams. [AUDIT_CONTROLS.json](AUDIT_CONTROLS.json)
records rejection of tampered evidence and preservation of failed/timed-out calls.
Original BASE selected destination elements/bits, LEN active/masked/tail predicates
and allowed agnostic alternatives, FFLAGS and VXSAT comparisons remain the observer.

These receipts validate original tested data on this build. They do not prove
all register/CSR/memory state, suppression/history, all overlap/configurations,
per-PC optimized admission, fault cause/address, concurrent mapping changes,
complete handler/return/restart or blocked P4-04 obligations. The two whole-file
FS/mstatus blockers, missing upstream EFFEW32 `vfwcvt.f.f.v`, privileged vset and
profile exclusions remain separate. See [SESSION0_RESULT_121.md](../../../SESSION0_RESULT_121.md).
