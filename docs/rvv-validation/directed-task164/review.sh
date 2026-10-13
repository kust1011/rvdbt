#!/bin/bash
set -euo pipefail
base=$1
review=$2
export PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1
mkdir -p "$review"
trap 'date -u > "$review/CLOSED"' EXIT
while ! test -f "$base/CLOSED"; do sleep 10; done
python3 - "$base" <<'PY'
import json,sys
from pathlib import Path
b=Path(sys.argv[1]);s=json.loads((b/'STAGE_STATUS.json').read_text());assert s['build']==0 and s['run'] in (0,1),s
a=json.loads((b/'corpus/summary.json').read_text());assert a['executed']==a['planned_executions'] and a['arms']['Reference']=={'PASS':a['planned_cases']},a
PY
while ! python3 "$base/scripts/resources164.py" gate offline "$review/OFFLINE_CAPACITY.json"; do sleep 10; done
(cd "$base" && sha256sum -c FREEZE.sha256) > "$review/freeze-before.log"
if python3 /home/vick/rvv-directed-task164/audit_parallel_retain.py "$base/corpus" "$review/audit-parallel" --audit-script "$base/scripts/audit.py" --jobs 4 --retain-failures > "$review/audit.log" 2>&1; then audit_rc=0; else audit_rc=$?; fi
controls_rc=125
if test "$audit_rc" = 0 || test -f "$review/audit-parallel/ALL_ACCOUNTED_WITH_FAILURES"; then
 if python3 "$base/scripts/controls_fma164.py" "$base/corpus" "$review/controls" > "$review/controls.log" 2>&1; then controls_rc=0; else controls_rc=$?; fi
fi
printf '{"build":0,"run":0,"audit":%s,"controls":%s,"export":125}\n' "$audit_rc" "$controls_rc" > "$review/STAGE_STATUS.json"
(cd "$base" && sha256sum -c FREEZE.sha256) > "$review/freeze-after.log"
test -f "$review/audit-parallel/audit/audit.json" && test "$controls_rc" = 0
python3 - "$base" "$review" "$audit_rc" <<'PY'
import json,sys
from pathlib import Path
b,r=map(Path,sys.argv[1:3]);s=json.loads((b/'STAGE_STATUS.json').read_text());s.update(audit=int(sys.argv[3]),controls=0,export=0,audit_traversal_complete=True,semantic_pass=int(sys.argv[3])==0)
(r/'STAGE_STATUS.json').write_text(json.dumps(s,indent=2)+'\n')
PY
python3 /home/vick/rvv-directed-task164/export_fma164.py "$base" "$review" "$review/evidence" > "$review/export.log" 2>&1
date -u > "$review/COMPLETE"
