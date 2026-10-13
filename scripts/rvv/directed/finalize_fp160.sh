#!/bin/bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1
base=/home/vick/rvv-directed-task157/fp-full-final
review=/home/vick/rvv-directed-task160
trap 'tmux wait-for -S rvv-directed-fpfull-20261013-160; tmux wait-for -S rvv-review-parallel-20261013' EXIT
while ! test -f "$base/COMPLETE"; do sleep 10; done
python3 - "$base" "$review" <<'PY'
import json,sys
from pathlib import Path
base,review=map(Path,sys.argv[1:])
s=json.loads((base/'STAGE_STATUS.json').read_text())
(review/'ORIGINAL_STAGE_STATUS.json').write_text(json.dumps(s,indent=2)+'\n')
assert s['build']==s['run']==0,s
PY
# Reserve Task159's entire four-worker offline allocation, even if fewer are live.
while ! python3 - "$review" <<'PY'
import json,sys,time
from pathlib import Path
rows=[];unknown=[]
for p in Path('/proc').iterdir():
 if not p.name.isdecimal():continue
 try:args=(p/'cmdline').read_bytes().split(b'\0');cmd=b' '.join(args).decode(errors='replace')
 except (FileNotFoundError,PermissionError,ProcessLookupError):continue
 if not args or Path(args[0].decode(errors='replace')).name not in ('python3','python'):continue
 if any('audit' in arg.decode(errors='replace') for arg in args[1:2]):
  rows.append(dict(pid=int(p.name),command=cmd))
  if not any(s in cmd for s in ('rvv-task159-full','rvv-task158-fixedpoint-full')):unknown.append(rows[-1])
r=dict(time=time.time(),live_auditors=rows,other_owners=unknown,reserved_task159_workers=4,fp_workers=4,affinity='none',nice=10)
(Path(sys.argv[1])/'OFFLINE_CAPACITY.json').write_text(json.dumps(r,indent=2)+'\n')
raise SystemExit(bool(unknown))
PY
 do sleep 10; done
sha256sum -c "$base/FREEZE.sha256" > /dev/null 2>&1 || (cd "$base" && sha256sum -c FREEZE.sha256 > "$review/freeze-before-audit.log")
python3 /home/vick/rvv-throughput-main-20261013/audit_parallel.py "$base/corpus" "$review/audit-parallel" --audit-script "$base/scripts/audit.py" --jobs 4 > "$review/audit.log" 2>&1
python3 "$base/scripts/reject_fp157.py" "$base/corpus" "$review/controls-frozen" > "$review/controls-frozen.log" 2>&1
python3 "$review/tools/controls_fp160.py" "$base/corpus" "$base/scripts" "$review/controls-geometry" > "$review/controls-geometry.log" 2>&1
python3 "$review/tools/cleanup_fp160_profiles.py" "$base" "$review/profile-cleanup" > "$review/profile-cleanup.log" 2>&1
(cd "$base" && sha256sum -c FREEZE.sha256) > "$review/freeze-after-audit.log"
python3 - "$review" <<'PY'
import json,sys
from pathlib import Path
(Path(sys.argv[1])/'STAGE_STATUS.json').write_text(json.dumps(dict(build=0,run=0,audit=0,controls=0,summary=0,cleanup=0),indent=2)+'\n')
PY
python3 "$review/tools/export_fp160.py" "$base" "$review" "$review/evidence" > "$review/export.log" 2>&1
cp "$review/OFFLINE_CAPACITY.json" "$review/evidence/"
cp "$review/profile-cleanup/summary.json" "$review/evidence/PROFILE_CLEANUP.json"
gzip -c "$review/profile-cleanup/records.json" > "$review/evidence/PROFILE_CLEANUP_RECORDS.json.gz"
date -u > "$review/COMPLETE"
