#!/bin/bash
set -euo pipefail
base=/home/vick/rvv-directed-task172
cd "$base"
export PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1 PYTHONPATH="$base/tools-fixed"
stage=wait-guests
trap 'rc=$?; printf "{\"stage\":\"%s\",\"returncode\":%s}\n" "$stage" "$rc" > FINALIZATION_FIXED_STATUS.json' EXIT
while ! test -f GUEST_FIXED_COMPLETE; do
 if test -f PIPELINE_FIXED_STATUS.json; then cat PIPELINE_FIXED_STATUS.json; exit 1; fi
 sleep 5
done
stage=join
python3 review_repaired_fpconvert172.py "$base" > join.log 2>&1
stage=audit-admission
python3 /home/vick/rvv-task168/offline_admission168.py 4 OFFLINE_ADMISSION.json
stage=audit
python3 /home/vick/rvv-throughput-main-20261013/audit_parallel.py "$base/review/corpus" "$base/review/audit-parallel" --audit-script "$base/tools-fixed/audit.py" --jobs 4 > audit.log 2>&1
for branch in same widen narrow; do
 stage="$branch-final-controls-admission"
 d="$branch-remaining"; if test "$branch" = narrow; then d="$d-fixed"; fi
 python3 /home/vick/rvv-task168/offline_admission168.py 1 "$d/CONTROLS_ADMISSION.json"
 stage="$branch-final-controls"
 python3 tools-fixed/controls_fpconvert172.py "$d/corpus" "$d/controls" > "$d/controls.log" 2>&1
done
stage=verify
sha256sum -c FREEZE.sha256 > freeze-final.log
stage=complete
date -u > COMPLETE_FIXED
