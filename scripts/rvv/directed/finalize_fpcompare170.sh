#!/bin/bash
set -euo pipefail
base=/home/vick/rvv-directed-task170
cd "$base"
export PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1 PYTHONPATH="$base/tools"
stage=wait-guests
trap 'rc=$?; printf "{\"stage\":\"%s\",\"returncode\":%s}\n" "$stage" "$rc" > REVIEW_STATUS.json' EXIT
while ! test -f GUEST_COMPLETE; do
 if test -f PIPELINE_STATUS.json; then cat PIPELINE_STATUS.json; exit 1; fi
 sleep 5
done
stage=join
python3 review_fpcompare170.py "$base" > join.log 2>&1
stage=audit-admission
python3 /home/vick/rvv-task168/offline_admission168.py 4 OFFLINE_ADMISSION.json
stage=audit
python3 /home/vick/rvv-throughput-main-20261013/audit_parallel.py "$base/review/corpus" "$base/review/audit-parallel" --audit-script "$base/tools/audit.py" --jobs 4 > audit.log 2>&1
for branch in minmax sign compare-class; do
 stage="$branch-final-controls-admission"
 python3 /home/vick/rvv-task168/offline_admission168.py 1 "$branch-remaining/CONTROLS_ADMISSION.json"
 stage="$branch-final-controls"
 python3 tools/controls_fpcompare170.py "$branch-remaining/corpus" "$branch-remaining/controls" > "$branch-remaining/controls.log" 2>&1
 stage="$branch-semantic-controls"
 python3 /home/vick/rvv-task168/offline_admission168.py 1 "$branch-remaining/SEMANTIC_CONTROLS_ADMISSION.json"
 python3 semantic_controls170.py "$branch-remaining/corpus" "$branch-remaining/semantic-controls" > "$branch-remaining/semantic-controls.log" 2>&1
 # The first two pilots were already checked during development.
 if test "$branch" = compare-class; then
  python3 semantic_controls170.py "$branch-pilot/corpus" "$branch-pilot/semantic-controls" > "$branch-pilot/semantic-controls.log" 2>&1
 fi
done
stage=verify
sha256sum -c FREEZE.sha256 > freeze-final.log
sha256sum -c SEMANTIC_CONTROLS_FREEZE.sha256 > semantic-freeze-final.log
sha256sum -c REVIEW_FREEZE.sha256 > review-freeze-final.log
stage=complete
date -u > COMPLETE
