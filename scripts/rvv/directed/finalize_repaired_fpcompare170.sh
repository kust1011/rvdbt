#!/bin/bash
set -euo pipefail
base=/home/vick/rvv-directed-task170
cd "$base"
export PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1 PYTHONPATH="$base/tools-v2"
stage=wait-guests
trap 'rc=$?; printf "{\"stage\":\"%s\",\"returncode\":%s}\n" "$stage" "$rc" > REVIEW_V2_STATUS.json' EXIT
while ! test -f GUEST_V2_COMPLETE; do
 if test -f PIPELINE_V2_STATUS.json; then cat PIPELINE_V2_STATUS.json; exit 1; fi
 sleep 5
done
stage=join
python3 review_fpcompare170_v2.py "$base" > join-v2.log 2>&1
stage=audit-admission
python3 /home/vick/rvv-task168/offline_admission168.py 4 OFFLINE_V2_ADMISSION.json
stage=audit
python3 /home/vick/rvv-throughput-main-20261013/audit_parallel.py "$base/review/corpus" "$base/review/audit-parallel" --audit-script "$base/tools-v2/audit.py" --jobs 4 > audit-v2.log 2>&1
for branch in minmax sign compare-class; do
 stage="$branch-final-controls-admission"
 d="$branch-remaining";if test "$branch" = compare-class; then d="$d-v2"; fi
 python3 /home/vick/rvv-task168/offline_admission168.py 1 "$d/CONTROLS_ADMISSION.json"
 stage="$branch-final-controls"
 python3 tools-v2/controls_fpcompare170.py "$d/corpus" "$d/controls" > "$d/controls.log" 2>&1
 stage="$branch-semantic-controls"
 python3 /home/vick/rvv-task168/offline_admission168.py 1 "$d/SEMANTIC_CONTROLS_ADMISSION.json"
 python3 semantic_controls170.py "$d/corpus" "$d/semantic-controls" > "$d/semantic-controls.log" 2>&1
done
stage=verify
sha256sum -c FREEZE.sha256 > freeze-final-v2.log
sha256sum -c SEMANTIC_CONTROLS_FREEZE.sha256 > semantic-freeze-final-v2.log
sha256sum -c V2_TOOLS_FREEZE.sha256 > v2-tools-final.log
sha256sum -c V2_MANIFEST_FREEZE.sha256 > v2-manifest-final.log
sha256sum -c V2_CONTROLLER_FREEZE.sha256 > v2-controller-final.log
stage=complete
date -u > COMPLETE_V2
