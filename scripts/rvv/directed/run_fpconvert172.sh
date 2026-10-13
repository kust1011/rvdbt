#!/bin/bash
set -euo pipefail
base=/home/vick/rvv-directed-task172
cd "$base"
export PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1 PYTHONPATH="$base/tools"
stage=freeze
trap 'rc=$?; printf "{\"stage\":\"%s\",\"returncode\":%s}\n" "$stage" "$rc" > PIPELINE_STATUS.json' EXIT
sha256sum -c FREEZE.sha256 > freeze-before.log
for branch in same widen narrow; do
 for phase in pilot remaining; do
  d="$base/$branch-$phase"
  mkdir "$d"
  stage="$branch-$phase-build"
  python3 tools/vadd.py build --family fpconvert172 --output "$d/corpus" --compiler clang-22 --build-jobs 4 --link /home/vick/rvv-directed-task145/link.ld --units-file "prepared/$branch-$phase.json" > "$d/build.log" 2>&1
  stage="$branch-$phase-admission"
  while ! python3 tools/resources164.py gate guest "$d/GUEST_ADMISSION.json"; do sleep 2; done
  stage="$branch-$phase-run"
  python3 tools/vadd.py run --root "$d/corpus" --engine /home/vick/rvdbt-host512-task167-build/build/bin/elfrun --spike /home/vick/rvv-directed-task145/deps/spike --pk /home/vick/rvv-directed-task145/deps/pk --sail /home/vick/rvv-act4-tools/bin/sail_riscv_sim --flags FLAGS.json --jobs 8 > "$d/run.log" 2>&1
  stage="$branch-$phase-result"
  python3 - "$d/corpus/summary.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]));assert s['counts']=={'PASS':s['planned_executions']},s
PY
  date -u > "$d/GUEST_COMPLETE"
  if test "$phase" = pilot; then
   stage="$branch-pilot-controls"
   python3 /home/vick/rvv-task168/offline_admission168.py 1 "$d/CONTROLS_ADMISSION.json"
   python3 tools/controls_fpconvert172.py "$d/corpus" "$d/controls" > "$d/controls.log" 2>&1
  fi
 done
done
stage=complete
sha256sum -c FREEZE.sha256 > freeze-after.log
date -u > GUEST_COMPLETE
