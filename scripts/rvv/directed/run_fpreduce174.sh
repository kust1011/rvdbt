#!/bin/bash
set -euo pipefail
base=/home/vick/rvv-directed-task174
cd "$base"
export PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1 PYTHONPATH="$base/tools"
stage=freeze
trap 'rc=$?; printf "{\"stage\":\"%s\",\"returncode\":%s}\n" "$stage" "$rc" > PIPELINE_STATUS.json' EXIT
python3 tools/resources164.py "$base/monitor" $$ &
sha256sum -c FREEZE.sha256 > freeze-before.log
for phase in pilot remaining; do
 d="$base/$phase"
 mkdir "$d"
 stage="$phase-build"
 python3 tools/vadd.py build --family fpreduce174 --output "$d/corpus" --compiler clang-22 --build-jobs 4 --link /home/vick/rvv-directed-task145/link.ld --units-file "prepared/$phase.json" > "$d/build.log" 2>&1
 stage="$phase-admission"
 while ! python3 tools/resources164.py gate guest "$d/GUEST_ADMISSION.json"; do sleep 2; done
 stage="$phase-run"
 python3 tools/vadd.py run --root "$d/corpus" --engine /home/vick/rvdbt-host512-task174-build/build/bin/elfrun --spike /home/vick/rvv-directed-task145/deps/spike --pk /home/vick/rvv-directed-task145/deps/pk --sail /home/vick/rvv-act4-tools/bin/sail_riscv_sim --flags FLAGS.json --jobs 8 > "$d/run.log" 2>&1
 stage="$phase-result"
 python3 - "$d/corpus/summary.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]));assert s['counts']=={'PASS':s['planned_executions']},s
PY
 date -u > "$d/GUEST_COMPLETE"
done
stage=join
python3 tools/review_fpreduce174.py "$base" > join.log 2>&1
stage=audit-admission
python3 /home/vick/rvv-task168/offline_admission168.py 4 OFFLINE_ADMISSION.json
stage=audit
python3 /home/vick/rvv-throughput-main-20261013/audit_parallel.py "$base/review/corpus" "$base/review/audit-parallel" --audit-script "$base/tools/audit.py" --jobs 4 > audit.log 2>&1
stage=controls-admission
python3 /home/vick/rvv-task168/offline_admission168.py 1 CONTROLS_ADMISSION.json
stage=controls
python3 tools/controls_fpreduce174.py "$base/review/corpus" "$base/controls" > controls.log 2>&1
stage=verify
sha256sum -c FREEZE.sha256 > freeze-after.log
stage=complete
date -u > COMPLETE
