#!/bin/bash
set -euo pipefail
base=/home/vick/rvv-directed-task175
family=$1
tooling=${RVV175_TOOLS:-$base/tools}
cd "$base/$family"
export PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1 PYTHONPATH="$tooling"
stage=freeze
trap 'rc=$?; printf "{\"stage\":\"%s\",\"returncode\":%s}\n" "$stage" "$rc" > PIPELINE_STATUS.json' EXIT
python3 "$tooling/resources164.py" monitor $$ &
sha256sum -c FREEZE.sha256 > freeze-before.log
for phase in pilot remaining; do
 mkdir "$phase"
 stage="$phase-build"
 python3 "$tooling/vadd.py" build --family "$family" --output "$phase/corpus" --compiler clang-22 --build-jobs 4 --link /home/vick/rvv-directed-task145/link.ld --units-file "prepared/$phase.json" > "$phase/build.log" 2>&1
 stage="$phase-admission"
 while ! python3 "$tooling/resources164.py" gate guest "$phase/GUEST_ADMISSION.json"; do sleep 2; done
 stage="$phase-run"
 python3 "$tooling/vadd.py" run --root "$phase/corpus" --engine /home/vick/rvdbt-host512-task174-build/build/bin/elfrun --spike /home/vick/rvv-directed-task145/deps/spike --pk /home/vick/rvv-directed-task145/deps/pk --sail /home/vick/rvv-act4-tools/bin/sail_riscv_sim --flags "$base/FLAGS.json" --jobs 8 > "$phase/run.log" 2>&1
 python3 - "$phase/corpus/summary.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]));assert s['counts']=={'PASS':s['planned_executions']},s
PY
 date -u > "$phase/GUEST_COMPLETE"
done
stage=join
python3 "$tooling/review_gaps175.py" "$PWD" "$family" > join.log 2>&1
stage=audit-admission
python3 /home/vick/rvv-task168/offline_admission168.py 4 OFFLINE_ADMISSION.json
stage=audit
python3 /home/vick/rvv-throughput-main-20261013/audit_parallel.py "$PWD/review/corpus" "$PWD/review/audit-parallel" --audit-script "$tooling/audit.py" --jobs 4 > audit.log 2>&1
stage=controls-admission
python3 /home/vick/rvv-task168/offline_admission168.py 1 CONTROLS_ADMISSION.json
stage=controls
python3 "$tooling/controls_gaps175.py" "$PWD/review/corpus" "$PWD/controls" > controls.log 2>&1
stage=verify
sha256sum -c FREEZE.sha256 > freeze-after.log
stage=complete
date -u > COMPLETE
