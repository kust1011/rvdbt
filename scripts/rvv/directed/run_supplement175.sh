#!/bin/bash
set -euo pipefail
base=/home/vick/rvv-directed-task175
cd "$base"
while [ ! -f narrow175/remaining/GUEST_COMPLETE ]; do sleep 2; done
mkdir supplement
cd supplement
export PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1 PYTHONPATH="$base/tools-supp"
stage=declare
trap 'rc=$?; printf "{\"stage\":\"%s\",\"returncode\":%s}\n" "$stage" "$rc" > PIPELINE_STATUS.json' EXIT
python3 "$base/tools-supp/resources164.py" monitor $$ &
python3 "$base/tools-supp/supplement_gaps175.py" declare prepared
sha256sum "$base/tools-supp/"{vadd,fp157,gaps175,fpslide175_next,audit,supplement_gaps175,controls_gaps175,resources164,storage149}.py "$base/tools-supp/qemu_gaps175.json" "$base/FLAGS.json" prepared/DECLARATION.json > FREEZE.sha256
stage=build
python3 "$base/tools-supp/supplement_gaps175.py" build --family fpslide175 --output corpus --compiler clang-22 --build-jobs 4 --link /home/vick/rvv-directed-task145/link.ld > build.log 2>&1
stage=admission
while ! python3 "$base/tools-supp/resources164.py" gate guest GUEST_ADMISSION.json; do sleep 2; done
stage=run
python3 "$base/tools-supp/supplement_gaps175.py" run --root corpus --engine /home/vick/rvdbt-host512-task174-build/build/bin/elfrun --spike /home/vick/rvv-directed-task145/deps/spike --pk /home/vick/rvv-directed-task145/deps/pk --sail /home/vick/rvv-act4-tools/bin/sail_riscv_sim --flags "$base/FLAGS.json" --jobs 8 > run.log 2>&1
python3 - corpus/summary.json <<'PY'
import json,sys
s=json.load(open(sys.argv[1]));assert s['counts']=={'PASS':s['planned_executions']},s
PY
stage=audit-admission
python3 /home/vick/rvv-task168/offline_admission168.py 1 OFFLINE_ADMISSION.json
stage=audit
python3 "$base/tools-supp/supplement_gaps175.py" audit corpus audit > audit.log 2>&1
stage=controls
python3 "$base/tools-supp/controls_gaps175.py" corpus controls > controls.log 2>&1
stage=verify
sha256sum -c FREEZE.sha256 > freeze-after.log
stage=complete
date -u > COMPLETE
