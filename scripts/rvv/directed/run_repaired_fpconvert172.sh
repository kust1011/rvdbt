#!/bin/bash
set -euo pipefail
base=/home/vick/rvv-directed-task172
cd "$base"
export PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1 PYTHONPATH="$base/tools-fixed"
stage=fixed-freeze
trap 'rc=$?; printf "{\"stage\":\"%s\",\"returncode\":%s}\n" "$stage" "$rc" > PIPELINE_FIXED_STATUS.json' EXIT
sha256sum -c FIXED_FREEZE.sha256 > fixed-freeze-before.log
stage=pilot-admission
python3 tools-fixed/resources164.py gate guest narrow-pilot-fixed/GUEST_ADMISSION.json
stage=pilot-replay
python3 tools-fixed/replay_fma167.py --original "$base/narrow-pilot/corpus" --output "$base/narrow-pilot-fixed/replay" --engine /home/vick/rvdbt-host512-task172-build/build/bin/elfrun --build-manifest /home/vick/rvdbt-host512-task172-build/MANIFEST.json --flags FLAGS.json --jobs 8 > narrow-pilot-fixed/replay.log 2>&1
stage=pilot-view
python3 repair_fpconvert172.py "$base" > narrow-pilot-fixed/view.log 2>&1
stage=pilot-controls-admission
python3 /home/vick/rvv-task168/offline_admission168.py 1 narrow-pilot-fixed/CONTROLS_ADMISSION.json
stage=pilot-controls
python3 tools-fixed/controls_fpconvert172.py narrow-pilot-fixed/corpus narrow-pilot-fixed/controls > narrow-pilot-fixed/controls.log 2>&1
stage=remaining-build
mkdir narrow-remaining-fixed
python3 tools-fixed/vadd.py build --family fpconvert172 --output "$base/narrow-remaining-fixed/corpus" --compiler clang-22 --build-jobs 4 --link /home/vick/rvv-directed-task145/link.ld --units-file prepared/narrow-remaining.json > narrow-remaining-fixed/build.log 2>&1
stage=remaining-admission
while ! python3 tools-fixed/resources164.py gate guest narrow-remaining-fixed/GUEST_ADMISSION.json; do sleep 2; done
stage=remaining-run
python3 tools-fixed/vadd.py run --root "$base/narrow-remaining-fixed/corpus" --engine /home/vick/rvdbt-host512-task172-build/build/bin/elfrun --spike /home/vick/rvv-directed-task145/deps/spike --pk /home/vick/rvv-directed-task145/deps/pk --sail /home/vick/rvv-act4-tools/bin/sail_riscv_sim --flags FLAGS.json --jobs 8 > narrow-remaining-fixed/run.log 2>&1
stage=remaining-result
python3 - <<'PY'
import json
s=json.load(open('narrow-remaining-fixed/corpus/summary.json'));assert s['counts']=={'PASS':s['planned_executions']},s
PY
sha256sum -c FREEZE.sha256 > original-freeze-after-repair.log
sha256sum -c FIXED_FREEZE.sha256 > fixed-freeze-after.log
stage=complete
date -u > GUEST_FIXED_COMPLETE
