#!/bin/bash
set -euo pipefail
base=/home/vick/rvv-directed-task170
cd "$base"
export PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1 PYTHONPATH="$base/tools-v2"
stage=prepare-v2
trap 'rc=$?; printf "{\"stage\":\"%s\",\"returncode\":%s}\n" "$stage" "$rc" > PIPELINE_V2_STATUS.json' EXIT
python3 tools-v2/prepare_fpcompare170.py "$base/prepared-v2" clang-22 > prepared-v2.log 2>&1
find prepared-v2 -type f -print0 | sort -z | xargs -0 sha256sum > V2_MANIFEST_FREEZE.sha256
chmod -R a-w prepared-v2
for phase in pilot-repair remaining-v2; do
 stage="$phase-build"
 d="$base/compare-class-$phase";mkdir "$d"
 if test "$phase" = pilot-repair; then units=REPAIR_PILOT_UNITS.json; else units=prepared-v2/compare-class-remaining.json; fi
 python3 tools-v2/vadd.py build --family fpcompare170 --output "$d/corpus" --compiler clang-22 --build-jobs 4 --link /home/vick/rvv-directed-task145/link.ld --units-file "$units" > "$d/build.log" 2>&1
 stage="$phase-admission"
 while ! python3 tools-v2/resources164.py gate guest "$d/GUEST_ADMISSION.json"; do sleep 2; done
 stage="$phase-run"
 python3 tools-v2/vadd.py run --root "$d/corpus" --engine /home/vick/rvdbt-host512-task167-build/build/bin/elfrun --spike /home/vick/rvv-directed-task145/deps/spike --pk /home/vick/rvv-directed-task145/deps/pk --sail /home/vick/rvv-act4-tools/bin/sail_riscv_sim --flags FLAGS.json --jobs 8 > "$d/run.log" 2>&1
 date -u > "$d/GUEST_COMPLETE"
 if test "$phase" = pilot-repair; then
  stage=pilot-join
  python3 repair_fpcompare170.py "$base" > compare-pilot-join.log 2>&1
  stage=pilot-controls
  python3 /home/vick/rvv-task168/offline_admission168.py 1 compare-class-pilot-v2/CONTROLS_ADMISSION.json
  python3 tools-v2/controls_fpcompare170.py compare-class-pilot-v2/corpus compare-class-pilot-v2/controls > compare-class-pilot-v2/controls.log 2>&1
  python3 semantic_controls170.py compare-class-pilot-v2/corpus compare-class-pilot-v2/semantic-controls > compare-class-pilot-v2/semantic-controls.log 2>&1
 fi
done
stage=complete
sha256sum -c V2_TOOLS_FREEZE.sha256 > v2-tools-after.log
sha256sum -c V2_MANIFEST_FREEZE.sha256 > v2-manifest-after.log
date -u > GUEST_V2_COMPLETE
