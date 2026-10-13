#!/bin/bash
set -euo pipefail
cd /home/vick/rvv-directed-task149/zero-full
export RVV_COMPRESS=1 PYTHONDONTWRITEBYTECODE=1
sha256sum -c FREEZE.sha256 > freeze-before.log
if python3 scripts/vadd.py build --family muldiv149 --output corpus --compiler clang-22 --build-jobs 4 --link ../user.ld --units-file ../ZERO_FULL_UNITS.json > build.log 2>&1; then build_rc=0; else build_rc=$?; fi
if [ "$build_rc" = 0 ]; then
  if python3 scripts/vadd.py run --root /home/vick/rvv-directed-task149/zero-full/corpus --engine /home/vick/rvdbt-host512-task142-build/build/bin/elfrun --spike /home/vick/rvv-directed-task145/deps/spike --pk /home/vick/rvv-directed-task145/deps/pk --sail /home/vick/rvv-act4-tools/bin/sail_riscv_sim --flags /home/vick/rvv-directed-task149/FLAGS.json --jobs 4 > run.log 2>&1; then run_rc=0; else run_rc=$?; fi
  if python3 scripts/audit.py corpus audit > audit.log 2>&1; then audit_rc=0; else audit_rc=$?; fi
  if python3 scripts/reject_zero149.py corpus controls > controls.log 2>&1; then controls_rc=0; else controls_rc=$?; fi
  if python3 scripts/summarize148.py . evidence > summarize.log 2>&1; then summary_rc=0; else summary_rc=$?; fi
else run_rc=125; audit_rc=125; controls_rc=125; summary_rc=125; fi
sha256sum -c FREEZE.sha256 > freeze-after.log
printf '{"build":%s,"run":%s,"audit":%s,"controls":%s,"summary":%s}\n' "$build_rc" "$run_rc" "$audit_rc" "$controls_rc" "$summary_rc" > STAGE_STATUS.json
date -u > COMPLETE
