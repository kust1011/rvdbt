#!/bin/bash
set -euo pipefail
base=$1
cd "$base"
export PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1
date -u > START
uptime > resource-before.log
free -b >> resource-before.log
df -B1 . >> resource-before.log
sed -n '/Cpus_allowed/p' /proc/self/status >> resource-before.log
ps -eo user,pid,ni,pcpu,pmem,comm --sort=-pcpu | head -20 >> resource-before.log
sha256sum -c FREEZE.sha256 > freeze-before.log
units=()
if test -f UNITS.json; then units=(--units-file UNITS.json); fi
if python3 scripts/vadd.py build --family mergemove151 --output corpus --compiler clang-22 --build-jobs 8 --link ../user.ld "${units[@]}" > build.log 2>&1; then build_rc=0; else build_rc=$?; fi
run_rc=125; audit_rc=125; controls_rc=125; summary_rc=125
if test "$build_rc" = 0; then
  if python3 scripts/vadd.py run --root "$base/corpus" --engine /home/vick/rvdbt-host512-task142-build/build/bin/elfrun --spike /home/vick/rvv-directed-task145/deps/spike --pk /home/vick/rvv-directed-task145/deps/pk --sail /home/vick/rvv-act4-tools/bin/sail_riscv_sim --flags ../FLAGS.json --jobs 12 > run.log 2>&1; then run_rc=0; else run_rc=$?; fi
  if python3 scripts/audit.py corpus audit > audit.log 2>&1; then audit_rc=0; else audit_rc=$?; fi
  if test "$run_rc" = 0 && test "$audit_rc" = 0; then
    if python3 scripts/reject_mergemove150_next.py corpus controls > controls.log 2>&1; then controls_rc=0; else controls_rc=$?; fi
    if python3 scripts/summarize148.py . evidence > summarize.log 2>&1; then summary_rc=0; else summary_rc=$?; fi
  fi
fi
sha256sum -c FREEZE.sha256 > freeze-after.log
printf '{"build":%s,"run":%s,"audit":%s,"controls":%s,"summary":%s}\n' "$build_rc" "$run_rc" "$audit_rc" "$controls_rc" "$summary_rc" > STAGE_STATUS.json
date -u > COMPLETE
