#!/bin/bash
set -euo pipefail
base=$1
cd "$base"
export PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1
python3 - <<'GATE'
import json, shutil
from pathlib import Path
assert not Path('corpus').exists(), 'preserve existing corpus'
budget=1024**3 if Path('UNITS.json').exists() else 4*1024**3
assert shutil.disk_usage('.').free>=10*1024**3+budget, '10GiB reserve plus finite batch allowance'
assert int(Path('/proc/meminfo').read_text().split('MemAvailable:')[1].split()[0])*1024>=budget+4*1024**3, 'healthy memory required'
GATE
date -u > START
free -b > resource-before.log
df -B1 . >> resource-before.log
sed -n '/Cpus_allowed/p' /proc/self/status >> resource-before.log
sha256sum -c FREEZE.sha256 > freeze-before.log
units=()
if test -f UNITS.json; then units=(--units-file UNITS.json); fi
if python3 scripts/vadd.py build --family fp157 --output corpus --compiler clang-22 --build-jobs 4 --link user.ld "${units[@]}" > build.log 2>&1; then build_rc=0; else build_rc=$?; fi
run_rc=125
if test "$build_rc" = 0; then
  if python3 scripts/vadd.py run --root "$base/corpus" --engine /home/vick/rvdbt-host512-task142-build/build/bin/elfrun --spike /home/vick/rvv-directed-task145/deps/spike --pk /home/vick/rvv-directed-task145/deps/pk --sail /home/vick/rvv-act4-tools/bin/sail_riscv_sim --flags FLAGS.json --jobs 8 > run.log 2>&1; then run_rc=0; else run_rc=$?; fi
fi
sha256sum -c FREEZE.sha256 > freeze-after.log
printf '{"build":%s,"run":%s,"audit":125,"controls":125,"summary":125}\n' "$build_rc" "$run_rc" > STAGE_STATUS.json
date -u > COMPLETE
# Offline audits belong to main on xbd. Task157 replays this new pilot locally.
