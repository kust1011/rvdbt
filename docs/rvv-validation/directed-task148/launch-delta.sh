#!/bin/bash
set -euo pipefail
cd /home/vick/rvv-directed-task148/delta
export PYTHONDONTWRITEBYTECODE=1
sha256sum -c FREEZE.sha256 > freeze-before.log
python3 scripts/vadd.py run --root /home/vick/rvv-directed-task148/delta/corpus --engine /home/vick/rvdbt-host512-task142-build/build/bin/elfrun --spike /home/vick/rvv-directed-task145/deps/spike --pk /home/vick/rvv-directed-task145/deps/pk --sail /home/vick/rvv-act4-tools/bin/sail_riscv_sim --flags /home/vick/rvv-directed-task148/FLAGS.json --jobs 2 > full-run.log 2>&1
python3 scripts/audit.py corpus audit > audit.log 2>&1
python3 scripts/reject148.py corpus controls > controls.log 2>&1
sha256sum -c FREEZE.sha256 > freeze-after.log
date -u > COMPLETE
