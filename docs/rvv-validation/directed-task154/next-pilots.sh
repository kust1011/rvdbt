#!/bin/bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1 RVV_COMPRESS=1
base=/home/vick/rvv-directed-task154
while pgrep -f '^python3 scripts/vadd.py run --root /home/vick/rvv-directed-task154/full/corpus' >/dev/null; do sleep 15; done
# Recheck reserve at each pilot; existing artifacts are never deleted.
for phase in qemu-pilot widen-pilot; do
 df -B1 "$base" > "$base/$phase/disk-launch.log"
 bash "$base/$phase/launch.sh" "$base/$phase" > "$base/$phase/launcher.log" 2>&1
 done
