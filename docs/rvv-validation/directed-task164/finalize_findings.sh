#!/bin/bash
set -euo pipefail
base=/home/vick/rvv-directed-task164
while ! test -f "$base/full-review/CLOSED"; do sleep 10; done
# Reference/ISA failure characterization consumes already-audited original raw.
test -f "$base/full-review/COMPLETE"
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$base/full/scripts" RVV_COMPRESS=1
while ! python3 "$base/resources164.py" gate offline "$base/FINDINGS_CAPACITY.json"; do sleep 10; done
nice -n 10 python3 "$base/findings_fma164.py" "$base/full/corpus" "$base/full-findings" > "$base/full-findings.log" 2>&1
nice -n 10 python3 "$base/retention_fma164.py" "$base" "$base/RETENTION.json" > "$base/retention.log" 2>&1
date -u > "$base/FINAL_DATA_COMPLETE"
