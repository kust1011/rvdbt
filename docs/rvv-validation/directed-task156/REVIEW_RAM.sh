#!/bin/bash
set -euo pipefail
base=/dev/shm/rvv-directed-task156-review
cd "$base"
export RVV_COMPRESS=1 PYTHONDONTWRITEBYTECODE=1
sha256sum -c FREEZE.sha256 > freeze-before.log
if nice -n 10 python3 scripts/audit.py corpus audit > audit.log 2>&1; then audit_rc=0; else audit_rc=$?; fi
controls_rc=125;summary_rc=125
if test "$audit_rc" = 0; then
  if nice -n 10 python3 scripts/reject_wmac156.py corpus controls > controls.log 2>&1; then controls_rc=0; else controls_rc=$?; fi
  if test "$controls_rc" = 0; then
    if nice -n 10 python3 scripts/summarize148.py . evidence > summary.log 2>&1; then summary_rc=0; else summary_rc=$?; fi
  fi
fi
sha256sum -c FREEZE.sha256 > freeze-after.log
printf '{"audit":%s,"controls":%s,"summary":%s}\n' "$audit_rc" "$controls_rc" "$summary_rc" > STAGE_STATUS.json
date -u > COMPLETE
