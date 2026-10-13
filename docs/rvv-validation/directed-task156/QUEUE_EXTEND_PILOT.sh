#!/bin/bash
# This bounded queue waits only for this session's existing guest worker pool.
set -euo pipefail
base=/home/vick/rvv-directed-task156
for attempt in $(seq 1 60); do
  if test -f "$base/wmac-full2/corpus/summary.json"; then
    cd "$base/extend-pilot"
    exec nice -n 10 bash launch.sh "$base/extend-pilot"
  fi
  sleep 30
done
echo 'WMAC guest pool did not complete within bounded queue interval' >&2
exit 75
