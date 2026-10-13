#!/bin/bash
set -euo pipefail
base=/home/vick/rvv-directed-task156
for attempt in $(seq 1 60); do
  if test -f "$base/extend-pilot/COMPLETE"; then
    cd "$base/destchunk-pilot"
    nice -n 10 bash launch.sh "$base/destchunk-pilot"
    python3 - <<'GATE'
import json
assert all(v==0 for v in json.load(open('STAGE_STATUS.json')).values()), 'destination-chunk pilot must pass before full'
GATE
    cd "$base/destchunk-full"
    exec nice -n 10 bash launch.sh "$base/destchunk-full"
  fi
  sleep 30
done
echo 'Extension pilot did not complete within bounded queue interval' >&2
exit 75
