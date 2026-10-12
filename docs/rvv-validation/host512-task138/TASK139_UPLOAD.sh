#!/bin/sh
# Prepared only. Main runs after review; no upload/push/merge performed by Task139.
set -eu
python3 scripts/verify_rvv_artifacts.py \
  --manifest docs/rvv-validation/host512-task138/TASK139_ARCHIVES.json \
  --archive-root /tmp/task139-final
# This existing release tag remains historical 49c44174. Main separately publishes
# the reviewed repository revision containing the Task139 reader/docs.
gh release upload rvv-validation-20261012 \
  /tmp/task139-final/task138-inspection.tar.gz \
  docs/rvv-validation/host512-task138/TASK139_ARCHIVES.json \
  --repo kust1011/rvdbt
