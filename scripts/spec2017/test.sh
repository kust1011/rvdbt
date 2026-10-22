#!/usr/bin/env bash
set -euo pipefail

echo 'SPEC2017RateTest has no workload definition in examples/benchmarks.py.' >&2
echo 'This legacy entry cannot run until test-input commands are defined.' >&2
echo 'ref.sh and train.sh use different input sets; neither substitutes for test.' >&2
exit 2
