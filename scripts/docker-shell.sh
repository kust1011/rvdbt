#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
IMAGE="${RVDBT_DOCKER_IMAGE:-rvdbt-dev:llvm15}"

docker run --rm -it \
  --platform "${PLATFORM}" \
  -v "${ROOT_DIR}:/workspace" \
  -w /workspace \
  "${IMAGE}" \
  /bin/bash
