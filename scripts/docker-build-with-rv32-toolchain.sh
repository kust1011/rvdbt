#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
IMAGE="${RVDBT_RV32_DOCKER_IMAGE:-rvdbt-dev:llvm15-rv32ia}"

docker build \
  --platform "${PLATFORM}" \
  -t "${IMAGE}" \
  -f "${ROOT_DIR}/Dockerfile.toolchain" \
  "${ROOT_DIR}"

echo "Built image: ${IMAGE}"
