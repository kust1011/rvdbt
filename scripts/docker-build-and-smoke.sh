#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
IMAGE="${RVDBT_DOCKER_IMAGE:-rvdbt-dev:llvm15}"

docker build \
  --platform "${PLATFORM}" \
  -t "${IMAGE}" \
  -f "${ROOT_DIR}/Dockerfile" \
  "${ROOT_DIR}"

docker run --rm \
  --platform "${PLATFORM}" \
  -v "${ROOT_DIR}:/workspace" \
  -w /workspace \
  "${IMAGE}" \
  /bin/bash -lc '
    set -euo pipefail
    git submodule update --init --recursive
    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
    cmake --build build -j"$(nproc)"
    test -x ./build/bin/elfrun
    test -x ./build/bin/elfaot
    ./build/bin/elfrun --help >/tmp/elfrun-help.txt || true
    ./build/bin/elfaot --help >/tmp/elfaot-help.txt || true
    echo "rvdbt: build + smoke test passed"
  '
