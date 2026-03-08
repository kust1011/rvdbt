#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
IMAGE="${RVDBT_RV32_DOCKER_IMAGE:-rvdbt-dev:llvm15-rv32ia}"
BUILD_DIR="${RVDBT_BUILD_DIR:-build}"
FSROOT_REL="${RVDBT_FSROOT_REL:-${BUILD_DIR}/troot}"
CACHE_REL="${RVDBT_CACHE_REL:-${BUILD_DIR}/tcache}"
EXAMPLE_SRC="${1:-examples/pi_double.c}"
OUTPUT_NAME="${2:-a.out}"
if [[ "$#" -gt 2 ]]; then
  GUEST_ARGS=("${@:3}")
else
  GUEST_ARGS=()
fi

GUEST_ARGS_JOINED=""
for arg in "${GUEST_ARGS[@]}"; do
  GUEST_ARGS_JOINED+=" '$(printf "%s" "${arg}" | sed "s/'/'\"'\"'/g")'"
done

if [[ ! -f "${ROOT_DIR}/${EXAMPLE_SRC}" ]]; then
  echo "Example source not found: ${ROOT_DIR}/${EXAMPLE_SRC}" >&2
  exit 1
fi

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  "${ROOT_DIR}/scripts/docker-build-with-rv32-toolchain.sh"
fi

docker run --rm \
  --platform "${PLATFORM}" \
  -v "${ROOT_DIR}:/workspace" \
  -w /workspace \
  "${IMAGE}" \
  /bin/bash -lc "
    set -euo pipefail
    git submodule update --init --recursive
    cmake -S . -B '${BUILD_DIR}' -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
    cmake --build '${BUILD_DIR}' -j\"\$(nproc)\"

    mkdir -p '${FSROOT_REL}' '${CACHE_REL}'
    riscv32-unknown-linux-gnu-gcc -march=rv32ia -mabi=ilp32 -fpic -fpie -static -O2 '${EXAMPLE_SRC}' -o '${FSROOT_REL}/${OUTPUT_NAME}'

    echo '[1/3] JIT run'
    './${BUILD_DIR}/bin/elfrun' --fsroot '${FSROOT_REL}' --cache '${CACHE_REL}' -- '${OUTPUT_NAME}'${GUEST_ARGS_JOINED}

    echo '[2/3] Build AOT'
    './${BUILD_DIR}/bin/elfaot' --cache '${CACHE_REL}' --mgdump '${CACHE_REL}' --elf '${FSROOT_REL}/${OUTPUT_NAME}'

    echo '[3/3] AOT run'
    './${BUILD_DIR}/bin/elfrun' --fsroot '${FSROOT_REL}' --cache '${CACHE_REL}' --aot on -- '${OUTPUT_NAME}'${GUEST_ARGS_JOINED}
  "
