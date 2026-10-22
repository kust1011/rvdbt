#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if (( $# > 1 )) || [[ ! "${1:-20}" =~ ^[0-9]+$ ]]; then
    echo "Usage: $0 [LLVM major version, default: 20]" >&2
    exit 2
fi
cd -- "$repo_root"
exec python3 "$repo_root/examples/benchmarks.py" \
    --rvdbt-build-dir "$repo_root/build-llvm-${1:-20}" \
    --prebuilts "$repo_root/prebuilts" \
    --riscv32-gcc riscv32-unknown-linux-gnu-gcc \
    --cache-dir rv32emu-no-prop \
    --no-qemu \
    --rvdbt-jit \
    --rvdbt-llvmaot \
    --rvdbt-llvmaot-hotspot \
    --rvdbt-llvmaot-noprop \
    --benchmark rv32emu
