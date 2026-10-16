#!/bin/sh
set -eu

exec python3 examples/benchmarks.py \
    --rvdbt-build-dir "${RVDBT_BUILD_DIR:-$(pwd)/build-llvm-${1:?LLVM version required}}" \
    --prebuilts "${RVDBT_PREBUILTS:-$(pwd)/prebuilts}" \
    --riscv32-gcc riscv32-unknown-elf-gcc \
    --rvdbt-jit \
    --rvdbt-llvmaot-1000 \
    --rvdbt-llvmaot \
    --objective test
