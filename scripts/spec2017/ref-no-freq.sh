#!/bin/sh
set -eu

# Usage: $0 [LLVM_VERSION]
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
if [ "$#" -gt 1 ]; then
    echo "Usage: $0 [LLVM_VERSION]" >&2
    exit 2
fi
llvm_version=${1:-20}
case "$llvm_version" in
    ''|*[!0-9]*) echo "LLVM_VERSION must be numeric" >&2; exit 2 ;;
esac
build_dir=${RVDBT_BUILD_DIR:-"$repo_dir/build-llvm-$llvm_version"}
case "$build_dir" in /*) ;; *) build_dir="$repo_dir/$build_dir" ;; esac
prebuilts=${RVDBT_PREBUILTS:-"$repo_dir/prebuilts"}
case "$prebuilts" in /*) ;; *) prebuilts="$repo_dir/$prebuilts" ;; esac
exec python3 "$repo_dir/examples/benchmarks_nofreq.py" \
    --rvdbt-build-dir "$build_dir" \
    --prebuilts "$prebuilts" \
    --riscv32-gcc "${RISCV32_GCC:-riscv32-unknown-elf-gcc}" \
    --cache-dir spec2017_no_freq \
    --rvdbt-jit-not-freq \
    --benchmark SPEC2017Rate
