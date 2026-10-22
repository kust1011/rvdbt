#!/bin/sh
set -eu

# Usage: $0 [LLVM_VERSION]; paths can be overridden without changing the script.
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
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
llvm_path=${LLVM_PATH:-"/usr/lib/llvm-$llvm_version"}
case "$llvm_path" in /*) ;; *) llvm_path="$repo_dir/$llvm_path" ;; esac
jobs=${RVDBT_JOBS:-4}
case "$jobs" in ''|0|*[!0-9]*) echo "RVDBT_JOBS must be positive" >&2; exit 2 ;; esac
mkdir -p -- "$build_dir/dbtcache" "$build_dir/troot" "$build_dir/tcache"
CC=${CC:-clang} CXX=${CXX:-clang++} cmake -S "$repo_dir" -B "$build_dir" \
    -G Ninja -DCMAKE_BUILD_TYPE=Debug "-DLLVM_PATH=$llvm_path"
exec cmake --build "$build_dir" --parallel "$jobs"
