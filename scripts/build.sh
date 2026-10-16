#! /bin/bash
set -euo pipefail
# $1 is llvm version
build_dir=build-llvm-${1:?LLVM version required}
mkdir -p "$build_dir"
cd "$build_dir"
mkdir -p dbtcache troot tcache

CC=clang CXX=clang++ cmake -GNinja -DCMAKE_BUILD_TYPE=Debug \
        -DLLVM_PATH=/usr/lib/llvm-$1 \
        ..

ninja -j4
