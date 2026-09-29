## RVV thesis continuation

This repository continues [Wendell Lin's rvdbt](https://github.com/Wendell-Lin/rvdbt)
and retains its Git history and original MIT license. The RVV research snapshot
adds RISC-V Vector execution paths to the lightweight QCG JIT, consecutive-vector-
instruction value retention (M1), and runtime-`vl`-based omission of eligible
inactive high chunks (M2). The integration commit imports the implementation as
one snapshot; it does not reconstruct the chronological development history.

The evaluated thesis scope is **QCG**, not complete native lowering of every RVV
1.0 instruction and not a claim of completed online LLVM-AOT performance. Forms
outside a direct route may use a semantic helper. The repository contains
experimental AOT/tiering paths; their presence does not make them evaluated
thesis results. Benchmark guest binaries and restricted input datasets are not
redistributed here.

See [the RVV QCG design and code map](docs/rvv-qcg.md) for the translation
path, M1/M2 legality, and focused checks.

For an x86 host with AVX-512 and an installed LLVM 20 toolchain:

```sh
git submodule update --init dbt/third_party/asmjit dbt/third_party/elfio
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-20 -DCMAKE_CXX_COMPILER=clang++-20 \
  -DLLVM_PATH=/usr/lib/llvm-20 -DRVV_HOST_CHUNK_BITS=512
ninja -C build -j2 elfrun
```

The AVX-512 host option is for running the emitted-code tests on a compatible
machine. The same source also contains narrower host-chunk routes; do not run
an AVX-512 build on a host without the required CPU features. See the existing
design notes below for the base translator; the RVV work extends rather than
replaces that architecture.

## My progress and todo
https://hackmd.io/iDSBjMJTSTiiBJ8ODpPvTQ?both
## RISCV-TESTS
To test prebuilt of `rv32ui` and `rv32um`, run
```shell
bash scripts/prebuilts-riscv-tests.sh
```
Or to test `rv32ui` and `rv32um` built from `riscv-tests`, patch and run script as follow.
```shell
cd riscv-tests
git apply ../patches/riscv-tests.patch
cd isa
make rv32ui rv32um
cd ../..
bash scripts/riscv-tests.sh
```
## Originally
Below are original content from the forked repo.
### Design docs: [docs/rvdbt.md](docs/rvdbt.md)
#### Building for rvdbt
```sh
# Pre-install clang++, cmake, ninja-build, libboost-all-dev, llvm-15, llvm-15-dev

cd <rvdbt>
git submodule update --init --recursive
mkdir build && cd build
CC=clang CXX=clang++ cmake -GNinja -DCMAKE_BUILD_TYPE=Debug ..
ninja
```
#### Using rvdbt
```sh
# First of all, rvdbt is only a proof of concept, it is quite unstable.
# File IO, memory maps, timers are permitted, rvdbt is able to run
# *Coremark* and *MIBench* benchsuite, as well as few examples in this repo.
# Supported platforms:
# 	guest ISA - *rv32ia*, host ISA - amd64
#	guest/host OS - linux v4+
#	tested with glibc/newlib and riscv32-unknown-linux-gnu-gcc 12.2.0

# Pre-install clang, libboost-all-dev, llvm-15, llvm-15-dev

cd <rvbdt>/build
# Create isolated fs root and cache dir
mkdir troot tcache

# Compile an example, use `target=rv32i` and `static` linking
<riscv32-gcc> -march=rv32i -fpic -fpie -static -O2 ../examples/pi_double.c
mv a.out troot

# Run: [options] -- [guest argv]. Guest argv is relative to `troot`!!
./bin/elfrun --fsroot troot --cache tcache -- a.out 100000
# expected out: prec=100000, res=3.1415926535897936, raw=400921fb54442d19
# increate a.out `prec` for benchmarking 
# It may fail, for example if different libc or ISA is used
# 	add logs: --logs dbt:ukernel
# compatible qemu cmd: 
# 	qemu-riscv32 troot/a.out 100000

# Use collected tcache/<checksum>.prof to create precompiled image
./bin/elfaot --logs dbt:aot --cache tcache --mgdump . --elf troot/a.out

# View compiled binary graph (graphviz dot). xdot suggested.
xdot modulegraph.gv

# Run, --aot on
./bin/elfrun --fsroot troot --cache tcache --aot on -- a.out 100000
```
