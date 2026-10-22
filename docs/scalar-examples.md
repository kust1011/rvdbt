# Scalar examples and inherited AOT workflow

The following material is retained from upstream for context. Its historical
LLVM versions, scalar scope and AOT examples are not the supported RVV replay
recipe or an RVV-AOT validation claim.

## Scalar instruction tests
To test prebuilt of `rv32ui` and `rv32um`, run
```shell
bash scripts/prebuilt-riscv-tests.sh
```
Both scalar runners locate inputs relative to their own repository. Their
optional build-directory argument defaults to `build-llvm-19`; relative paths
are resolved from the repository root, and absolute paths may be used:
```sh
bash scripts/prebuilt-riscv-tests.sh "build with spaces"
bash scripts/riscv-tests.sh /absolute/path/to/build
```
The selected build must contain executable `bin/elfrun`. The runners create
`troot` and `tcache` there, reject missing inputs and failed copies, and return
nonzero if any test fails. These inherited scalar checks use guest exit status;
they are separate from the RVV validation above.

Or to test `rv32ui` and `rv32um` built from `riscv-tests`, patch and run script as follow.
```shell
cd riscv-tests
git apply ../patches/riscv-tests.patch
cd isa
make rv32ui rv32um
cd ../..
bash scripts/riscv-tests.sh
```
## Original build and execution example

See the [original architecture](rvdbt.md) for the inherited system design.
Run the commands below from the repository root unless a `cd` is shown.

### Building rvdbt
```sh
# Pre-install clang++, cmake, ninja-build, libboost-all-dev, llvm-15, llvm-15-dev

cd <rvdbt>
git submodule update --init --recursive
mkdir build && cd build
CC=clang CXX=clang++ cmake -GNinja -DCMAKE_BUILD_TYPE=Debug ..
ninja
```
### Running rvdbt
```sh
# First of all, rvdbt is only a proof of concept, it is quite unstable.
# File IO, memory maps, timers are permitted, rvdbt is able to run
# *Coremark* and *MIBench* benchsuite, as well as few examples in this repo.
# Supported platforms:
# 	guest ISA - *rv32ia*, host ISA - amd64
#	guest/host OS - linux v4+
#	tested with glibc/newlib and riscv32-unknown-linux-gnu-gcc 12.2.0

# Pre-install clang, libboost-all-dev, llvm-15, llvm-15-dev

cd <rvdbt>/build
# Create isolated fs root and cache dir
mkdir troot tcache

# Compile an example, use `target=rv32i` and `static` linking
<riscv32-gcc> -march=rv32i -fpic -fpie -static -O2 ../examples/pi_double.c
mv a.out troot

# Run: [options] -- [guest argv]. Guest argv is relative to `troot`!!
./bin/elfrun --fsroot troot --cache tcache -- a.out 100000
# expected out: prec=100000, res=3.1415926535897936, raw=400921fb54442d19
# increase a.out `prec` for benchmarking
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
