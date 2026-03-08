## Design docs: [docs/rvdbt.md](docs/rvdbt.md)

### Building rvdbt
```sh
# Pre-install clang++, cmake, ninja-build, libboost-all-dev, llvm-15, llvm-15-dev

cd <rvdbt>
git submodule update --init --recursive
mkdir build && cd build
CC=clang CXX=clang++ cmake -GNinja -DCMAKE_BUILD_TYPE=Debug ..
ninja
```

### Running in Docker
```sh
# rvdbt targets linux/amd64 host ISA.
# On Apple Silicon this uses Docker's amd64 emulation.

cd <rvdbt>
./scripts/docker-build-and-smoke.sh

# Optional: open an interactive shell in the same image
./scripts/docker-shell.sh
```

Notes:
- `docker-build-and-smoke.sh` builds a dev image, initializes submodules, builds rvdbt with clang+ninja, and runs `elfrun --help` / `elfaot --help`.
- Override defaults with env vars: `DOCKER_PLATFORM`, `RVDBT_DOCKER_IMAGE`.
- To actually execute guest code, provide a prebuilt static `rv32` Linux ELF in `troot/` (the image verifies rvdbt itself, but does not include a full `riscv32-linux-gnu` userspace toolchain).

### Running with riscv-gnu-toolchain in Docker
```sh
# Build image with riscv32-unknown-linux-gnu-gcc (from riscv-gnu-toolchain)
./scripts/docker-build-with-rv32-toolchain.sh

# Compile an example and run:
# JIT run -> build AOT -> AOT run
./scripts/docker-compile-and-run-example.sh examples/pi_double.c pi_double
```

Notes:
- Toolchain image is intentionally separate because building riscv-gnu-toolchain is heavy.
- Default toolchain image name can be overridden with `RVDBT_RV32_DOCKER_IMAGE`.
- If the toolchain configuration changes, rebuild the image before rerunning examples.

### Using rvdbt
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
