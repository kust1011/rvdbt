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

## Build, run and check RVV

Start with the [public portable replay](docs/rvv-validation/portable-external.md).
It provides configurable DUT, host/guest toolchains, dependency location, isolated
cache and output directories, then builds and checks one complete adapted Ara
file and one retained RVVTS sequence in B/M1/M2/BOTH against Spike. It requires
a compatible AVX-512 Linux host and the documented tools, not a private host.
The checked build includes diagnostics and is **not a performance recipe**.

The complete 595-form retained replay uses the same public runner, but requires
separately supplied input ELFs, original checker snapshots and independent
references. Start with its [retained-corpus commands and bundle prerequisites](docs/rvv-validation/portable-external.md#retained-directed-corpus).
**There is not yet a public download of that complete bundle.** The committed
index and two runnable samples are not substitutes for the missing data.

The stable reading path is:

- [Architecture and code map](docs/rvv-qcg.md): QCG translation, M1/M2 legality,
  helpers and allocator boundaries.
- [Support and evidence guide](docs/rvv-author-guide.md): accepted scope,
  formal/diagnostic/oracle inventory and missing evidence.
- [Public build/run/check](docs/rvv-validation/portable-external.md): fresh
  execution and explicit receipt reuse.
- [627-form scope](docs/rvv-current-scope.md) and
  [original-case navigation](docs/rvv-validation/all-form-records/README.md):
  per-form source/assertion/package selectors.

## Validation evidence

The [measured d252 replay](docs/rvv-validation/delivery-task182/README.md#measured-d252-replay)
has its own [result](docs/rvv-validation/delivery-task182/MEASURED_D252_RESULT.json)
and [595-form ordinary CSV](docs/rvv-validation/delivery-task182/MEASURED_D252_PER_FORM.csv):
95,242 units / 380,968 four-arm calls / 12,069,048 selected checks, plus separately
classified focused, external and sequence results. It uses the measured
executable/library with correctness diagnostics enabled, not identical timing
flags. Independent reference executions are retained, not regenerated.

The RV32/ELEN64 catalogue has **595 applicable mnemonic/operand forms** and
32 excluded ei64 indexed-memory forms. The
[frozen correctness replay](docs/rvv-validation/final-task197/README.md) records
B/M1/M2/Both results for all 595 applicable forms on its pinned executable:
12,069,048 ordinary comparisons, 2,256 focused positives, 592 denial controls,
21,316 external calls and 9,888 sequence DUT checks. The
[historical 595-row CSV](docs/rvv-validation/final-task197/PER_FORM_RESULTS.csv) joins those
compact results; it does not make the complete raw inputs/results public.

For a form's selected dimensions and original answer predicate, then its concrete
source/assertion/reference locators, run from the repository root:

```sh
python3 scripts/rvv_verify.py show --form vadd.vv
python3 scripts/rvv_scope_report.py \
  --navigation docs/rvv-validation/all-form-records/navigation.json.gz \
  --form vadd.vv --output /absolute/path/to/new-form-records
```

These are evidence readers, not new executions. Follow the per-form records to
the original oracle/checker; no universal synthetic expected-output generator is
provided. Research session logs, temporary builds and experiment queues are not
required by the public sample entry.

That historical replay used fresh DUT execution with retained ELFs and independent
references, not fresh oracle execution. Complete latest raw/runner archives remain
in research storage with no public download; selected older CHIPS/ACT/Ara
inspection packages are linked in the support guide. A new build has a new
identity and does not inherit those results. The public two-fixture replay is
independently usable but cannot reproduce or replace the full matrix.

Finite form counts are not full RVV conformance, a tested VLEN/SEW/LMUL Cartesian
product, or proof that M1/M2 admitted every target. General precise fault/retry
and guest-handler repair/return remain unverified. Older performance results
retain their original executable/configuration.

## Inherited scalar examples

The following material is retained from upstream for context. Its historical
LLVM versions, scalar scope and AOT examples are not the supported RVV replay
recipe or an RVV-AOT validation claim.

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
