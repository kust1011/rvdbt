# Portable external replay

Run on an AVX512 host with LLVM/Clang/LLD22, CMake, Ninja, Boost/OpenSSL development
files, a RISC-V bare-metal GCC with RV32 ilp32d multilib, Python numpy/jsonpickle/mergedeep. Spike needs Boost system/regex libraries and dtc; PK needs target newlib headers.
Use a new checkout and unused output directories. No historical goldens are generated.

```sh
git submodule update --init dbt/third_party/asmjit dbt/third_party/elfio
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-22 -DCMAKE_CXX_COMPILER=clang++-22 \
  -DLLVM_PATH=/usr/lib/llvm-22 -DRVV_HOST_CHUNK_BITS=512
ninja -C build -j2 elfrun
python3 scripts/fetch_rvv_external.py --output /path/to/new-dependencies
```

Fetch Spike and PK from URLs/revisions in scripts/rvv/sources.lock.json. For each:
`git clone URL SOURCE; git -C SOURCE checkout --detach REVISION`.
Build Spike with `mkdir build; cd build; ../configure --prefix=INSTALL; make -j2; make install`.
Build PK with `mkdir build; cd build; ../configure --host=riscv64-unknown-elf --with-arch=rv32gc --with-abi=ilp32d; make -j2`.
Dependencies are obtained independently; no toolchains are distributed.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_rvv_external.py
python3 scripts/run_rvv_external.py \
  --rvvts /path/to/new-dependencies/rvvts \
  --engine build/bin/elfrun --library-dir build/lib \
  --spike /path/to/spike-install/bin/spike --pk /path/to/pk-build/pk \
  --libgcc "$(riscv64-unknown-elf-gcc -march=rv32g -mabi=ilp32d -print-libgcc-file-name)" \
  --compiler clang-22 --llc llc-22 --output /path/to/new-replay
```

Source/header notices and exact adaptations are in the two fixture READMEs.
The lock, SHA manifest, original source, API inputs/body, full observation parser
and original comparator identify the oracle. Missing/changed inputs fail before
execution; nonzero exit, timeout, incomplete output and mismatches fail replay.
Raw commands/stdout/stderr/return/timeout/checker results and fresh executable
identities remain in the new output. Bulky working caches and host dumps stay
there; only selected small raw artifacts should be archived in Git.

To resume an interrupted replay, add `--reuse-successful-from /path/to/prior-replay`
and still choose a new output directory. Reuse requires matching executable and
guest-ELF identities, fixture, configuration, execution options, and intact raw
output. Output/cache directory paths may relocate; VLEN, method flags, reference
ISA and proxy kernel may not change. Each reused output is checked again by the
current checker. The summary separates `new_calls` from `reused_receipts`;
rechecked receipts are not new guest executions.

This replay covers two fixtures. It does not reproduce historical595-form results
or validate general precise fault/retry, signal delivery or arbitrary configurations.

On a bare GCC installation without target libc, configure PK with LDFLAGS=-nostdlib
and run make with CFLAGS=-I/path/to/newlib/headers. PK itself links freestanding.
On xbd, libnewlib-dev and Boost system/regex packages were downloaded and extracted
with apt download / dpkg-deb -x into new scratch, without installing globally.
Spike configure used --with-boost=/usr --with-boost-libdir=PRIVATE_LIBDIR
--with-boost-asio=boost_system --with-boost-regex=boost_regex. Include PRIVATE_LIBDIR
and Spike install/lib in LD_LIBRARY_PATH when replaying. These are dependency
adaptations, with failed attempts retained, not changes to guest checks.

After replay, run full-packet negative controls (tool checks, not ISA counts):
```sh
RVVTS_SOURCE=/path/to/new-dependencies/rvvts \
RVVTS_PACKET=/path/to/new-replay/runs/rvvts/Spike/stdout \
python3 -m unittest discover -s scripts -p test_rvv_external_packet.py
```

Verify emitted input/body and complete observer transport before accepting replay:
```sh
python3 scripts/verify_rvv_external_elf.py --elf /path/to/new-replay/guests/rvvts.elf \
  --nm llvm-nm-22 --output /path/to/new-replay/elf-verification.json
python3 scripts/audit_rvv_external_admission.py --results /path/to/new-replay --source .
```
