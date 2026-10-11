# Task80: actual CHIPS smoke records

These are selected original small raw records from Task80 (2026-10-11), copied
byte-for-byte with original commands/paths. [Source manifest](source-manifest.json)
records their hashes and source locators. [Source/build provenance](source-build-provenance.json)
retains selected Git, submodule and compiler records; full host/private staging
content is omitted. [Configure command](engine-build/configure-command.json),
[configure result](engine-build/configure-result.json), [engine build command](engine-build/build-command.json)
and [engine build result](engine-build/build-result.json) document the fresh engine build.
Fixture [build registration](build/build.json), [command](build/command.json),
[stdout](build/stdout) and [stderr](build/stderr) retain reconstruction evidence.
No binary, toolchain or working cache is distributed in this directory.

Task80 built source `85a51c988a07622e286ae8eb208d37ffcad7f41c` locally, then ran
those engine/library bytes on an AVX-512 AMD Ryzen 9 9950X3D / Ubuntu24.04.3 host.
Clang/LLD20.1.8 rebuilt the pinned CHIPS stage2 fixture byte-identically. Recorded
SHA256 identities (new engine build, separate from historical candidates):

| Object | SHA256 |
|---|---|
| elfrun | c556199719fe01d5e7eee75d86429e9687341784b9b749143bf2d2678cf34133 |
| libdbtjitshared.so | 16e8d97d87a551e2d9ee1396c012957842289d4f3d49dfb2a9b0ad8ec3e09d92 |
| Fixture ELF | 94a1a592014d8d287fb17dc17fcd42e0c05e98f3fb694e253d5c87856f30440b |

[Invocation](results/invocation.json) and [manifest](results/manifest.json) bind
those identities, fixture and configurations. The historical run used a private
Boost1.74 runtime dependency, whose hash is recorded there; the payload is omitted.
A reader must provide compatible development/runtime dependencies independently.
The commands are provenance with historical paths, not executable portable paths.

| Configuration | Raw exit | Raw stdout | Result/raw directory |
|---|---:|---|---|
| B | 0 | `CHIPS_PASS\n` | [records](results/chips-vsmul-vv-B/) |
| M1 | 0 | `CHIPS_PASS\n` | [records](results/chips-vsmul-vv-M1/) |
| M2 | 0 | `CHIPS_PASS\n` | [records](results/chips-vsmul-vv-M2/) |
| BOTH | 0 | `CHIPS_PASS\n` | [records](results/chips-vsmul-vv-BOTH/) |

Each directory includes command, case, result and exact stdout/stderr.
[Summary](results/summary.json) records four PASS, zero controls and unchanged
candidate identities. These are four executions of one complete `vsmul.vv`
fixture at VLEN1024, not four newly covered forms or new 595-form validation.
The result records explicitly say `instruction_route=NOT_OBSERVED_BY_THIS_RUNNER`.
Zero route counters/header-only frame diagnostics do not prove per-PC M1/M2
admission. The original selected-output checker does not establish arbitrary
mask/tail/overlap/restart, full state or full RVV conformance. Task81 packaging
adds zero executions and does not recreate golden generation.

## Reader workflow: build -> pinned fixture -> four results

For the exact Task80 source, use a separate checkout at the SHA above; the current
delivery includes later documentation/index packaging. On a compatible AVX-512
host with LLVM20 development files, Clang/LLD20, CMake, Ninja and Boost installed,
run from the repository root:

```sh
git submodule update --init dbt/third_party/asmjit dbt/third_party/elfio
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-20 -DCMAKE_CXX_COMPILER=clang++-20 \
  -DLLVM_PATH=/usr/lib/llvm-20 -DRVV_HOST_CHUNK_BITS=512
ninja -C build -j2 elfrun

git clone --recurse-submodules https://github.com/chipsalliance/riscv-vector-tests.git /path/to/chips
git -C /path/to/chips checkout --detach f76bff121dce91b6b23e1d37be77a5e44af914c3
git -C /path/to/chips submodule update --init --recursive

PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_rvv_smoke.py \
  --upstream /path/to/chips --compiler clang-20 \
  --engine build/bin/elfrun --library-dir build/lib \
  --output /path/to/new-smoke --jobs 2
```

The [source lock](../../../scripts/rvv/sources.lock.json) pins CHIPS and environment
`81721c126d7dd7335829948b4a19070546e465d6`. The existing
[licensed fixture](../../../scripts/rvv/fixtures/chips-vsmul-vv/README.md) contains
the complete stage2 assembly and unchanged goldens under Apache-2.0. Only this
already cleared fixture is distributed. No ATG/RVISmith source or test binaries
are copied. The runner verifies source/ELF identity, then registers the newly
built DUT and writes four configured results to a new directory. A rebuilt DUT
may have different byte identities; keep that separate from this saved record.
`--build-only` cannot reproduce these four execution results.

To inspect saved records without executing the DUT, rebuild only the fixture into
an unused directory, then use the existing auditor:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_rvv_smoke.py \
  --upstream /path/to/chips --compiler clang-20 --build-only \
  --output /path/to/new-fixture-build
PYTHONDONTWRITEBYTECODE=1 python3 scripts/audit_rvv_results.py \
  --results docs/rvv-validation/smoke-task80/results \
  --inputs /path/to/new-fixture-build/inputs
```

The auditor requires the rebuilt, registered input ELF, deliberately omitted from
Git. It checks record consistency, not independent attestation of execution or
ISA truth. No complete historical campaign or oracle-generation workflow is
provided. See [current-scope retrieval limits](../current-scope/README.md#retrieval-limits)
for unpublished historical dependencies.
