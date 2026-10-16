# Build Profiles And Focused Regressions

`Release` selects compiler optimization, not a measurement policy. Use a fresh
build directory for each profile. Plain configuration requires CMake 3.13+
(`add_compile_definitions`/`FindPython3` need 3.12, existing `target_link_options`
needs 3.13). Presets and all commands shown here require CMake 3.21+, Ninja, Python 3,
Boost program_options, LLVM development files, and initialized asmjit/ELFIO
submodules. Set `LLVM_PATH` to the LLVM installation prefix, not its CMake directory.

```sh
git submodule update --init --recursive
cmake --preset performance -DLLVM_PATH=/usr/lib/llvm-20
cmake --build build/performance --target elfrun -j2
cmake --preset diagnostic -DLLVM_PATH=/usr/lib/llvm-20
cmake --build build/diagnostic --target elfrun -j2
```

The performance profile uses Release, host chunks 128, host FMA off, FP
contraction off, FRound implementation 2, no rounding no-op, no ASAN, and all
three counter switches off. `performance-host512` changes only host width and
FMA, with its own build directory; it requires AVX-512F+BW and FMA to execute
even structural tests because these flags apply to the whole binary.
`diagnostic` keeps the same semantics and enables the three counter switches.
It is not a timing configuration. Plain configuration is `custom`, with these
counters now defaulting off; existing caches retain their values. Performance
policy rejects counter-on and known incompatible FP/ASAN settings, not arbitrary
compiler flags or runtime options supplied by a caller.

## Instrumentation Boundary

| Switch | Enabled behavior | Performance setting |
| --- | --- | --- |
| `RVDBT_FAST_STATS` | Admission, chunk, residue and related counters; runtime reporting off does not disable collection; increments are removed by `if constexpr` when compiled off | OFF |
| `RVDBT_CENSUS` | Vector-handler probe/census checks; with both runtime switches off there are checks but no census collection or per-instruction timestamps; handler hooks are removed by `if constexpr` when compiled off | OFF |
| `RVDBT_RA_STATS` | Translation-time spill/fill and global/local counts in QRegAlloc | OFF |

RA counters do not count execution of emitted spill instructions. Turning them
off leaves the existing reporting storage/API present but zero; derived dynamic
spill accounting in AOT then has no measurements. Zero is not a measured absence
of spills. Other runtime dispatch, fault checks and explicitly armed QCG census
sites still exist. These profiles do not claim all framework overhead is gone.

Allowlisted performance changes are host width/FMA for a declared machine and
the runtime method selection under study. Use the same source, compiler, FP
policy, allocator/semantic fixes and measurement boundaries for B/M1/M2/Both.
Record their exact commands and method flags separately: presets do not invent
or validate those four runtime recipes. Leave all other research switches at
defaults, disable traces/censuses, and do not inject extra `-D` definitions.
Rounding no-op, legality/obligation bypasses, unguarded profiled load/jalr value
substitution and oracle target lists are not allowed performance strategies.
Default-off experiments are not thereby accepted supported combinations.

Each successful configuration writes `build-profile.txt` with effective policy
options. Retain it together with `CMakeCache.txt`, `compile_commands.json`, source
diff/commit, compiler version, exact runtime commands and binary/shared-library
hashes. Inspect actual compiler commands for injected flags. Validate correctness
on the very performance binary being measured; diagnostic results supplement,
but never replace, that validation. Rebuild into a new directory rather than
overwriting an executable used by an active run.

## Comparing Build Profiles

### Measured Thesis Configuration

The completed 26-round core/four-round external campaign measured executable
`d252ef99ca083a784c25972c6091218d82de7ba5827a524e47befe1e65ef37ac`
with library `79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af`.
It did **not** use the new `performance` preset. Its retained cache specifies
Release, Clang/LLVM 22, host512, FMA OFF, FP contraction OFF, rounding implementation
2, rounding no-op OFF, ASAN OFF, and **FAST_STATS/CENSUS ON**. Its allocator also
increments translation-time spill/fill counters unconditionally. Runtime reporting
being off does not remove `if constexpr(kFastStats)` admission/per-chunk updates.
The census handler hook still checks its runtime switches when compiled on;
runtime census off avoids collection/timestamps, not the compiled hook/checks.
No separate elapsed-time cost for these retained counters was established.

All four retained timing arms explicitly set `--rvv-qcg-hit-counter=0`,
`--rvv-route-census=0`, `--rvv-stats=0` and `--rvv-run-frame-census=0`.
The generated direct-hit counter is therefore disabled; it is distinct from
the compile-time FAST_STATS/CENSUS gates. FAST_STATS updates occur when their
fast-path functions execute; compiling them in does not establish which paths
each workload reaches or the elapsed cost. In particular, runtime `rvv-stats`
controls reporting, not removal of the compiled chunk/residue updates.
The original 9984 observations retain their validity as measurements of that
recorded, instrumented configuration; they are not counter-free measurements.

The exact retained source is
`thesis_rvv_20260921/artifacts/final_build_performance_20261014/complete-remeasurement-20261015/snapshot/candidate-source.tar.gz`
(SHA256 `7e26c5454b7a5c58641947a3658e9896002dcc4d53c9e2a974d57f271e516e2f`);
the adjacent `CMakeCache.txt` and campaign `manifest.json` bind source, configuration
and measured identities. These are research-storage locations, **not published
downloads**. The dirty source snapshot is not the public `56eccf7` commit.
Publishing it requires a licensed source archive, initialized dependency revisions,
build commands/cache and binary/library manifest; no publication is implied here.

Given that exact source snapshot and its dependencies, reconstruct its policy in a
new directory (substitute your LLVM prefix):

```sh
cmake -S "$MEASURED_SOURCE" -B "$REBUILD" \
  -DCMAKE_C_COMPILER=clang-22 -DCMAKE_CXX_COMPILER=clang++-22 \
  -DLLVM_PATH="$LLVM_ROOT" -DCMAKE_BUILD_TYPE=Release \
  -DRVV_HOST_CHUNK_BITS=512 -DRVDBT_HOST_FMA=OFF \
  -DRVDBT_FP_CONTRACT_OFF=ON -DRVDBT_FROUND_IMPL=2 \
  -DRVDBT_FROUND_DIAG_NOP=OFF -DDBT_ASAN=OFF \
  -DRVDBT_FAST_STATS=ON -DRVDBT_CENSUS=ON
cmake --build "$REBUILD" --target elfrun --parallel 2
```

That snapshot predates the RA gate and profile options. For the current checkout,
the corresponding **configuration**, not identical-source/binary reproduction, uses
the same arguments plus `-DRVDBT_BUILD_PROFILE=custom -DRVDBT_RA_STATS=ON`.
Always record the newly produced identity. The recorded four method commands and
flags belong to the campaign artifact; the public diagnostic fixture flags are
not a substitute for those timing commands.

For a bounded counter-cost comparison, first validate the counter-off executable,
then compare two separate builds of one source with identical semantic/method
flags, inputs and timing boundary, changing only the three counter switches.
Start with a few alternating fresh-process pairs including translation and a
chunk-heavy case; retain output checks, absolute times and variability. Do not
infer a cost from instruction presence, pool new samples with the thesis means,
or start another 26-round campaign without authorization.

The bounded 2026-10-16 check used one isolated source tree, Clang22 Release,
host512 and otherwise identical normalized CMake caches (both policy labels
`custom`, because `performance` rejects counter-on). Only FAST_STATS, CENSUS
and RA_STATS differ. Three alternating fresh-process pairs at VLEN512/BOTH
for K1 and LavaMD passed all 12 output checks using the existing campaign
inputs/oracles and process-timer boundary. Mean seconds off/on were
5.538001/5.496951 (K1) and 0.313943/0.310617 (LavaMD); paired geometric
on/off ratios were 0.992741 and 0.989465. This short shared-host sample does
not establish zero overhead or a stable counter-off advantage, and is not
pooled with the 9984 observations. Raw commands, perf events, outputs, source
pins, options and reset receipt are retained under the research artifact
`artifacts/main-review-20261015/native-20261016/counter-comparison/`;
`counter-20261016.py` reproduces this bounded design, not the full campaign.
The prepared comparison source (including dependency sources) is
`artifacts/main-review-20261015/native-20261016/counter-profiles-source.tar.gz`
in the same research storage (SHA256
`f408bf328df2463fdbde9130818cbc0eb17c4d7a3f42d3c991cf85215d0279ec`).
`SOURCE_RECEIPT.json` records both binaries/options and differences from the
timed snapshot: among shared runtime source files, only the RA counter gate
and its comments differ; the other changes are build policy and test fixtures.
This prepared archive is not a public release or a replacement timed binary.

### Local Source Integration

Local commit `8d69e49a8f8976d83f3b5d17c6000b6053889176` records the existing
production integration, not a reconstructed development history. All 23 changed
file blobs, and all 127 non-test `.cpp`/`.h`/`.S`/`.inc` production files present
in the retained timed source archive (excluding third-party sources), match that
archive byte-for-byte. This does not equate the entire commit/build environment
with the timed source archive; retain the original archive, CMake cache, compiler
commands, dependency identities and measured d252/79d0 executable/library pins.

Subsequent review maintenance adds build policy, checker/fixture repairs,
comments, portable runners and same-TU oracle-loader extraction. In particular,
`RVDBT_RA_STATS=ON` preserves the original spill/fill bookkeeping: the same
emit/store-or-fill/global-or-local counters increment at the same translation
sites, after the same QIR moves. Pre-increment versus discarded post-increment
does not change these unsigned counter effects. `OFF` removes that bookkeeping,
not the spill/fill moves. This ON-path equivalence is a source-level statement,
not a byte-identical rebuild or new full-matrix result. FAST_STATS/CENSUS remain
separate switches; the new counter-off performance policy cannot inherit d252's
completed correctness or timing identity. No new 26-round matrix was run.

Results obtained before introducing these profiles retain their original build
configuration. A mutable build directory's current CMake cache does not establish
the options used for an older executable. Bind the manifest to the measured
binary and shared libraries; disassembly can confirm specific instrumentation
when the original build record is incomplete.

Changing instrumentation requires a separate build and correctness checks before
timing. Preserve the original observations and compare matched runs; do not
relabel existing measurements as counter-free or assume the instrumentation's
cost without measuring it.

## Focused CTest Entry Point

```sh
cmake --build build/performance --target regression-static -j2
ctest --test-dir build/performance -L static --no-tests=error --output-on-failure
cmake --build build/performance --target regression-native -j2
ctest --test-dir build/performance -L native --no-tests=error --output-on-failure
```

`regression-focused` builds both groups. Test executables are excluded from the
default product build but remain individually buildable. `BUILD_TESTING=OFF`
disables registration, the Python dependency and aggregate targets, not individual
legacy executable targets. CTest does not build missing executables; missing
tests/tools, crashes and assertion failures are failures, not skips.

| Label | Existing tests | Requirements / evidence |
| --- | --- | --- |
| static | `qra_vpr_test`, `rvv_vector_run_admission_test`, `rvv_vector_run_codegen_test`, `rvv_active_chunk_plan_test`, `rvv_frame_finalizer_test`, `rvv_fp_component_run_test`, `vfma_typedchunk_route_test`, `rvv_mem_e64_route_test` | Linux x86-64; QIR/RA/emission/structural assertions, not native RVV execution. Codegen checks also use objdump. |
| native | `vchunk_dataflow_test` | Linux x86-64 with AVX-512F+BW; executes generated code under vector pressure and checks lane data |
| native | `rvv_active_chunk_census_test` | Same plus BMI2; emitted-site checks and actual execution/counter/oracle checks |

Use host128 for portable structural CI. Higher global compiler ISA settings apply
to *every* test; the wrapper checks width/FMA flags before starting it. It reads
the intersection of Linux CPU flags, which includes OS-enabled AVX state. Unknown
platform/capability is not treated as native proof. Additional manually supplied
ISA flags are outside this check and require matching hardware.

Optional missing hardware returns 77, which CTest reports as SKIP. Native tests
can contain structural portions too; a skipped executable is never native PASS.
The adapter also recognizes the selected legacy tests' explicit native-skip
messages; unconstrained tail elements and `0 skipped` summaries are not skips.
For a required native job configure the same build with:

```sh
cmake -S . -B build/performance -DRVDBT_NATIVE_REQUIRED=ON
cmake --build build/performance --target regression-focused -j2
ctest --test-dir build/performance -L focused --no-tests=error --output-on-failure
```

In required mode unavailable hardware or an internal native skip returns nonzero
failure instead of 77. The native group always contains two registered tests;
do not filter them away in a required job. CTest's ordinary skip-success is
intentional only for optional jobs. External guest suites and Python source
audits are separate layers, not covered or claimed by these ten C++ tests.

The selected tests do not depend on `RVDBT_FAST_STATS`, `RVDBT_CENSUS`, or
`RVDBT_RA_STATS` collection. Admission/codegen tests inspect the separate
translation-time `rvvrun::g_stats`; codegen and active-chunk census tests explicitly
arm separate lane/frame/QCG census mechanisms. Those mechanisms are not removed
by these three compile switches, so their assertions remain meaningful in the
performance build. In particular, `rvv_active_chunk_census_test` does not require
the vector-helper `RVDBT_CENSUS` hook.

### Jenkins Commands

Run from the repository root with `LLVM_PATH` set to the runner's LLVM prefix.
Use a separate build directory from any ongoing measurement. These commands
build the selected tests explicitly; configuring or building `elfrun` alone is
not sufficient.

```sh
git submodule update --init --recursive
cmake --preset performance -B build/ci-static -DLLVM_PATH="$LLVM_PATH"
cmake --build build/ci-static --target regression-static -j2
ctest --test-dir build/ci-static -L static --no-tests=error --output-on-failure
```

On the required AVX-512F+BW/BMI2 native runner:

```sh
git submodule update --init --recursive
cmake --preset performance -B build/ci-native -DLLVM_PATH="$LLVM_PATH" \
  -DRVDBT_NATIVE_REQUIRED=ON
cmake --build build/ci-native --target regression-focused -j2
ctest --test-dir build/ci-native -L focused --no-tests=error --output-on-failure
```

The required job includes all eight structural tests and both native tests.
Do not override the shell/CTest failure status. Optional native coverage can use
the same commands with `RVDBT_NATIVE_REQUIRED=OFF`; SKIP is not native PASS.
