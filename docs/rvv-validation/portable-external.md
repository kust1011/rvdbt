# Public RVV build, run and check

This is the maintained, host-independent correctness entry. It runs **two
fixtures**, not the historical 595-form matrix: the complete adapted Ara
`vredsum.c` (20 assertions/200 elements, VLEN1024) and a retained 16-instruction
RVVTS API-derived sequence (VLEN2048). Both use the same newly built ELF in
Spike+PK and B/M1/M2/BOTH. No SSH, private paths or task-local runner rewriting
is required. See the [support/evidence guide](../rvv-author-guide.md) for limits.

## Build and dependencies

Use Linux x86-64 with AVX-512 support for the host512 emitted code (including
the required AVX-512 subsets), LLVM/Clang/LLD 22, CMake, Ninja, Boost/OpenSSL
development files and Python 3 with numpy/jsonpickle/mergedeep. Guest linking
needs RISC-V bare-metal GCC's RV32 ilp32d libgcc multilib. Spike also needs dtc
and Boost system/regex; PK needs target newlib headers. Toolchains are not bundled.
Do not execute host512 code on an incompatible CPU.

From the repository root, choose your own toolchain and build location:

```sh
BUILD="$PWD/build-rvv-check"
CC=clang-22
CXX=clang++-22
LLVM_ROOT=/usr/lib/llvm-22
git submodule update --init dbt/third_party/asmjit dbt/third_party/elfio
cmake -S . -B "$BUILD" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DRVDBT_BUILD_PROFILE=diagnostic \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DLLVM_PATH="$LLVM_ROOT" -DRVV_HOST_CHUNK_BITS=512 \
  -DRVDBT_FP_CONTRACT_OFF=ON -DRVDBT_FROUND_DIAG_NOP=OFF \
  -DRVDBT_FAST_STATS=ON -DRVDBT_CENSUS=ON -DRVDBT_RA_STATS=ON
cmake --build "$BUILD" --target elfrun -j2
```

This is an **instrumented correctness/admission build**, not a formal performance
configuration. Keep `CMakeCache.txt`, `build-profile.txt` and
`compile_commands.json` with your run. Release alone does not select the
performance policy. See the [configuration boundaries](../rvv-author-guide.md#configuration-and-ownership-boundaries).

Select an unused dependency directory:

```sh
DEPS=/absolute/path/to/new-dependencies
python3 scripts/fetch_rvv_external.py --output "$DEPS"
```

[sources.lock.json](../../scripts/rvv/sources.lock.json) separates pinned source
URLs/revisions/licenses from the runner. Fetch Spike and PK using their
`spike_replay` and `pk_replay` entries:
`git clone URL SOURCE`, then `git -C SOURCE checkout --detach REVISION`.
Build Spike in a new build directory with
`../configure --prefix=INSTALL`, `make -j2`, `make install`.
Build PK separately with
`../configure --host=riscv64-unknown-elf --with-arch=rv32gc --with-abi=ilp32d`,
then `make -j2`. Supply appropriate configure/compiler paths for your toolchain.
Without target libc, PK can build freestanding using `LDFLAGS=-nostdlib` and
`make CFLAGS=-I/path/to/newlib/headers`. Non-system shared libraries may require
`LD_LIBRARY_PATH`; the runner prepends the selected DUT library directory.

The bundled [Ara fixture](../../scripts/rvv/fixtures/ara-vredsum/README.md) and
[RVVTS fixture](../../scripts/rvv/fixtures/rvvts-20261089/README.md) retain source,
licenses, inputs and wrapper adaptations. Fixture SHA256s are in
[external-sha256.json](../../scripts/rvv/fixtures/external-sha256.json).
The fetcher verifies retained Ara originals; the runner verifies bundled hashes
and the pinned clean RVVTS checkout. It records selected executable/library
hashes, but does not certify the source provenance of user-supplied Spike/PK
binaries: build those from the lock and retain build records.

## Run and check

Select absolute paths. `OUT` and `CACHE` must be unused and non-overlapping.
The runner isolates each fixture/arm's cache; it does not consume an old compiled
DUT cache. Omit `--cache-dir` to use `OUT/work`.

```sh
DUT="$BUILD/bin/elfrun"
DUT_LIB="$BUILD/lib"
SPIKE=/absolute/path/to/spike-install/bin/spike
PK=/absolute/path/to/pk-build/pk
GUEST_CC=riscv64-unknown-elf-gcc
OUT=/absolute/path/to/new-replay
CACHE=/absolute/path/to/new-replay-scratch
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_rvv_external.py
python3 scripts/run_rvv_external.py \
  --rvvts "$DEPS/rvvts" --engine "$DUT" --library-dir "$DUT_LIB" \
  --spike "$SPIKE" --pk "$PK" \
  --libgcc "$("$GUEST_CC" -march=rv32g -mabi=ilp32d -print-libgcc-file-name)" \
  --compiler "$CC" --llc "$LLVM_ROOT/bin/llc" \
  --cache-dir "$CACHE" --output "$OUT"
```

Acceptance is inline: missing/changed fixtures, build/execution failure, timeout,
incomplete output or a comparison mismatch returns nonzero. Inspect
`summary.json` only after exit zero. A default completed replay records 10 new
calls: two Spike references and eight DUT executions. `identity.json`,
`build-logs/`, `guests/` and `runs/` retain commands, hashes, raw outputs and
checker outcomes. The fixed flags manifest is
[external-flags.json](../../scripts/rvv/fixtures/external-flags.json);
Ara overrides VLEN to 1024. This is not an arbitrary-flags test interface.

Check observer transport and optimized-path admission separately:

```sh
RVVTS_SOURCE="$DEPS/rvvts" RVVTS_PACKET="$OUT/runs/rvvts/Spike/stdout" \
  python3 -m unittest discover -s scripts -p test_rvv_external_packet.py
python3 scripts/verify_rvv_external_elf.py --elf "$OUT/guests/rvvts.elf" \
  --nm "$LLVM_ROOT/bin/llvm-nm" --output "$OUT/elf-verification.json"
python3 scripts/audit_rvv_external_admission.py --results "$OUT" --source .
```

Packet controls need the real pinned API and recorded packet; without them they
SKIP, not PASS. Ara compares retained upstream literals/observations; RVVTS
compares its full declared packet against the new Spike output using the original
API comparator. GPR/PC/memory final state and instruction-intermediate flags
are outside that packet. Ara retains source bounds/macro limitations described
in its fixture reader.

## Fresh execution versus retained evidence

### Retained Directed Corpus

For the existing all-form directed index, `run_rvv_retained.py` reuses
`rvv_verify` selectors and each entry's original hash-pinned packet predicates. Supply the
retained input tree and independently retained reference tree separately, each
with paths relative to the index's original root. They may point to the same
read-only extraction when the package contains both. No SSH, source rewriting,
golden generation or immutable historical DUT pin is used:

```sh
python3 scripts/run_rvv_retained.py preflight \
  --raw-root "$INPUTS" --reference-root "$REFERENCES"
python3 scripts/run_rvv_retained.py run --entry b145-000 --max-units 1 \
  --raw-root "$INPUTS" --reference-root "$REFERENCES" \
  --engine "$DUT" --library-dir "$DUT_LIB" --output "$OUT" --cache-dir "$CACHE"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_rvv_retained.py
```

Preflight inventories every indexed entry by default; a missing manifest, ELF,
reference or command fails. It is not execution or an all-raw hash audit. Run
defaults to one unit/four arms, in one entry per process to isolate family adapters.
`--max-units` explicitly raises that bound. Fresh DUT packets must pass both the
existing specification predicate and comparison to the hash-checked retained
reference; excluded rows receive no credit. New output/cache roots are mandatory
unless explicitly resuming. `--resume` rechecks saved captures, including an
execution that lacks its check receipt; it never launches a captured call again.
An incomplete launch without an execution receipt blocks for diagnosis.
Each unit/arm has a distinct cache, removed only after successful checks; raw
stdout/stderr are streamed to lossless gzip, including failures. Historical TB
dump options are omitted, without changing semantic flags. A 10GiB reserve plus
the next capture estimate is enforced. Sail references use the original retained
four-byte signature decoder, with stdout hash and decoded-packet identity checks;
they are not compared to the hash of a different transport artifact.
Receipts record the new DUT/library and actual checker-module identities, not
historical PASS credit. The summary says `PASS_SELECTED_UNITS`, never full595.
No compiler/reference tools are needed to execute already-built input ELFs.
The input tree must also contain the entry's original tool snapshot and pinned
data at their relocated paths. Each entry runs in a fresh process; all declared
tool/data pins are verified before import. `checker-bindings.json` records
resolved module paths and actual/expected hashes, rejects transitive modules
outside the snapshot pins, and includes the FP estimate-table data pins.

For an explicitly authorized ordinary campaign, independent entry processes
isolate family adapters; controller/entry locks prevent duplicate owners:

```sh
nice -n 10 python3 scripts/run_rvv_retained.py campaign --all-units --jobs 4 \
  --raw-root "$INPUTS" --reference-root "$REFERENCES" \
  --engine "$DUT" --library-dir "$DUT_LIB" --output "$OUT" --cache-dir "$CACHE" --resume
```

The current index declares 95,242 ordinary units, 380,968 four-arm calls and
12,069,048 selected case/arm checks. `campaign.json` derives these counts from
the manifests; `STATUS.json` reports checked progress, not presumed completion.
Creating `OUT/STOP_NEW_UNITS` drains before the next unit without killing an
active guest. A failed entry creates that marker automatically; diagnose and
archive it before an explicit resume. The 595 forms are finite selected rows,
not all combinations of SEW/LMUL/VLEN/masks or complete ISA semantics.

After completion, recount the actual unique unit/arm receipts against the
original manifests, output existence, checker pins and DUT/library identity:

```sh
python3 scripts/run_rvv_retained.py audit \
  --raw-root "$INPUTS" --reference-root "$REFERENCES" \
  --engine "$DUT" --library-dir "$DUT_LIB" --output "$OUT"
```

`AUDIT.json` reports forms, units, calls, selected checks and actual method
options; `AUDIT_PER_FORM.csv` gives the directly recounted per-form result and
four-arm call/check counts. Calls containing several forms appear in each
applicable row, so per-form calls/units are not additive campaign totals.
This performs no guest calls or full raw rehash: it relies on the
original per-call checks/hash receipts and verifies output presence. Correctness
diagnostic options are recorded, not equated with formal timing options.

The 2026-10-16 bounded checks ran the measured d252/79d0 pair on one unit each
from Task155, Task171 and Task176, covering compressed checks, legacy ledgers
and the delivered FP unary predicate. All four arms passed for each. Resuming
the FP unary capture made zero new DUT calls and rechecked four captures.
The thirteen adapter unit tests check tooling contracts, including receipt
recount rejection controls, not ISA execution.

The real-packet rejection script is a CLI, **not** a unittest discovery test:

```sh
python3 scripts/test_rvv_verify.py --checkout "$PWD" \
  --raw "$INPUTS/rvv-directed-task145/corpus" --output "$CONTROLS_JSON"
```

Its separately run receipt accepted 17 original packets and rejected missing,
truncated, nonzero-exit, timeout and corrupted-CSR outputs. Discovery success
alone does not establish these controls, nor does this offline check run a DUT.

**The complete input/reference bundle is not yet publicly packaged.**
The 102-entry/595-form index alone is insufficient. A private selected bundle
has now been prepared (95,242 units, original checker pins and retained reference
transport), and the [measured d252 replay](delivery-task182/README.md#measured-d252-replay)
completed with an actual full key/receipt recount. The bundle's separate one-unit
relocation pilot made four calls / 268 checks outside the original host paths;
it is not a second full native replay. Publication still needs mixed-license and
generated-data permission clearance, with full metadata/checksum verification.
This adapter covers ordinary directed units,
not the historical focused denials, external suites or sequence supplements.

### Execution Modes

- Default replay: new guest builds, fresh Spike references and fresh DUT runs;
  frozen input/body and upstream expected literals, no new input generation.
- Resume: add `--reuse-successful-from /absolute/path/to/prior-replay`, still
  choosing new output/cache roots. Matching successful DUT **and reference**
  receipts may be reused; it is not necessarily a fresh-DUT run. Identities,
  guest ELFs, raw hashes and execution options must match; changed receipts fail.
  Each reused output is checked again. Read `new_calls` and `reused_receipts`.
- Offline package inspection: reruns predicates on saved outputs, no guest runs.
  See [original-case navigation](all-form-records/README.md).
- [Frozen 595-form replay](final-task197/README.md): fresh DUT executions at
  that historical build, retained ELFs/oracles and no fresh reference execution.
  Full raw/runner archives are not publicly downloadable.

Archiving a new run should include the lock, fixture licenses/hashes, effective
build options, tools/provenance, guest ELFs and complete raw/checker receipts.
Bulky distributable data belongs in a licensed archive with a checksum and
retrieval/rebuild instructions. No such public archive is currently available
for the full latest matrix. Two fixture passes cannot fill that gap or establish
general fault/retry, signal delivery or complete ISA coverage.
