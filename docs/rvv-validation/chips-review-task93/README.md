# Retained primary CHIPS inspection, Task93

This is delivery gate5 packaging of the existing sealed47-batch primary scope. It performs no guest runs, expected-value generation or candidate builds. Canonical bindings come from xbd `/home/vick/rvv-task90/task90`; the existing local Task90 summary remains `artifacts/external_suite_coverage_20261007/task90` in the author evidence tree. Main owns the existing author guide, current-scope prose, thesis, PDF and email.

`clean961` means recorded executable SHA256 `6fda0f9ab06c2c824b5301d1f302b76799842981b00a88fffa85fe43f1dbd84f`. `historical2af5` means `2af5d3e6b0d11564c1fe93cd86b4b7ec5467f8249a785b3ee4c350b440ad8de9`. Shared library identity is `1773ca2bf867b0d3bdd76f1b60b168cbeda6d620a71ebd0ae9653d6da6feea6d`. The package physically separates the candidate receipts. Historical registered-corpus.tar.gz is not clean961 proof.

The 94 current CHIPS94 archives are published in the [GitHub Release](https://github.com/kust1011/rvdbt/releases/tag/rvv-validation-20261012), targeting `49c44174fe95b68d85fcecf01b2a3bf8731e74d3`. The frozen upload inventory is [CHIPS94_ARCHIVES.json](https://github.com/kust1011/rvdbt/releases/download/rvv-validation-20261012/CHIPS94_ARCHIVES.json); [Task101 receipt](../release-task101/RECEIPT.json) records public downloads and offline checks. Archives and scratch remain on xbd `/home/vick/rvv-task93`. `ARCHIVES.json` records exact sizes and hashes. Named batch archives share one extraction root with core; a large batch is divided by named original form family, keeping its stages, capture patches, logs and original histories together. Oversized measurement archives remain in `size-preflight/` and are not delivery files.

## Reader workflow

Run these assertion-dependent tools and the extraction snippet with normal Python: do not use `python -O`, `python -OO`, or set `PYTHONOPTIMIZE`. Optimized Python removes acceptance assertions.

Download the frozen manifest and its 94 named archives using public URLs:

```sh
mkdir chips-archives
cd chips-archives
curl -fL -o ARCHIVES.json https://github.com/kust1011/rvdbt/releases/download/rvv-validation-20261012/CHIPS94_ARCHIVES.json
python3 - <<'DOWNLOAD'
import json, subprocess
base = 'https://github.com/kust1011/rvdbt/releases/download/rvv-validation-20261012/'
for item in json.load(open('ARCHIVES.json'))['archives']:
    subprocess.run(['curl', '-fL', '--retry', '3', '-o', item['file'], base + item['file']], check=True)
DOWNLOAD
cd ..
```

Extract each listed archive into a new directory. No original author path or remote mount is needed to inspect the extracted evidence.

```sh
mkdir inspection
python3 - chips-archives inspection <<'PY'
import hashlib, json, pathlib, sys, tarfile
archives, destination = map(pathlib.Path, sys.argv[1:])
for item in json.loads((archives / 'ARCHIVES.json').read_text())['archives']:
    p = archives / item['file']
    assert hashlib.sha256(p.read_bytes()).hexdigest() == item['sha256']
    with tarfile.open(p) as tf:
        for m in tf.getmembers():
            assert m.isfile() and not pathlib.Path(m.name).is_absolute()
            assert '..' not in pathlib.Path(m.name).parts
        tf.extractall(destination)
PY
cd inspection
PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_rvv_chips_inspection.py .
PYTHONDONTWRITEBYTECODE=1 python3 tools/check_rvv_chips_rejection.py . ../chips-rejection
python3 tools/verify_rvv_chips_inspection.py . --form vadc.vim \
  --candidate clean961 --vlen 128 --arm B --batch carrymove128 --case vadc_vim-0 --contexts
```

Each selected row identifies the canonical ledger row, candidate, exact ELF, flags/VLEN/arm, source, original assertion selector and physical receipt. Follow `SOURCE_CHAIN.json` for the original build-command file and ordinal, source/linked-ELF hash manifest, stage1 and captured patch. Open the full stage2 `.S` for unchanged TEST_CASE expected words, inputs, target bodies, stores and CSR checks. Open its stage1, captured patch and generation/oracle/merger commands/logs to inspect how the original expected values arose. `tools/runner.original.py` is the exact retained runner; the verifier calls its original `classify` predicate on recorded stdout and return code.

`SOURCE_GEOMETRY.csv` supplies exact source, line, requested VL, SEW, LMUL, mask and source hash. Its passing-file configurations are source context, not runtime branch counters or a Cartesian product. `LITERAL_CONFIG_CONTEXTS.json` supplies exact source lines and setup/assertion windows for the seven configuration files and twelve conversion files outside that historical CSV. The three vset forms retain their expected CSR constants and rd relations directly in original source/adaptation records. Canonical primary bindings intentionally retain UNKNOWN fields. Program-level acceptance does not assert individual opcode execution/influence or independent M1/M2 admission.

The configuration selector joins each source file to its retained geometry rows, not a multiplication of separate field sets. `--contexts` prints those rows with their original line numbers; the 19 files without historical geometry rows return exact literal source contexts, including register-valued AVL/vtype setup. No canonical UNKNOWN field is filled with an inferred runtime value. Original fail256 and wrong-answer controls remain separate from instruction coverage. The original allocation failures and eight unsafe original store dispositions are retained; repaired storage inputs have distinct sources/hashes. CHIPS expected values/checker limitations, ELEN64 generator adaptations and locally computed configuration constants remain disclosed. Task47 supplements and Task54 new/profile outputs are outside this primary package; their receipts are not used to replace primary witnesses.

## Licenses and excluded dependencies

Pinned CHIPS revision is `f76bff121dce91b6b23e1d37be77a5e44af914c3` (Apache2); env submodule is `81721c126d7dd7335829948b4a19070546e465d6` (BSD notices retained). Upstream tracked source, original headers and licenses are preserved. Local package/inspection tools retain repository MIT. CHIPS derivatives, including generator patches, retain their source license; the package does not collectively relicense components. `LICENSE_AUDIT.json` identifies notices and the credential-pattern scan. The TestFloat3 origin license is also retained as a notice; its code is fetched with the pinned checkout. The CHIPS env/ps header identifies its gem5 asmtest basis; the [original asmtest BSD notice](https://gem5.googlesource.com/public/gem5-resources/+/refs/heads/develop/src/asmtest/LICENSE) is included separately in licenses/GEM5_ASMTEST_BSD.txt. Restricted/unrelated third-party fixtures are excluded.

ELFs, toolchains, libraries, Spike/pspike/merger executables, TestFloat3 source, caches, TB dumps and Git stores are excluded. Inspection does not require them. Fetch/build instructions for optional reconstruction:

```sh
git clone https://github.com/chipsalliance/riscv-vector-tests.git deps/chips
git -C deps/chips checkout --detach f76bff121dce91b6b23e1d37be77a5e44af914c3
git -C deps/chips submodule update --init --recursive
# This pinned checkout contains the required TestFloat3 source.
(cd deps/chips && go build -o build/generator && go build -o build/merger merger/merger.go)
git clone https://github.com/riscv-software-src/riscv-isa-sim.git deps/spike
git -C deps/spike checkout --detach 20feb9c2bf2a7deab964d8190b0cbd4b4131bec3
mkdir deps/spike/build
(cd deps/spike/build && ../configure --prefix="$PWD/../install" && make && make install)
```

`records/historical/MANIFEST.json`, batch build_commands.json and generator_metadata.json record original tools, hashes and full commands. For ELEN64 generation, inspect/apply `sources/chips/elen64_generator/independent-elen.patch` and the separate adapter patch to an isolated pinned checkout. Generation is unnecessary for inspection: stage1 data, captured answers and stage2 are already retained. Do not regenerate expected values to verify this package.

For an optional source-only rebuild, install clang20/lld, then use the shipped existing builder with a fetched pinned checkout and the source SHA256 from navigation:

```sh
python3 tools/build_rvv_chips.py --upstream deps/chips \
  --source sources/chips/carrymove128/stage2/vadc_vim-0.S \
  --source-sha256 SOURCE_SHA256_FROM_NAVIGATION --output rebuilt-case
```

This build is not a new oracle check; no byte-identical rebuilding promise is made across arbitrary tool versions. No reexecution instructions upgrade the retained result scope.
