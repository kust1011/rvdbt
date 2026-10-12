# Task142 final signal-copy build regression

[Result](../../../SESSION0_RESULT_142.md) · [counts](combined/SUMMARY.json) · [forms](combined/FORMS.md) · [original-predicate audit](AUDIT.json) · [partition](PARTITION.json) · [build pins](BUILD_SUCCESS.json) · [host checks](TEST_SUCCESS.json).

Task142 uses source `8111040faad84ded7f84fc5bd34d10461bfc50ca`, including reviewed signal-copy correction `ad5e3c8`. Actual build: `xbd:/home/vick/rvdbt-host512-task142-build/build/`, Clang22/LLVM22.1.6, Release, RV32/ELEN64, `RVV_HOST_CHUNK_BITS=512`. [Configuration match](CONFIGURATION_MATCH_137.json) checks 44 relevant options against Task137; [source](SOURCE_EQUALITY.json) and [dependencies](DEPENDENCY_EQUALITY.json) authenticate 297/442 files. The final executable is `e2559c5cd930e919503c79b44af219c243041e86f5b83a157bec860814e8336b`; library `79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af`.

The current portable entry uses the published public asset in
[TASK143_ARCHIVES.json](TASK143_ARCHIVES.json), compatible with the existing
`verify_rvv_artifacts.py`. The immutable manifest records its staging identity;
the matching asset is now uploaded to the validation release. The unchanged transport archive
and identity remain in [TRANSPORT.json](TRANSPORT.json). Remote retained raw is
`xbd:/home/vick/rvdbt-host512-task142/`; build/source/binaries remain in its
separate build root. Task137/138 history is immutable.

Use reviewed revision **0d253a45ddce1b45f46c843e986b29410d04786f** or a later
delivery revision containing this reader, navigation and manifest.
The existing `rvv-validation-20261012` release tag can host the new asset but its
historical source ZIP does not contain this reader. From a cloned repository:

```sh
git checkout --detach 0d253a45ddce1b45f46c843e986b29410d04786f
git merge-base --is-ancestor f50a1bf HEAD
test -f docs/rvv-validation/host512-task142/TASK143_ARCHIVES.json
```

Use Python 3.10+, assertions enabled (`PYTHONOPTIMIZE` unset; no `-O`/`-OO`).
The already published Task139 supplement, CHIPS94 and ACT db2 assets and licensed
repository Ara91 archive supply source/checker metadata; reuse existing checked
extractions if available. They are not republished in the new Task142 asset.
The following public acquisition recipe creates new directories:

```sh
mkdir downloads
curl -q -fL --retry 3 --no-netrc -o downloads/CHIPS94_ARCHIVES.json \
  https://github.com/kust1011/rvdbt/releases/download/rvv-validation-20261012/CHIPS94_ARCHIVES.json
curl -q -fL --retry 3 --no-netrc -o downloads/act-db2-task110.tar.gz \
  https://github.com/kust1011/rvdbt/releases/download/rvv-act-db2-20261012/act-db2-task110.tar.gz
curl -q -fL --retry 3 --no-netrc -o downloads/task138-inspection.tar.gz \
  https://github.com/kust1011/rvdbt/releases/download/rvv-validation-20261012/task138-inspection.tar.gz
# Final signal-copy build outputs:
curl -q -fL --retry 3 --no-netrc -o downloads/task142-inspection.tar.gz \
  https://github.com/kust1011/rvdbt/releases/download/rvv-validation-20261012/task142-inspection.tar.gz
python3 - <<'PY_DOWNLOAD'
import hashlib, json, pathlib, subprocess
manifest = pathlib.Path('downloads/CHIPS94_ARCHIVES.json')
assert hashlib.sha256(manifest.read_bytes()).hexdigest() == 'e327f0a5c043f453e1a5a32b72005c886e48573cd99326cd4059b81ddc73d8a0'
base = 'https://github.com/kust1011/rvdbt/releases/download/rvv-validation-20261012/'
for item in json.loads(manifest.read_text())['archives']:
    subprocess.run(['curl', '-q', '-fL', '--retry', '3', '--no-netrc', '-o',
                    'downloads/'+item['file'], base+item['file']], check=True)
PY_DOWNLOAD
```

Verify identities and safely extract into new roots, before going offline:

```sh
python3 scripts/verify_rvv_artifacts.py \
  --manifest docs/rvv-validation/host512-task138/TASK139_ARCHIVES.json --archive-root downloads
python3 scripts/verify_rvv_artifacts.py \
  --manifest docs/rvv-validation/host512-task142/TASK143_ARCHIVES.json --archive-root downloads
python3 - <<'PY_EXTRACT'
import hashlib, json, pathlib, tarfile
P = pathlib.Path
chips = json.loads(P('downloads/CHIPS94_ARCHIVES.json').read_text())['archives']
act = dict(file='act-db2-task110.tar.gz', bytes=445180486,
           sha256='4597c521427b2cd9e6bfda04a5a717e3e2a50a17854e307144b2c190e24526bc')
current = json.loads(P('docs/rvv-validation/host512-task138/TASK139_ARCHIVES.json').read_text())['artifacts'][0]
raw142 = json.loads(P('docs/rvv-validation/host512-task142/TASK143_ARCHIVES.json').read_text())['artifacts'][0]
ara = json.loads(P('docs/rvv-validation/ara-review-task91/MANIFEST.json').read_text())
ara['file'] = ara['archive']
for root, items, archives in [('inspection/chips', chips, P('downloads')),
                             ('inspection/act', [act], P('downloads')),
                             ('inspection/current', [current], P('downloads')),
                             ('inspection/task142-raw', [raw142], P('downloads')),
                             ('inspection/ara', [ara], P('docs/rvv-validation/ara-review-task91'))]:
    dest = P(root); dest.mkdir(parents=True, exist_ok=False); seen = set()
    for item in items:
        archive = archives/item['file']
        assert archive.stat().st_size == item['bytes']
        h = hashlib.sha256()
        with archive.open('rb') as f:
            for block in iter(lambda: f.read(1024*1024), b''): h.update(block)
        assert h.hexdigest() == item['sha256']
        with tarfile.open(archive) as tf:
            for member in tf:
                name = P(member.name)
                assert member.isfile() and not name.is_absolute() and '..' not in name.parts
                assert member.name not in seen; seen.add(member.name)
                tf.extract(member, dest)
PY_EXTRACT
```

Select an existing form across suites offline with the **new raw root**:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv_scope_report.py \
  --host512-corpus docs/rvv-validation/host512-task142/combined/navigation.json.gz \
  --host512-raw inspection/task142-raw --host512-evidence inspection/current \
  --chips-package inspection/chips --act-db2-package inspection/act \
  --ara-package inspection/ara --form vle32.v --arm B \
  --output inspection/select142-vle32
```

This selects ten existing records across CHIPS/ACT/Ara and retains both original
ACT reference blockers separately. Each output directory must be new. Missing
Task142 receipts fail before writing a selection; Task139 raw is never a current
fallback. Omitting the raw option produces `NOT_CHECKED`, not current credit.
Only `inspection/task142-raw` receives current-build credit; `inspection/current`
supplies unchanged source/checker metadata. `record.json` links literal source,
assertion, original checker, actual command, build pins, result and raw files.
The reader rechecks CHIPS exit/stdout, original ACT execute109 predicates and
unchanged Ara observers without executing guests or reference engines. Use
`--suite chips|act|ara`, `--case`, `--arm`, or another `--form` to narrow records.

For an optional complete retained-receipt inspection using the existing reader
(no new guest execution), replace the selector arguments with
`--host512-corpus docs/rvv-validation --host512-task142-build`, retaining all
explicit roots and choosing a new output directory. This is not required for the
selected-form handoff. Full output also includes `PORTABLE_SOURCES.json.gz`.
Historical nested results keep their original build attribution.

[Membership/license inspection](TASK143_MEMBERSHIP.json) records the derived
asset: all original streams/observers/text dumps, queue/build/configuration
receipts and five documented repository-owned orchestration scripts are retained;
126 `build-evidence/receipts/*/emit-*.bin` executable x86 code dumps are excluded.
`LICENSE.txt` and `NOTICE.md` are added. No executable binaries, libraries,
private inputs, undocumented sources, toolchain, work/cache or supplementary
source packages are included. The original `RAW_MANIFEST.json.gz` is retained
unchanged and describes the original transport, including the 126 omissions;
it is not an inventory of the public payload. Archive identity is verified using
the new public manifest. Original corpus receipt hashes/expected values are
unchanged. Original upstream licenses remain in the required source packages;
there is no collective relicensing. Frozen absolute paths are provenance.

External checks, local engineering regressions and configuration evidence have
different meanings. [TEST_SUCCESS.json](TEST_SUCCESS.json) records final-build
host interface/FRM/MMU, codegen/admission and normal memory checks; these add no
external instruction credit. The signal interface test has `guest_calls=0`.
[CONFIGURATION_DURING.json](CONFIGURATION_DURING.json) and
[CONFIGURATION_AFTER.json](CONFIGURATION_AFTER.json) authenticate actual cache
and compile settings. Guest VLEN comes from commands; ACT/Ara chunk width from
stderr; unprinted CHIPS width and SEW/LMUL/VL/mask/tail/vstart tuples remain
UNKNOWN. Source literals are source evidence, not observed runtime tuples.

The same-build queue is exactly 11,532 CHIPS positives plus 212 controls, 7,668 ACT, 1,888 Ara whole-file and 16 TEST_CASE1/2-only scoped MAC calls. Three exact pilots plus 21,313 disjoint remaining calls receive credit once. Controls earn no positive form credit; scoped MAC keeps `whole_file_pass=false` and original failing TEST_CASE3/4 output. The [two original ACT reference blockers](ORIGINAL_ACT_REFERENCE_BLOCKERS.json) remain outside the accepted queue and accessible through navigation; they receive zero fresh DUT/reference calls. Prior-build execution credit is zero. Program acceptance and aggregate counters are not per-target native admission or complete architectural-state capture.

**Guest restart is NOT VERIFIED.** No guest handler return, mapping repair, same-PC retry/P4-04 equivalent, new reference, performance campaign, LLVM expansion, publication or issue closure occurred. The launcher owns the completion signal.
