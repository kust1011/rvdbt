# Final retained corpus on the Task137 executable

[Task138 report](../../../SESSION0_RESULT_138.md) · [suite/method summary](combined/SUMMARY.md) · [counts](combined/SUMMARY.json) · [forms](combined/FORMS.md) · [same-build partition](PARTITION.json) · [original-predicate audit](AUDIT.json)

Every one of the 21,316 retained CHIPS/ACT/Ara calls has a fresh Task138 receipt on `/home/vick/rvdbt-goldens-task137/current/build/bin/elfrun`, SHA256 `da5209ae488403f3eb2a15af8bf0376df4844eefb46b9525c8a0834f8e3f4d5e`, with library `79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af`. Three unchanged original pilots plus 21,313 disjoint original calls form the full same-build queue. Prior-build execution credit is zero.

The existing Task128/129 reporter joins current authenticated receipts to unchanged original source/checker bindings. Historical nested bindings retain their historical results/configuration, and Task128 target-code observations remain historical. The final navigation gives actual Task138 commands, results, streams and observers separately. CHIPS controls earn no positive form credit. Ara TEST_CASE1/2 scoped MAC results have `whole_file_pass=false`; original failing TEST_CASE3/4 remain visible in stdout/observer data. ACT's two original reference blockers retain their original reference receipts and are outside the accepted queue.

Portable inspection uses a downloaded checkout, the published CHIPS94 and ACT db2
packages, the repository's licensed Ara91 archive, and the Task139 supplement.
The supplement is [published in the validation release](https://github.com/kust1011/rvdbt/releases/download/rvv-validation-20261012/task138-inspection.tar.gz).
Its exact identity is in [TASK139_ARCHIVES.json](TASK139_ARCHIVES.json); that
immutable staging manifest retains its prepublication status. The original
[Task139 report](../../../SESSION0_RESULT_139.md) records the isolated checks.
No author directory or xbd mount is used by the following checks.

Use [repository revision dc7aeed](https://github.com/kust1011/rvdbt/tree/dc7aeedaff8a197b239ef49c0bf7e5db3563b173)
or a later delivery revision containing this reader and its documentation.
The existing validation release tag targets historical 49c44174; adding assets
does not update that tag's source ZIP. Check `python3 scripts/rvv_scope_report.py
--help` for `--host512-raw` and `--host512-evidence` before inspection.

Use Python 3.10+ with assertions enabled (`PYTHONOPTIMIZE` unset, no `-O`/`-OO`).
From the downloaded repository root, acquire the frozen assets into `downloads/`:

```sh
mkdir downloads
curl -q -fL --retry 3 --no-netrc -o downloads/CHIPS94_ARCHIVES.json \
  https://github.com/kust1011/rvdbt/releases/download/rvv-validation-20261012/CHIPS94_ARCHIVES.json
curl -q -fL --retry 3 --no-netrc -o downloads/act-db2-task110.tar.gz \
  https://github.com/kust1011/rvdbt/releases/download/rvv-act-db2-20261012/act-db2-task110.tar.gz
# Final current outputs and missing reader dependencies:
curl -q -fL --retry 3 --no-netrc -o downloads/task138-inspection.tar.gz \
  https://github.com/kust1011/rvdbt/releases/download/rvv-validation-20261012/task138-inspection.tar.gz
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
python3 - <<'PY_EXTRACT'
import hashlib, json, pathlib, tarfile
P = pathlib.Path
chips = json.loads(P('downloads/CHIPS94_ARCHIVES.json').read_text())['archives']
act = dict(file='act-db2-task110.tar.gz', bytes=445180486,
           sha256='4597c521427b2cd9e6bfda04a5a717e3e2a50a17854e307144b2c190e24526bc')
current = json.loads(P('docs/rvv-validation/host512-task138/TASK139_ARCHIVES.json').read_text())['artifacts'][0]
ara = json.loads(P('docs/rvv-validation/ara-review-task91/MANIFEST.json').read_text())
ara['file'] = ara['archive']
for root, items, archives in [('inspection/chips', chips, P('downloads')),
                             ('inspection/act', [act], P('downloads')),
                             ('inspection/current', [current], P('downloads')),
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

Run the existing reader offline with explicit roots. This audits all 21,316
current receipts, original-call equality, binary/library pins, normalized flags,
current streams/results/observer hashes, CHIPS exit/stdout acceptance, the
original execute109 ACT predicate and unchanged Ara observers. It resolves every
original bound source/checker dependency through existing `FILES.json`,
`PATHS.json` and `LEGAL_RESTORATIONS.json` schemas. `PORTABLE_SOURCES.json.gz`
contains these joins; `navigation.json.gz` retains the original fields and adds
current local paths. No guest, compiler or reference engine is invoked.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv_scope_report.py \
  --host512-corpus docs/rvv-validation --host512-task138-build \
  --host512-raw inspection/current/raw --host512-evidence inspection/current \
  --chips-package inspection/chips --act-db2-package inspection/act \
  --ara-package inspection/ara --output inspection/audit138
```

Select exact form/suite/case/arm records using the same reader. Each output
folder must be new. These examples cover arithmetic, memory, FP, masks and
configuration; omit `--suite` to inspect all existing suite bindings.

```sh
for form in vadd.vv vle32.v vfadd.vv vmand.mm vsetvli; do
  PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv_scope_report.py \
    --host512-corpus docs/rvv-validation/host512-task138/combined/navigation.json.gz \
    --host512-raw inspection/current/raw --host512-evidence inspection/current \
    --chips-package inspection/chips --act-db2-package inspection/act \
    --ara-package inspection/ara --form "$form" --arm B --output "inspection/select-$form"
done
```

Open each `record.json`: `records` contains the original call, literal
source/checker selectors, actual current command, build pins, result and observed
configuration; `portable_sources.records` gives verified local file paths and
any legal-prefix length. For CHIPS, read the selected full stage2 `.S`, its
`TEST_CASE` windows, package `SOURCE_CHAIN.json` row (`batch`, `case`), stage1,
answer-capture patch and original generator/merger logs. The retained original
`tools/runner.original.py` checks exit/stdout; source geometry/literal contexts
are separate from runtime observations. For ACT, follow the original `.S`,
`signature.h`, frozen `.results` and package case `ORACLE.json`, `.sig`, original
`sig_modify.py`, and Sail/compile/QEMU logs. Current literal checker sites and
frozen word metadata are in `inspection/current/metadata/act/`; the one
Task104 `Vls32-vluxei32.v` source/capture/result/log chain is under
`inspection/current/metadata/task104/`. For Ara, follow the verified original
source, compiled adapter and runner, then the existing Ara `BINDINGS.json` and
`PATHS.json`; earlier missing sources/observers are in the supplement. The
current stdout and `observer.json` expose original assertion completion and
scoped failures. Historical nested results never earn Task138 credit.

Inspect `CONFIGURATION_DURING.json`, `CONFIGURATION_AFTER.json`, actual
`CMakeCache.txt` and `compile_commands.json` under `inspection/current/raw/` for
Release, host512 and production/executable flags. Guest VLEN is in each command;
ACT/Ara printed chunk width is in stderr. CHIPS printed width and missing
SEW/LMUL/VL/mask/tail/vstart runtime tuples remain UNKNOWN. Source-only entries
and the two original ACT reference blockers remain outside the accepted queue.
A selector without `--host512-raw` explicitly reports `NOT_CHECKED`.

The supplement preserves every authenticated direct current receipt file,
including the retained TB text, and necessary reader metadata. It excludes
ELFs, libraries, toolchains, work/cache, Git stores, restricted generator
vectors and private inputs. `NOTICE.md`, `licenses/`, `PROVENANCE.json` and
`LEGAL_RESTORATIONS.json` distinguish repository MIT records, Ara SHL-0.51
source/derivatives, and ACT's original code/data licenses. Removing a recorded
notice prefix recovers the exact historical compiled source hash; no test answer
is edited. Public source archives are reused rather than duplicated wholesale.

This is portable inspection of frozen evidence. Optional reconstruction depends
on pinned generator, merger, TestFloat, toolchain, Sail/QEMU/Spike and adapter
versions described in the individual package guides and original command logs.
There is no single-command promise to rebuild every historical oracle or obtain
byte-identical binaries with arbitrary tools. The original xbd collector remains
a live-author audit script, not the portable reader entry point.

Guest VLEN and flags are actual command settings. Printed `RVV_STATS` chunk width is observed separately. Source SEW/LMUL/requested VL/mask/tail/vstart literals remain source claims; unprinted runtime tuples remain UNKNOWN. Program acceptance and aggregate route counters are not full-state captures or a current per-target native census. Remaining ISA/restart and native unexpected-fault/mapping/concurrency limits are unchanged. No guest handler return, mapping repair, same-PC retry, P4-04/equivalent, fault/restart batch, performance campaign, optional-feature expansion, push or closure occurred. The launcher signals main.
