# ACT db2 inspection and replay — Task110

This adds the accepted Task109 execution at ACT
`db2b9fd7aa71a6e669417f711379988541f1464c` to the existing delivery.
The [c3e primary reader](../act-primary-task99/README.md) and its original records
remain separate. [RESULT_INDEX.csv](RESULT_INDEX.csv) selects a concrete source,
configuration, original checker, expected signature and raw receipt in the db2
package; [ACCOUNTING.json](ACCOUNTING.json) records the exact units.

2,147 marked instruction/SEW inputs produced 1,919 files; 228 inputs were profile
excluded (128 ei64, 100 optional FP16/Zvfh). One file, `Vls32-vluxei32.v`, is the
exact Task104 prior join. Task109 executed 1,918 new files: 1,916 full-file PASS
on B/M1/M2/Both (7,664 DUT calls), two whole-file QEMU platform blockers and zero
unattempted outputs. Original Sail captures: 1,918 PASS; same-ELF QEMU: 1,916 PASS,
two SIGILL. Two additional diagnostic QEMU calls also failed. Thus 11,500 primary
guest calls and 11,502 including diagnostics were archived. Task110 adds zero
guest calls. Task104's six calls are not added to these totals.

36 sources match c3e bytes; 637 additional outputs match after the recorded
comment/whitespace/equivalent preprocessor guard normalization; 1,246 still differ
(including Task104). These are exact output comparisons, not new semantic
coverage. The original `EXACT_QUEUE.json`, `CONCRETE_DIFFERENCES.json`, modular
seeds, testplans and complete GNU source diffs are in `records/`.
The accepted form union stays **595**. The retained clean961 executable/library
and tool identities are in `records/LAUNCH_REGISTRATION.json`; these receipts do
not transfer to newer builds.

The inspection archive is staged at
`xbd:/home/vick/rvv-task110/act-db2-task110.tar.gz`. It has no new public Release
URL. [ARCHIVE.json](ARCHIVE.json) gives its measured size and SHA256. Obtain it
from that host, then inspect on any Python 3.9+ machine:

```sh
scp xbd:/home/vick/rvv-task110/act-db2-task110.tar.gz .
mkdir act-db2-inspection
tar xzf act-db2-task110.tar.gz -C act-db2-inspection
PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify_rvv_act_db2.py act-db2-inspection
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_rvv_act_db2.py act-db2-inspection
python3 scripts/verify_rvv_act_db2.py act-db2-inspection --case Vls8-vluxei8.v
```

The index has all 1,919 outputs, including a distinct Task104 prior row, with
source/checker/config hashes, geometry, original testplan line and c3e comparison
class. `CASES.json` contains only the 1,918 Task109 results.

The same scripts are shipped in `tools/` inside the archive, so a repository
checkout is optional. `-O`, `-OO` and optimized `PYTHONOPTIMIZE` are explicitly
rejected by the verification entry point. The focused controls reject missing
raw, nonzero/timeout exit, missing/duplicate PASS summary, FAILED text and missing
Sail signature. [OFFLINE_ACCEPTANCE.json](OFFLINE_ACCEPTANCE.json) records the
full package check; [NEGATIVE_CONTROLS.txt](NEGATIVE_CONTROLS.txt) records controls.

`FILES.json` lists every inspection file's size/hash; `PATHS.json` resolves
historical locators without requiring historical home directories. `CASES.json`
and `FORMS.json` provide navigation. Essential original generated sources,
capture signatures, processed expected values, original checker/env/config,
all original Task109 scripts, original producer sources/requirements, per-engine
commands/results/stdout/stderr, identity snapshots, preservation and corrected
checker/target audit records, original prelaunch failures and diagnostic failures
are retained. Source files are deduplicated by mapping generated paths to the
identical case source. Original licenses/notices and `LICENSE_AUDIT.json` remain;
the package is not relicensed as a single work.

The full raw tree remains `xbd:/home/vick/rvv-task109/` (about 12 GB).
`FULL_RAW_INDEX.json` gives exact path, byte count and SHA256 of excluded guest
ELFs, TB maps and disassemblies; no TB dump is committed to Git. Partial slow
Python diffs and redundant producer/generated test trees stay in full raw;
complete original GNU differences are included. The inspection package is not
an executable toolchain or a complete full-raw copy. To verify excluded raw files
on a relocated full-raw tree, use `--full-raw-root /path/to/rvv-task109`.

The older `records/common/reference_config/sig_modify.py` is retained as original
configuration material; Task109 imported `records/producer/framework/src/act/sig_modify.py`,
whose hash is bound by the oracle. Replay and inspection use that actual processor.

The offline checker reprocesses all 1,918 frozen Sail captures with original db2
`act.sig_modify`, evaluates the three acceptance expressions extracted from the
unchanged `execute109.py` against original raw files and rejects inconsistent
identity/exit/summary/arm bindings. It cannot independently reconstruct guest
architectural results. Original `signature.h` ran in the archived guests; host
PASS means frozen evidence is consistent with those original predicates.
The archived audit records 483,103 target labels reached in each arm
(1,932,412 reach tuples). Inspection verifies audit accounting; TB reach is not
recomputed without the separately indexed raw. Reach does not establish
optimized target admission (**NOT_ESTABLISHED**).

Original compiled checker macro sites in PASS files: BASE `RVTEST_SIGUPD_V`
669,484; LEN 114,729; FFLAGS 89,449; VXSAT 21,628; scalar `RVTEST_SIGUPD` 1,494.
BASE observes selected first destination elements/bits; LEN retains original
active/masked/tail and allowed agnostic alternatives; CSR predicates retain
original flags. These are static macro sites, not dynamic assertions or full
architectural state comparisons. The 383 indexed and 97 FOF files passed original
selected result predicates; no general fault/restart/cause/address proof follows.

`ADAPTER_DELTAS.json` and `deltas/` expose the historical user adapter.
**Startup `csrs mstatus` is adapted; tested `cp_custom_vfp_state` `csrrc`/`csrrs`
is NOT removed.** `signature.h` is byte-identical in original and user env
(SHA256 `d4e7f032695ccd4bfb7dcf92687909aa20d4140e7f4ec7d999b829382f0ccacb`).
`Vf32-vfmv.f.s` and `Vf64-vfmv.f.s` preserve their original FS-state setup and
checker. QEMU SIGILL at `csrrc zero,mstatus,t1`, PCs `0x80005d20` and `0x8000738c`,
blocked both whole files before DUT; they have zero DUT calls and are not PASS.
The missing upstream EFFEW32 `vfwcvt.f.f.v` input and privileged vset obligations
remain separately unverified. Broader fault decisions belong to main review.

For a future explicitly requested single-case replay, export the archived
commands using local tool locations:

```sh
python3 scripts/replay_rvv_act_db2.py act-db2-inspection \
  --case Vls8-vluxei8.v --output /tmp/db2-one-case \
  --sail /opt/sail/bin/sail_riscv_sim --qemu /opt/qemu/bin/qemu-riscv32 \
  --stage /opt/clean961 --clang /opt/llvm/bin/clang-22
cat /tmp/db2-one-case/COMMANDS.json
# Only when a new run is intended:
# sh /tmp/db2-one-case/replay.sh
```

Export runs no guests. The script rebuilds the original source with retained
config and explicit original defines, captures/processes a new Sail signature,
compares it to the retained expected, performs the same-ELF QEMU selfcheck and
replays the archived four arm commands with isolated FS/cache. `timeout`, `cmp`,
Python, clang-22 and lld must be available. Verify exact executable/library pins
from `LAUNCH_REGISTRATION.json` before attributing results to the old build.
A replay with changed tools is a new identity, not verification of these receipts.
Blocked cases export only their historical reference steps and stop at original
QEMU failure. Task104 is deliberately excluded from this exporter.

This is a new Task110 command export, **not retroactively the script used for
Task109**. Old raw runners are unchanged and still document their historical
absolute paths; do not run `execute109.py batch` or delete receipts to manufacture
new work. No guest suites were rerun for this delivery, and no production,
thesis/status, public Release, push or email change is part of Task110.

To rebuild the inspection package from a relocated retained campaign, obtain the
pinned upstream `COPYING.APACHE`, `COPYING.BSD`, `COPYING.CC`, `README.md` under
`ACT-` filenames and the original generated-header `BSD-3-Clause-Clear.txt` in a
license directory. These files are already included in the inspection package.
The packager only copies evidence and hashes files:

```sh
python3 scripts/package_rvv_act_db2.py --campaign /data/rvv-task109 \
  --output /data/task110/inspection --tools ./scripts \
  --licenses /data/act-db2-inspection/licenses \
  --readme docs/rvv-validation/act-db2-task110/README.md
```

The package's logical content is reproducible from those retained inputs;
tar timestamps/ownership mean a rebuilt compressed archive need not have the
same byte hash. Historical full raw locators remain readable in original records;
new `PATHS.json` and `FULL_RAW_INDEX.json` use the supplied campaign root.
