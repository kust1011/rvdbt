# Task125 retained production integration

See [SESSION0_RESULT_125.md](https://github.com/kust1011/rvdbt/blob/9dfc020b2aa7e98d068d954555b5902082538702/SESSION0_RESULT_125.md) for results and limits.
`RECEIPTS.json.gz` contains every new call, unchanged original call metadata,
complete new command, build pins, result, available counters and raw file hashes.
`form-bindings.json.gz` joins each new receipt to its explicitly older-build
source/configuration/assertion binding. Three `*-queue.json.gz` files retain the
manifest-derived selection. Earlier Task120–122 artifacts stay unchanged.
Original queue header counts/pins remain historical metadata; `AUDIT.json`,
`SELECTION.json` and `IDENTITY_BEFORE/AFTER.json` give the Task125 counts/pins.

Read a form's exact links:

```sh
python3 - vle32.v <<'PY'
import gzip,json,sys
p='docs/rvv-validation/production-task125/form-bindings.json.gz'
rows=json.loads(gzip.decompress(open(p,'rb').read()))
for r in rows:
    if sys.argv[1] in r['form'].split(';'):
        print(json.dumps(r,indent=2))
        break
PY
```

Task119's executable sources are now ordinary repository targets. In a configured
Linux x86-64 LLVM22 build, reuse existing test infrastructure:

```sh
cmake --build BUILD --target rv32_llvm_memory_admission_test rv32_memory_run_scanner_test -j4
timeout 120 BUILD/bin/rv32_llvm_memory_admission_test
timeout 120 BUILD/bin/rv32_memory_run_scanner_test
```

The linked production probe takes a retained original ELF as `FSROOT/t.elf` and
a fresh writable cache directory; it boots normally but executes no guest code:

```sh
cmake --build BUILD --target rv32_host_copy_linkage_test -j4
timeout 90 BUILD/bin/rv32_host_copy_linkage_test FSROOT CACHE
```

Actual bounded xbd commands, compiler identity, stdout/stderr/rc and all failed
attempts are retained here. `scripts/replay_memory_task125.py` uses the retained
xbd evidence tree and original acceptance modules; `scripts/collect_memory_task125.py`
authenticates selected calls and source/build identities. These are correctness
receipts, not performance measurements or general external-suite dependencies.

Raw archive/transport locators and 39,384 verified files are recorded in
[LOCAL_RAW_AUDIT.json](LOCAL_RAW_AUDIT.json). Large raw streams and TB maps live in
that archive and the remote root. No push, issue closure or completion signal is
performed by these scripts; launcher owns signaling.
