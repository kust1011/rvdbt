# Prelaunch/build observations

`W/AGENTS.md` was requested and read was attempted; the file is absent. No
AGENTS.md exists at the workspace's ancestor paths. Active upstream delivery plan
and current THESIS_STATUS were read. Starting HEAD18d911e on the requested branch;
existing untracked Python caches are preserved.

The first serial compilation was intentionally terminated to use bounded local
parallel compilation; this was not a guest/reference/DUT failure. Its generated
partial directory remains at
`/home/user/research/materials/task146-directed-build-20261013/corpus`, with launch
log `/home/user/research/materials/task146-build.log`. No case was executed there.
A fresh build with `--build-jobs 4` uses
`/home/user/research/materials/task146-directed-build4-20261013/corpus`.
Both manifest bytes have the declaration's SHA256; no obligation was dropped.
All successful formal compiler commands and stderr are in the fresh corpus.

The separately declared pilot selects64 existing finite units, VLEN128,
SEW16/64, LMUL1, all16 forms,828 cases. Its manifest retains the full-family
ordinals and records the exact selection. It earns no formal case credit. This
confirms the fixed Sail executable's ordinary initialized-state support before
full execution. No initial guest/reference/DUT failure occurred in the pilot.
128 isolated actual-packet corruption controls are intentional negative evidence,
not formal test failures. The old pilot runner and updated separated audit are
retained independently of the full-run versions.

One prelaunch scp command mistakenly named an absent destination directory
`xbd:/home/vick/rvv-directed-task146/final-unavailable-path` and exited1:
`scp: /home/vick/rvv-directed-task146/final-unavailable-path: No such file or directory`.
No guest run was affected. The destination was created as `scripts-final/` and
transfer succeeded; old pilot scripts were preserved before installing final
runner/auditor. This is an environment/transfer error, not a test/reference/DUT
failure. Original stderr is retained in this record from the tool receipt.

The first local transport verification began before tar extraction completed and
correctly rejected the partial tree (64,703 observed vs193,372 expected files,
including RAW_MANIFEST.json). Original failure is preserved at
`/home/user/research/materials/task146-transport-first-failure.txt` with the exact
assertion and example missing paths. This is an environment/transport sequencing
error, not a test/reference/DUT failure or missing remote payload. Extraction is
allowed to finish before a fresh full verification. The frozen remote archive and
formal raw are unchanged. The final TRANSPORT.json records the completed check.
