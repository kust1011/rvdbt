# Task88: fresh checkout external replay

The small/ bundle retains original commands, raw stdout/stderr, return/timeout,
checker observations, original compare reports, fresh build and dependency logs,
selected emitted host bytes/disassembly and their source locators/hashes. Logs
larger than200KB are gzip-compressed losslessly. Original bulky caches, ELFs,
full TB dumps and source/build scratch remain on xbd under
/home/vick/rvv-portable88-20261012; no historical evidence was deleted.

Fresh production source built at69ce3f8; its dbt Git tree is byte-identical to
all Task88 checkpoints. Replay runner at3425955, final offline audit at7a332f1.
The independent checkout and source-built DUT are new; historical DUT binaries
were not reused. fresh-build-provenance.json records exact configure/build,
submodules, compiler, runtime libraries and source/executable identities.

replay1 retains Ara Spike/B PASS and the M1 duplicate-option CLI failure before
guest entry. replay2 revalidates/reuses those two same-ELF receipts and executes
the remaining eight. Ten unique valid guest calls: two Spike and eight DUT;
one additional failed DUT launcher call. The summary's10 is its population,
not ten new calls in replay2. Every valid receipt exits0 without timeout.

Ara: all five original functions,20 assertions/200 comparisons per receipt;
VLEN1024. RVVTS: complete original16-instruction API-derived sequence,
VLEN2048/e32/m1/VL64,8768-byte packet,32vectors/32full64FPR/10CSR exact.
RVVTS original MachineState.py and BSD3 notice are in source_evidence/;
execution imports the separately fetched pinned checkout. Padding, complete
GPR/PC/mstatus/final memory and intermediate instruction flags are outside scope.
No new goldens or ISA counts are generated. See SESSION0_RESULT_88.md and
../portable-external.md for commands, observations, admission and limitations.

admission.json and target-host.* show current M1/Both target frame0 with3members,
4chunks and count1, two width2 batches. Frame1 has4members and is distinct.
Ara has zero multi-member admission. The offline admission parser initially
rejected because objdump continuation lines were parsed across line boundaries;
raw guest output was unchanged and the same load/op/store requirements remain.
All attempt diagnostics and raw dependency failures remain in small/.
