# Task134 attempts

All 5,901 new original guest calls passed on their first attempt. Three matching
Task133 calls were credited only after full-object, final production identity,
stream-hash and original-predicate authentication. No guest retry or rerun occurred.

Evidence tooling initially used `dbt.dir` instead of the actual `dbtstatic.dir`
archive target and asserted 51 commands; the actual set is 53 (52 C++ plus one
assembly). The next assertion incorrectly required C++ flags on `rvv_host_copy.S`.
The final audit checks all 52 production C++ commands and retains the assembly
command separately. The original script versions and second assertion stderr are
retained. The first assertion traceback is retained in the session launcher log;
it failed at the `assert len(prod)==51` line. No build or guest command depended
on either failed audit, and no production/test rebuild was invoked.

The offline queue audit initially required `chunk_bytes=64` in every stderr;
CHIPS does not enable the ACT exit statistics. After removing that unsupported
requirement it exposed a second mistaken all-VLEN1024 assertion. Original retained
CHIPS/Ara calls have several VLENs. Exact flags were unchanged; final audit records
the real per-suite distribution. Both original scripts/stderr are retained under
`audit.initial.*` and `audit.second.*`. Neither audit executes guest instructions.

One SCP/SSH connection failed during banner exchange; the old remote audit script
remained and no dependent checks were launched. Successful transfer and audit were
explicitly required before focused tests. No stale executable was used after a
build failure: Task134 performs no build. Prior Task133 build failures and its
accidental stale test batch remain in the untouched Task133 report/archive; no
fault credit or queue result is imported from those attempts.

Local extraction was started before the 424MiB archive transfer completed. It
failed with `gzip: stdin: unexpected end of file` / `tar: Unexpected EOF in archive`
(exit2). The partial extraction is retained separately as
`task134-memory-raw-20261013.initial-incomplete`; it receives no verification credit.
Final extraction is gated on successful transfer and the remote archive SHA256.

The large SCP archive download later ended with `lost connection` (exit1).
The partial file was resumed using `rsync --partial --append-verify`; final
archive SHA256 must match the remote complete archive before extraction/credit.
