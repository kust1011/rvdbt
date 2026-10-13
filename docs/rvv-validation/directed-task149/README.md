# Task149 directed multiply/divide

`muldiv149.py` declares all16 vmul/vmulh/vmulhu/vmulhsu and
vdiv/vdivu/vrem/vremu vv/vx forms. [Denominator](DENOMINATOR.json) and the
compressed [initial declaration](DECLARED_MANIFEST.json.gz) precede execution.
The shared capture, fixed Spike/Sail packet oracle and e2559c5c host512 four DUT
arms are reused. See [spec review](SPEC_REVIEW.json) for arithmetic and classes.

New artifacts only: set `RVV_COMPRESS=1`. Logical file paths accept legacy plain
bytes first, otherwise gzip. Each compressed artifact has `.storage.json`
with logical SHA256/length and compressed SHA256/length. Original build and
execution commands remain in place. stdout is streamed into gzip without a
raw disk copy; packets share the stdout gzip inode when bytes agree. Sail
signature packets are independent gzip files. Sources/ELFs and new cache files
are losslessly compressed. Workers materialize one recoverable guest ELF per
unit and share it with arms by hard link, then retain compressed symlinks for
arm paths. Restore with `storage149.materialize(path)`; restore both a unit ELF
and its `work/.../fs/t.elf` path when replaying the recorded DUT command. Cache
files can likewise be materialized to reuse them. No old artifacts are modified.

Every growing build/run unit checks the >=10GiB free reserve with a 64MiB
transient allowance; large compressed writes add their logical size allowance,
and audit admission reserves another1GiB. Streaming capture rechecks reserve
on each chunk. [Pilot storage estimate](STORAGE_ESTIMATE.json) uses allocated
unique inodes, the largest pilot unit times the full4224 units and a2GiB
metadata/audit allowance. This intentionally overestimates typical units.

Pilot: [summary](PILOT_SUMMARY.json), [full replay](PILOT_AUDIT.json),
[controls and lossless identities](PILOT_CONTROLS.json). Controls use actual
independent packets and leave original outputs unchanged. A separately retained
storage-corruption control is intentionally invalid. Local storage regression
checks additionally verify plain compatibility, exact logical identity,
hard-link deduplication, streamed capture and reserve refusal. No synthetic
packet supplies guest/reference completion credit. [Actual branch examples](REVIEW_EXAMPLES.json)
record independent packet positions, source/ELF identity, observed lane values
and CSRs. The read-only extractor supplies no golden data. Its initial utility
syntax error is retained in [first failures](FIRST_FAILURES.json).

Frozen remote artifacts:
- `xbd:/home/vick/rvv-directed-task149/pilot/`
- `xbd:/home/vick/rvv-directed-task149/full/`

The [full launcher](launch-full.sh) builds the frozen manifest, runs four bounded
workers, audits every retained packet/source/target/adapter, runs rejection
controls and writes minimal per-form evidence plus stage status. No new archive
or repeated transport package. Affinity28–31 and nice10 apply locally after load
checks. The task launcher owns completion signaling.

[Next carry/borrow declaration](next-carry/PER_FORM_DECLARATION.json) and
[predicates](next-carry/SPEC_PREDICATES.json) were prepared while the full run
executes. All guest executions are NOT_RUN; no carry ELF is built. Prepared
checker unit controls earn no RVV credit. Shared-runner routing and an independent
pilot are prerequisites for that next family.
