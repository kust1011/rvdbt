# Task178 frozen common-build regression

This queue replays accepted single-instruction directed matrices and external
CHIPS/ACT/Ara programs on immutable Task174. The build is
`18521de85c7ba352b0dbc6155f26d96c25522b6a6bc81cb26fb38c4c0b1f79a4`;
[the source/build manifest](BUILD_MANIFEST_174.json) records immutable172 plus
the three Task171 scalar-insertion production hunks. Task177 owns actual
multi-instruction M1/BOTH admission. Requested flags here do not prove that
an individual target entered an optimized route.

The [frozen plan](DIRECTED_PLAN.json.gz) contains every original manifest path,
its hash, accepted case indices, original ELF build-command hash, exact
checker/dependency pins, four-arm flags, legal per-form counts and reuse status.
Its 595 form owners reconcile [the Task175 source map](SOURCE_MAP_175.json).
Task176 supplies the three completed unary forms; Task173's final matrix and
supplement are included. Original failed164 FMA and failed169 insertion results
are superseded by accepted167/171 sources. Original narrow172 failures are
superseded by the fixed source views. Overlapping pilots receive no duplicate
credit. Tasks174/175/176 use exact existing Task174 DUT receipts, independently
rechecked against their original references and commands. Every other owner
receives new Task174 executions in `/home/vick/rvv-task178/directed/`.

Task162's 132 full compression source-mask-alias declarations and Task165's
384 conflicting-EEW/v0 declarations are excluded using explicit original case
IDs. Task166's corrected generator supplies the 596 pilot reserved exclusions.
Early arithmetic reserved-start profiles and reserved configuration declarations
also receive no legal credit. Frozen ELFs can contain incidental excluded
packets; their bytes remain retained. Source-map counts are historical receipts,
not this queue's denominator. The complete accepted matrices also retain legal
no-body, configuration and supplemental cases omitted from some historical
"ordinary" count columns.

The execution host must retain the original immutable input roots listed in the
plan. No guest or reference is rebuilt or rerun. Python assertions must be enabled.
The repository entrypoint exposes the queue stages:

```sh
python3 scripts/rvv/regression178.py status
python3 scripts/rvv/regression178.py prepare
python3 scripts/rvv/regression178.py external
python3 scripts/rvv/regression178.py run
python3 scripts/rvv/regression178.py external-audit
python3 scripts/rvv/regression178.py focused --focused-suite guard165
python3 scripts/rvv/regression178.py summarize
```

`prepare` declares immutable inputs; it launches no guest. `run` proves a bounded
pilot for each entry before its disjoint remainder, then audits retained packets.
Completed stages are resumed without rerun. New execution directories must not
exist; a failed partial stage is retained in its original namespace. The focused
stage supports guard165, guard166, faults, fof-startmask and vill; its corresponding
`tools/focused.py SUITE audit` command independently rechecks the retained output.
`external-audit` serializes with directed audit through an offline lock.

The owned adapter sources are in `scripts/rvv/regression178/`: prepare declares
source/ownership; replay executes and audits packets; external preserves original
suite predicates with stream compression; audit_external rechecks exact joins;
focused handles original page-edge observers; run resumes the declared queue;
summarize produces the final tables; admission178 monitors and gates processes.
These sources are staged in `xbd:/home/vick/rvv-task178/tools/`. They reuse pinned
family checkers in place. The oldest Task145 combined checker is called directly;
its repeated decoding of identical packets is memoized without changing any
predicate expression. No raw output supplies an expected value.

Every directed case's manifest gives VLEN, SEW/EEW, LMUL/EMUL, VL, vstart,
register operands and overlaps, mask, tail/mask policy, scalar/immediate inputs,
initial sticky flags, and semantic scenario tag. These are declared finite
case dimensions, not exhaustive Cartesian coverage. The exact contract is the
pinned original predicate and source/spec review for its family:

| Owners | Dimensions and oracle contract |
|---|---|
|145–146,148–152|Integer arithmetic/logic/shifts, signed/unsigned boundaries, divide-zero/overflow, carry/borrow packed masks, merge/move selection, comparisons, legal overlaps, RV32 scalar/immediate width, masks/policies/initialized starts. Exact modular/result/state predicates plus original Spike/Sail packets.|
|147–148 configuration|AVL ranges, zero registers, preservation, unsupported vtype/vill and legal policy changes. Original configuration contract and original initialized Spike/Sail packets; reserved preserve/start profiles excluded.|
|153,155,159 fixed point|Saturation and sticky vxsat, all vxrm modes, ties/rounding, scaling and narrowing widths, accumulator carry and suppression. Exact integer predicates and original Spike/Sail packets.|
|154,161|Multiply-accumulate, signed/unsigned widening arithmetic/MAC, extension and destination chunk boundaries. Exact integer/state predicates and original references.|
|159 mask,162,163,169 prefix|Packed mask boundaries, scalar popcount/first, slides/gathers/compression, reductions, prefix/index and whole-register transfers. Original full-register/CSR predicates, permitted tails, and reference packets; illegal overlap/group declarations excluded.|
|165–166|EEW/SEW/EMUL/NF, field spacing, stride/index order, aligned conflicting stores, access suppression, register groups, memory/canary preservation. Exact original memory predicates and original references; unordered store winners use the accepted set rather than requiring the reference winner. Focused legal page-edge accesses and original denial controls are separate.|
|168|Whole-register/mask memory, FOF returned VL, masks/starts, masked policy, later page faults, vill and exit-only denial controls. Original memory/FOF predicates plus preserved reference packets. No handler return/repair/retry claim.|
|171 transfers|Scalar extraction/insertion, prestart/VL0 preservation, boxing/payloads and FP splat, full vector/FPR/CSR state. Corrected original permissive Sail packets and frozen ELFs.|
|160,167,170,172–176 FP|All valid rounding modes, exact arithmetic/FMA/conversion, canonical NaNs and signaling flags, valid/malformed boxes, sign/min/max/class/comparison, widened operands, reductions, unary special values, mask/prestart/tail flag suppression. Exact rational/integer/spec-table predicates plus original Spike/Sail packets. Task174 retains its bounded unordered-sum acceptance; arbitrary inexact sums remain excluded. Task176 sqrt uses rational squared intervals; estimates use ratified tables without tolerance.|

Each reference is checked with the frozen ISA predicate before reuse. Each new
DUT packet must pass that predicate and the original reference relation. The
second audit reopens retained streams and checks execution/command/hash joins.
No reference executor runs during finalization. Original Task176 reference
SoftFloat ancestry and exact-rational independence limits remain unchanged.

External queues preserve complete original call objects: 11,744 CHIPS (11,532
positives and 212 controls), 7,668 ACT, and 1,904 Ara (1,888 whole-file accepted
calls plus 16 TEST_CASE1/2-only calls). CHIPS uses its original exit/exact stdout
classifier; ACT evaluates the exact original execute109 guest-checker expression
against frozen embedded signature goldens; Ara invokes the original typed/scalar/
CSR/initialization parsers. Original source operands, expected data and adapters
remain unchanged. The two ACT reference blockers remain outside the accepted
queue. Ara scoped MAC calls must preserve original TEST_CASE3/4 failures and
never receive whole-file PASS.

[Storage preflight](STORAGE_PREFLIGHT.json) records actual capacity and a 16GiB
compressed-output budget with a 10GiB reserve. New streams are compressed during
capture. Only new successful fs/cache scratch is deleted, with exact paths in
`CLEANUP.jsonl`; frozen binaries, manifests, references and failures remain.
Guest admission caps own/shared guests at 8/16; no build is needed; audit uses
at most two own workers, serialized, with shared offline limit four. All workers
run at nice10 without affinity. `RESOURCES.jsonl` retains actual sampled process
and free-space evidence. No performance, Linux, LLVM, publication or messaging
work is included.

The [measured storage update](STORAGE_UPDATE.json) replaces the initial budget
with a conservative 60GiB projection. A nice10 transfer controller acts below
22GiB free. Closed successful NEW `pilot/runs` and `remaining/runs` are stored
in `/home/user/research/materials/task178-common-raw-20261014/*.tar.gz` with
archive SHA256, exact members and every compressed storage-receipt hash checked
before moving their source paths. No original input, reference, raw failure or
external scoped-failure output is moved. The final transfer ledger maps each
original new-result namespace to its retained archive. To inspect an archive,
verify its SHA256 against the adjacent `.transfer.json`, then extract into a
new inspection directory; archive paths are relative `pilot/runs` and
`remaining/runs`. Restore those two directories to their original remote
namespace only after checking they are absent and the matching TRANSFER.json
identifies this archive, before requesting another retained-packet audit.
