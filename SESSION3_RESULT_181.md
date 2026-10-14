# Task181 — final179 P4 common-build validation

Continued uncommitted178 at `481bfb5`. **P4 complete for all 595 accepted finite forms and all accepted external queues on immutable179**: **12,071,304 positive directed DUT packet checks**, **592 focused denial controls**, and **21,316 external calls**, all independently reaudited. **Zero accepted ISA failures or accepted-queue blockers.** Ordinary coverage is **3,017,262 cases/arm**; focused positives add564 cases/arm. B/M1/M2/BOTH use the original predicates, frozen ELFs, flags and independent reference packets. No ELF rebuild or reference execution occurred. [Final result](docs/rvv-validation/directed-task181/evidence/FINAL_RESULT.json), [compact595-form table](docs/rvv-validation/directed-task181/evidence/PER_FORM_RESULTS.md), [CSV](docs/rvv-validation/directed-task181/evidence/PER_FORM_RESULTS.csv).

**Final executable:** `xbd:/home/vick/rvdbt-host512-task179-build/build/bin/elfrun`, SHA256 **8a468967852b8f16225b359fce99c0d22ab286d6314cb90a79934a7376207281**. Library SHA256 **79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af** is unchanged. Original174 is **18521de85c7ba352b0dbc6155f26d96c25522b6a6bc81cb26fb38c4c0b1f79a4**, retained and superseded. No174 DUT PASS receives179 credit. [Candidate/plan pins](docs/rvv-validation/directed-task181/CANDIDATE_PIN.json), [all 102 original-versus-final build identities](docs/rvv-validation/directed-task181/ORIGINAL_VERSUS_FINAL.json), [original174 manifest](docs/rvv-validation/directed-task181/BUILD_MANIFEST_174.json), [final179 manifest](docs/rvv-validation/directed-task181/BUILD_MANIFEST_179.json).

All 102 directed entries complete. **380,968 ordinary directed commands**, **2,848 focused commands** and **21,316 external commands** give **405,132 unique Task181 DUT commands**. Recovery authenticates and rechecks one earlier same181 capture, counted once; there is zero historical174/179 DUT execution reuse. The separate minimal entrypoint performs8 additional commands/84 checks without matrix credit. Counts below are outputs actually checked, counted once across execution and independent audit.

| Family owner | Forms | Planned positive checks | Actual checked | Failed ISA | Blocked |
|---|---:|---:|---:|---:|---:|
|145|3|37,572|37,572|0|0|
|146|13|216,308|216,308|0|0|
|147|1|112,952|112,952|0|0|
|148|19|492,788|492,788|0|0|
|149|16|377,024|377,024|0|0|
|150|15|450,636|450,636|0|0|
|151|6|146,616|146,616|0|0|
|152|20|486,608|486,608|0|0|
|153|10|445,600|445,600|0|0|
|154|8|152,608|152,608|0|0|
|155|8|745,600|745,600|0|0|
|159|24|1,886,048|1,886,048|0|0|
|160|10|499,768|499,768|0|0|
|161|35|415,056|415,056|0|0|
|162|11|245,072|245,072|0|0|
|163|10|372,808|372,808|0|0|
|165|128|342,864|342,864|0|0|
|166|96|273,424|273,424|0|0|
|167|16|950,656|950,656|0|0|
|168|54|179,480|179,480|0|0|
|169|9|218,480|218,480|0|0|
|170|21|386,724|386,724|0|0|
|171|5|50,608|50,608|0|0|
|172|21|944,556|944,556|0|0|
|173|18|683,640|683,640|0|0|
|174|6|344,448|344,448|0|0|
|175|9|133,560|133,560|0|0|
|176|3|479,800|479,800|0|0|

| External suite | Planned calls | Actual checked | Failed | Blocked accepted calls | Outcome |
|---|---:|---:|---:|---:|---|
|CHIPS|11,744|11,744|0|0|11,532 positives +212 denial controls|
|ACT|7,668|7,668|0|0|All accepted signature predicates PASS|
|ARA|1,904|1,904|0|0|1,888 whole-file PASS +16 TEST_CASE1/2-only SCOPED_PASS|

| Focused suite | Planned checks | Actual checked | Positive | Denial controls | Failed | Blocked |
|---|---:|---:|---:|---:|---:|---:|
|guard165|128|128|80|48|0|0|
|guard166|160|160|96|64|0|0|
|faults|1472|1472|992|480|0|0|
|fof-startmask|128|128|128|0|0|0|
|vill|960|960|960|0|0|0|

**Separate retained exclusions/blockers:** the original two ACT reference-blocked cases remain outside7668 accepted calls. Ara’s16 scoped calls preserve the exact original174 stdout failure payloads for TEST_CASE3/4 and never receive whole-file PASS. Source-reserved 162 compression-mask aliases (132 declarations),165 conflicting-EEW/v0 declarations (384),166 reserved pilot declarations (596), and reserved arithmetic/configuration profiles remain excluded by original case IDs. They are not failed accepted ISA cases or missing595 forms. Original failed164 FMA/169 insertion and failed172 narrowing receipts retain their original provenance; accepted167/171/corrected172 sources supply the queue. [External exact joins](docs/rvv-validation/directed-task181/evidence/EXTERNAL_EXACT_JOINS.json.gz), [scoped payload identity proof](docs/rvv-validation/directed-task181/ARA_SCOPED_OUTCOMES_PRESERVED.json), [frozen accepted plan](docs/rvv-validation/directed-task181/DIRECTED_PLAN.json.gz), [162 exclusions](docs/rvv-validation/directed-task178/TASK162_SOURCE_RULE_RECEIPT_EXCLUSIONS.json), [165 exclusions](docs/rvv-validation/directed-task178/TASK165_RECLASSIFICATION_EXCLUSIONS.json).

The exact own174 run controller967939 and post controller973813 were suspended to prevent future scheduling, then stopped after active remaining b149-006 completed372,648 checks. No guest was signaled. Obsolete resource monitor970845 was separately validated and stopped after a completed JSONL sample. Superseded174 retains **1,232,420 directed checks**, including **859,620 independent rereads**, plus its complete21,316-call external audit. Unrun174 work is superseded, not failedISA. Its supported trace1 host-frame fault before the first RVV instruction remains retained in177/179 evidence;179 repairs the returning observer’s duplicate frame teardown. [Controller/partial receipts](docs/rvv-validation/directed-task181/SUPERSEDED174.json), [partial174 family counts](docs/rvv-validation/directed-task181/PARTIAL174_BY_FAMILY.json), [monitor stop](docs/rvv-validation/directed-task181/OLD174_MONITOR_STOP.json).

Original178 harness failures were diagnosed from original raw. b146 audit stopped1 at an indentation/import error before checking packets; corrected audit reopens216,308174 DUT packets, with no guest rerun. Ara’s original path parser required stdout beside stderr; recovery materializes both retained gzip streams and executes only221 previously unattempted calls, then audits all 21,316 exact174 receipts. Both error histories remain retained. [Raw diagnosis joins](docs/rvv-validation/directed-task181/HARNESS_DIAGNOSIS.json), [178 attempt history](docs/rvv-validation/directed-task178/ATTEMPTS.md).

Task181’s b175-095 stop is an inherited harness binding error, not a179 ISA failure: the stale review175 prestate cache ignores declared QEMU shift_values and rejects an original reference before the failing unit launches a DUT. Exact frozen tools-next validates900 original references and3600 original174 DUT packets. Only two narrowing checker bindings are amended; queue definitions, indices, ELFs, reference packets, flags and candidate bytes remain unchanged. The failed remaining directory/log/stop receipts are retained. Recovery checks manifest/ELF/flags/engine/library/command identity before using one complete same181 capture; all other needed calls are newly executed. Its full independent audit passes. [Diagnosis](docs/rvv-validation/directed-task181/NARROW175_DIAGNOSIS.json), [plan amendment](docs/rvv-validation/directed-task181/PLAN_AMENDMENT.json), [retained error](docs/rvv-validation/directed-task181/narrow175-reference-prestate-attempt1.log).

The delayed duplicate external launch was rejected before any guest and is retained; per-call receipts, not the overwritten progress header, establish counts. Transfer SSH255 failures retain verified archives/original raw or incomplete capture attempts. Gzip metadata with SHA256, an idempotent receiver, non-multiplexed connections and bounded transport retries recover packaging without guest/reference/build reruns. Failed raw is retained in its original namespace. [Duplicate-launch receipt](docs/rvv-validation/directed-task181/LAUNCH_ATTEMPT.json), [metadata recovery](docs/rvv-validation/directed-task181/TRANSFER_RECOVERY.json), [capture recovery](docs/rvv-validation/directed-task181/TRANSFER_CAPTURE_RECOVERY.json).

Steady-state181 controllers share guest admission8/shared16, two cross-controller predicate slots, serialized audits, shared offline limit4, nice10 and no assigned affinity. Compression participates in the common slot/offline lock. Resource samples: **4,936**, own/shared guest peaks **4/7**, observed nice **10**, minimum free **18.975GiB**, above10GiB reserve. The initial174 drain overlapped181 startup while174 retained its private predicate semaphore; combined cross-version predicate occupancy is not proven, and sparse process sampling is not continuous occupancy proof. This limitation is disclosed rather than presented as fully clean resource compliance. [Preflight](docs/rvv-validation/directed-task181/PREFLIGHT.json), [resource result](docs/rvv-validation/directed-task181/evidence/RESOURCE_FINAL.json), [transition limitation](docs/rvv-validation/directed-task181/TRANSITION_RESOURCE_LIMITATION.json).

Every new stream is captured with gzip. **102 verified archives /1,268,670,066 bytes** retain closed successful directed streams under `/home/user/research/materials/task181-common179-raw-20261014`; each has archive CRC/SHA256 and storage/member-hash verification before moving only its new successful roots. [Compact final archive index](docs/rvv-validation/directed-task181/TRANSFER_INDEX.json) maps original namespaces and exact receipt hashes. Full member ledgers remain beside local archives and at `xbd:/home/vick/rvv-task181/TRANSFERS.jsonl`; the large exported ledger is intentionally not duplicated into the compact git packet. External, focused and failed remaining raw stay at `xbd:/home/vick/rvv-task181`. All174 raw/inputs/references stay retained. Packaging performs no recursive historical hashing, ELF rebuild or reference execution.

**Same-build P3 is separately complete in Task180:** all 2418 sequence cases/arm,9672 DUT checks/2640 commands,30,456 PC/arm rows and1824 multi frames/1472 native-executed frames pass on the same179 hash. The four inadvertently removed test-only identity assertions are restored and the complete codegen suite passes. Focused179 trace1 evidence remains retained; neither a full2418-case trace1 matrix nor all-form trace1 coverage is claimed. Requested B/M1/M2/BOTH flags here do not establish per-target native admission. [P3 totals](docs/rvv-validation/directed-task181/P3_TASK180_FINAL_TOTALS.json), [restored assertions result](docs/rvv-validation/directed-task181/P3_TASK180_RESTORED_ASSERTIONS_RESULT.json).

**Source integration:** preserve167 FMA invalid-product flags (`f238a5d` /session3 `1f9a054`),172 RMM narrowing underflow (`47028a8`), exactly the three171 scalar insertion production hunks (`73fc8e2`, isolated174 integration),179 returning trace frame lifetime (`79da14c`), and180 restored test assertions (`9b768b6`). Test/CMake fixtures and frozen source hashes must be preserved after conflict resolution. Task181 changes orchestration/validation only; its local production tree is not relabeled as frozen179. A rebuilt binary has a new identity and receives no implicit181 receipt credit. [Concrete source requirements and diffs](docs/rvv-validation/directed-task181/SOURCE_INTEGRATION.md).

Reproduce a bounded new pilot using retained host inputs:

```sh
python3 scripts/rvv/regression181.py minimal \
  --output /home/vick/rvv-task181-minimal-fresh --entry b145-000
```

The tested minimal entrypoint passes84 checks/8 new commands in a fresh namespace, with no rebuild/reference run. [Minimal result](docs/rvv-validation/directed-task181/MINIMAL_RESULT.json), [lineage](docs/rvv-validation/directed-task181/MINIMAL_LINEAGE.json). Finite operand/mask/register/policy matrices, original reference ancestry, bounded unordered FP sums and original parser scopes remain explicit limits. No handler return/mapping repair/same-PC retry, persistent AOT-cache closure, Linux/LLVM extension, performance run, publication, push or email is claimed. All155 dirty file hashes are preserved; the commit includes only owned178/181 code/docs. Requested tmux completion signals follow the owned commit.
