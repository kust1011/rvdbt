# Exact Task128 host512 retained external corpus

21,316 original calls = 5,904 actual Task128 receipts + 15,412 actual Task129 receipts. Full call identities are disjoint; Task128 calls were not repeated. All use the unchanged executable 849e6dd0… and matching library 79d0ba2a….

| Suite | Original calls | Whole-file/registered PASS | Scoped PASS | Checked forms |
|---|---:|---:|---:|---:|
|chips|11744|11744|0|595|
|act|7668|7668|0|590|
|ara|1904|1888|16|422|

The checked-form union is 595. CHIPS includes 11,532 positives and 212 separate controls. Ara includes 1,888 whole-file passes and the original 16 TEST_CASE1/2 MAC outcomes, each with whole_file_pass=false. ACT’s two original reference-blocked outputs remain outside its 7,668 accepted calls. Mismatch/crash/timeout/runner-error/unattempted accepted calls: zero.

Each arm has 2,936 CHIPS calls (2,883 positives + 53 controls), 1,917 ACT calls, and 476 Ara calls (472 whole-file + four scoped). See [form navigation](FORMS.md) and [reader instructions](../README.md).

| Suite | Actual guest VLEN command settings: distinct calls |
|---|---|
|chips|128=9564; 256=116; 512=116; 1024=1672; 2048=116; 4096=160|
|act|1024=7668|
|ara|128=12; 256=20; 512=44; 1024=1708; 2048=88; 4096=32|

These VLEN settings are concrete commands, not a Cartesian set of observed runtime tuples. Original source SEW/LMUL/requested-VL/mask/tail/vstart literals and source/checker windows remain source evidence; current printed VL/vtype/scalar/CSR/checker observations stay separate. Missing runtime dimensions remain UNKNOWN.

Enabled direct/M1/M2 flags, aggregate counters and program acceptance do not establish individual target-native admission. Task128’s specific target-PC observations retain guarded native, scalar and helper routes with their original limits. Its 14 focused host tests and eight exit-only helper controls are separate evidence, adding no external credit.

This finishes the finite retained corpus on the exact build. It does not establish every semantic combination, complete state/suppression/history, general overlap/restart or unexpected native host-fault recovery. No guest handler return, mapping repair, same-PC retry, P4-04/equivalent or new reference was executed. Earlier failures/exclusions remain separately attributed; no production changes, push or issue closure.
