# Task142 complete retained corpus on final signal-copy build

All 21,316 calls have fresh Task142 receipts on e2559c5cd930e919503c79b44af219c243041e86f5b83a157bec860814e8336b; prior-build credit: zero. Three unchanged pilots plus 21,313 disjoint remaining calls.

| Suite | Positives / whole-file PASS | Controls PASS | Scoped PASS |
|---|---:|---:|---:|
| CHIPS | 11,532 | 212 | 0 |
| ACT | 7,668 | 0 | 0 |
| Ara | 1,888 | 0 | 16 |

Each B/M1/M2/BOTH arm: CHIPS 2,883 positives + 53 controls; ACT 1,917; Ara 472 whole-file + 4 scoped. Two ACT reference blockers remain outside the queue. Checked-form union: 595. See [forms](FORMS.md), [counts](SUMMARY.json) and [reader instructions](../README.md).

Guest VLEN/flags are actual command settings. Source SEW/LMUL/requested VL/mask/tail/vstart literals remain source evidence; unprinted runtime dimensions remain UNKNOWN. Enabled flags and aggregate counters are not a target-native census. No guest handler return, mapping repair, same-PC retry, new reference, fault/restart or performance campaign was executed. Earlier target-admission observations remain attributed to their original build.
