# Retained external corpus on the exact Task128 host512 executable

[Task129 report](https://github.com/kust1011/rvdbt/blob/9dfc020b2aa7e98d068d954555b5902082538702/SESSION0_RESULT_129.md) · [combined host512 summary](combined/SUMMARY.md) · [machine counts](combined/SUMMARY.json) · [per-form table](combined/FORMS.md) · [exact-call partition](PARTITION.json) · [attempts](ATTEMPTS.md)

Task128's 5,904 memory calls and Task129's 15,412 remaining calls form an exact disjoint union of the original 21,316 calls: CHIPS Task120 11,744, ACT Task121 7,668 and Ara Task122 1,904. Full original call objects, including ELF identity, configuration and original acceptance scope, are subtracted. No opcode-name filtering is used in Task129. All calls use `/home/vick/rvdbt-host512-task128/build/bin/elfrun`, SHA256 `849e6dd0a11e78d19319a2d04b93a644f4dd04e9fbc86dd8b350288392d655a3`, with library `79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af`.

Raw is retained at `xbd:/home/vick/rvdbt-host512-task129` and `/home/user/research/materials/task129-host512-raw-20261013`. The [archive identity](ARCHIVE.json) and [transport registry](TRANSPORT.json) pin the 57,642,924-byte archive, SHA256 `9470eea51229f0035ad06f27d2cf8b038a31fb13c44e4e26cb1f4ee16d1f1e58`. `TRANSPORT.json` uses the existing `verify_rvv_artifacts.py --manifest` schema for separately obtained archive verification.

The combined navigation has one record per actual original call. Each record resolves to an actual Task128 or Task129 remote and local raw receipt, exact command/result, original source/checker/assertion bindings, source configuration literals and separately identified observed runtime evidence. Historical fields inside original bindings remain historical. No execution timestamps are invented and no Task128 call is reexecuted to produce this union.

Select a form and optionally a suite, original case or arm:

```sh
python3 scripts/rvv_scope_report.py \
  --host512-corpus docs/rvv-validation/host512-task129/combined/navigation.json.gz \
  --form vadd.vv --suite chips --arm B --output /tmp/host512-vadd
```

`record.json` contains the actual receipts and all original locators. CHIPS source/assertion/configuration selectors resolve in the [unchanged CHIPS inspection package](../chips-review-task93/README.md), remote `/home/vick/rvv-task93/inspection-task94-clean`; Form selection also reads the authenticated retained CHIPS geometry/literal copies and returns exact source rows/windows separately from runtime evidence. ACT literal sites and frozen signatures resolve in `/home/vick/act-current121/comparison-sites.json.gz` and `comparison.json.gz`, locally `/home/user/research/materials/act-current121-raw-20261012/`. [Ara original comparison text](../current-production-task122/comparison.json.gz) retains unchanged source/adapter/literals; current Task128/129 `observer.json` and stdout retain actual observation/comparison completion. Original Ara bindings and reviewed Task82 reduction B joins remain explicit.

With both downloaded raw roots available, rebuild the offline union into a fresh directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv_scope_report.py \
  --host512-corpus docs/rvv-validation --host512-build --output /tmp/host512-audit
```

This verifies complete-call partition/receipt equality, unique execution receipts, original flags, pinned candidate, raw command/result/stream/file joins, original CHIPS acceptance, and scoped Ara disposition. The retained remote collector additionally recomputes the original ACT predicate and unchanged Ara observer and authenticates source/ELF/checker/expected inputs and original runner hashes. [Local raw audit](LOCAL_RAW_AUDIT.json) checks the independently downloaded archive against every retained raw manifest entry.

Guest VLEN is taken from each actual command; source SEW/LMUL/VL/mask/tail/vstart literals do not establish corresponding runtime tuples. Missing observations stay UNKNOWN. Original check completion is bounded by the original checker: it is not full architectural-state or semantic Cartesian coverage. Enabled switches and aggregate counters do not identify individual native targets; Task128's [target-specific observations](../host512-task128/TARGET_CODE.json.gz) retain their exact bounded admission limits.

The [14 Task128 focused host tests](../host512-task128/FOCUSED_RESULTS.json) and eight exit-only helper controls are separate local/controlled evidence, adding no external call or form credit. No native unexpected-fault recovery, guest handler return/repair/retry, P4-04/equivalent, mapping-race or complete restart claim is established. Earlier excluded/reference/invalid-context cases remain excluded. No production changes, new references, push or issue closure; launcher owns completion signaling.
