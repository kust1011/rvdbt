# Suite execution accounting

## Additional ACT source revision

The [ACT db2 campaign](act-db2-task110/README.md) is separate from the older
accounting snapshot below. Its 2,147 marked instruction/SEW inputs produce
1,919 files; 228 inputs are excluded by the selected RV32/ELEN64 profile
(128 ei64 indexed inputs and 100 optional FP16/Zvfh inputs). One output reuses
an exact previously accepted case. Of the remaining 1,918, 1,916 pass the original
self-check under B/M1/M2/Both, giving 7,664 additional clean961 DUT executions.
Two complete files stop at tested privileged state setup in QEMU, with no DUT
calls. There are no unattempted outputs in this queue.

The 3,836 primary reference calls comprise 1,918 Sail passes and 1,916 QEMU
passes plus two QEMU failures. Two additional QEMU diagnostic failures are
retained separately. These are execution counts, not new instruction forms:
the checked union remains 595. The linked index records the original source,
checker, configuration, signature and each result. Replay-interface smoke tests
are recorded separately and do not increase this campaign's counts.

## Earlier registered-receipt snapshot (Task96)

This is an offline accounting checkpoint over `xbd:/home/vick/rvv-task90/task90`,
including its accepted Ara overlays. No guests, compilers or references were run.
The existing [Task90 report](current-scope/ara-accepted-evidence.md) gives form sets
and historical registrations, but does not give final distinct execution counts.
The accompanying [JSON](suite-execution-summary.json) separates physical receipts,
ledger dispositions and form bindings. It is not an upstream coverage denominator.
Original suite universes remain **UNKNOWN** for all five suites.

| Suite / candidate | Distinct registered DUT receipts | Distinct registered reference receipts | Controls / skipped units |
|---|---|---|---|
| CHIPS clean961 | 11,636 positive PASS | See reference rows below | 212 successful rejection calls; 32 Task54 prelaunch BLOCKED cells |
| CHIPS historical2af5 | 11,568 positive PASS | — | 212 successful rejection calls |
| CHIPS explicit references | — | 60 PASS: pspike17, Spike17, QEMU26 | Separate from primary DUT executions below |
| ACT clean961 | 7,920 PASS | — | Eight Task53 prelaunch BLOCKED cells |
| ACT historical2af5 / historical-f8123 | 256 / 160 PASS | — | Separate prior candidates |
| ACT historical-unresolved | 6,624 retained BLOCKED diagnostic receipts | — | 8,188 further BLOCKED execution rows lack usable raw locators; candidate/ELF recovery unresolved |
| ACT references | — | QEMU1,979 PASS +2 REFERENCE_ERROR; Sail1,878 PASS | Four other-candidate NOT_RUN rows; no registered harness controls |
| RVV-ATG clean961 | 736 PASS (Task61:4; Task62:732) | — | Producer/signature blockers are source dispositions, not calls |
| RVV-ATG explicit reference rejects | — | Two QEMU REFERENCE_ERROR | Full capture/reference call count is not registered; no registered harness controls |
| Ara clean961, baseline + overlays | 1,892 PASS +104 RESULT_MISMATCH +40 BLOCKED diagnostic attempts | — | Sixteen baseline NOT_RUN rows across DUT/reference; scoped MAC rechecks add no calls |
| Ara historical2af5 | 368 PASS | — | Kept separate from clean961 |
| Ara references, baseline + overlays | — | 481 PASS +32 RESULT_MISMATCH +3 REFERENCE_ERROR +10 BLOCKED diagnostic attempts | Ara89:390 retained parser rejection controls, zero guest calls |
| SiFive RIF clean961 | 8,604 raw PASS | — | Includes 2,172 quarantined O2 diagnostic receipts and432 repaired reduction endpoints |
| SiFive RIF explicit same-ELF QEMU | — | 1,262 PASS | 108 compile/link records excluded; full producer/capture reference count unregistered |

An actual receipt requires a retained stdout locator and numeric return code;
`UNKNOWN`, `待查`, `NOT_RUN` and prelaunch blockers are not calls. A call is keyed
by its normalized stdout path and reference/DUT role. Multiple forms, aliases,
source blocks and `SCOPED_ACCEPTANCE` rows sharing it count once. Separate raw
paths remain separate observations even for the same ELF/configuration. Conversely,
the old summary's ELF/executable/library/arm/flags identity counts configurations,
not repeated calls. PASS means the recorded scoped checker verdict. A BLOCKED
receipt can be an actual diagnostic attempt; a BLOCKED row without a receipt is
a skipped obligation. Failure status spellings are retained in JSON, not collapsed
into ISA failures. Harness PASS can mean successful rejection of a bad answer.

The JSON keeps every cohort/candidate/row-kind/status partition, recorded arm and
VLEN sets, plus a ledger row selector and source/checker/adapter/raw pointer for
each receipt group. Select those cohorts in `SUITE_RUN_MANIFEST.csv`, then join
`row_id = ACTUAL_FORM_VALIDATION_BINDINGS.csv.ledger_row_id` for exact ELF,
executable/library hashes, full flags, known configuration tuples and predicates.
The arm/VLEN sets in a group are navigation, **not** their Cartesian product.
Missing runtime SEW/LMUL/VL/mask/tail/vstart dimensions remain unknown.

These separate **SOURCE_CASE disposition rows** retain skipped/blocked source
units. They are registrations of files/functions/generated inputs, not calls or
the original suite universe; their PASS labels must not be added to receipts.

| Suite | Source rows | Recorded dispositions |
|---|---:|---|
| CHIPS | 5,321 | PASS2,416; NOT_RUN2,886; BLOCKED10; UNKNOWN9 |
| ACT | 4,074 | PASS1,917; REFERENCE_ERROR2; UNKNOWN2,155 |
| RVV-ATG | 365 | PASS185; NOT_RUN166; BLOCKED14 |
| Ara | 1,057 | PASS276; NOT_RUN420; BLOCKED61; BUILD_ERROR20; N/A276; RESULT_MISMATCH4 |
| SiFive RIF | 4,086 | PASS2,151; BUILD_ERROR723; BLOCKED_SHARED_PLATFORM989; BLOCKED108; OPTIONAL_EXTENSION_UNSUPPORTED50; RV32_INDEX_EEW64_NA64; PLATFORM_ERROR1 |

Ara reconciliation: final ledger **4,685 = 2,255 historical +2,430
SCOPED_ACCEPTANCE** rows. The historical summary's947 DUT registrations cover
911 PASS +36 mismatches across candidates; another40 baseline DUT attempts have
BLOCKED dispositions but actual raw/exit evidence. Baseline physical receipts
therefore comprise619 clean961 DUT +368 historical2af5 DUT +166 references.
The scoped bindings resolve to1,769 physical overlay receipts (1,417 DUT +352
references), not2,430 calls; the16 MAC bindings recheck existing failing baseline
receipts. Ara89's eight preliminary reference failures add eight further distinct
historical calls outside the valid overlay queue. Thus the receipt partitions
above use2,036 clean961 DUT,368 historical DUT and526 references. **This is a
registered-receipt accounting scope, not an exhaustive all-time total:** Task85
also retains separate8 DUT/2 Spike reproductions outside these bindings; their
scoped raw joins are absent here, so they are disclosed separately and not guessed
into the deduplicated count.

Tasks82–89 retain original vs derivative distinctions: Task82 adds nine diagnostic
M1/M2/BOTH full-file calls and reuses six B/Spike receipts; Task83's30 form bindings
share20 calls in four legacy-macro derivative programs (eight functions executed,
12 of20 original function obligations unexecuted). Tasks84/85/86's1,465 current FP
block/arm receipts cover293 blocks,291 all-five PASS and two DUT-rejected reserved
overlap blocks. The80 old context receipts remain separate history: five raw PASS
and75 mismatches, none admitted. Task86's80 repair calls replace the accepted scope
of16 old blocks; the277 reused blocks do not become new calls. Ara89 extracts166
original blocks into39 programs:830 bindings share195 PASS receipts (156 DUT,
39 Spike); eight earlier Spike failures make47 recorded references. Its81 excluded
blocks are skipped obligations, not81 failed executions. Ara422 is the final
direct checked-form set, not a count of calls or whole-file passes.

Concrete retained checker/source pointers below are relative to author evidence
root `artifacts/rvv_validation_delivery_20261009/` unless otherwise stated. These
are separately retained artifacts, not promises of public availability.

| Suite | Original checker, retained source/adapter and scope |
|---|---|
| ACT | `act-generation53/common/upstream/env/` and `common/user_env/signature.h`; pinned `riscv-arch-test-act4/framework/src/act/sig_modify.py`; `act-generation53/execute.compute.py.txt` records Sail capture, signature conversion and exactly one original TEST PASSED/no TEST FAILED/exit0 predicate. Original generated `.S` under `generated/rv32i/`; Linux adapter under `common/user_env/`. BASE selects element0/bit0 or scalar, LEN checks its recorded destination extent/tail rules, selected FFLAGS/CSR checks; no universal whole-state observer. Task53 has7,504 clean961 PASS, plus416 retained clean961 PASS; prior256 historical2af5 and160 historical-f8123 PASS stay separate. |
| RVV-ATG | `atg-integration61/isolated/` retains original generated target bodies/signature macros; `atg-integration61/adapt.py` and `adapter/env/` retain Linux entry/halt/link adaptation; `reference.py` retains independent Spike signature capture; `run_queue.py` records the byte comparison. Task62 original bodies are `atg-generation62/outputs/*/first/body.S`, with `OUTPUT_MANIFEST.json` and the ledger's `checked_state`/`checker_scope` for output/store scope. Frozen e32m1 plus limited e64 profile; only written signatures are target-checked; low32 extraction/helpers are coupled. The two reserved-input reference rejects and producer contract blockers are not arithmetic PASS. |
| Ara | Original sources `external_suite_coverage_20261007/ara/raw/source/apps/riscv-tests/isa/rv64uv/*.c`, with original typed VCMP/scalar/flags predicates and retained macro headers. `ara-remainder52/adapt_shared.py` preserves shared-context adapters; Tasks82–89 retain `adapter/*.c`, `checker.py`, `CONFIGS.json`, `BUILD_COMMANDS.json` and exact raw results. [Task91 bundle](ara-review-task91/README.md) supplies concrete package-relative original source/header/adapter/checker paths in `BINDINGS.json`/`PATHS.json`. Source/ELF identities, not opcode names, select context. Original short buffers, stale checker entries, FP16/RV64 profile blockers, invalid contexts and whole-file failures remain disclosed. M1/M2 admission is not inferred from PASS. |
| SiFive RIF | `rif-generation64/Graph_compiled_source.cpp` retains the producer; per-root `outputs/*/original.c` retains unchanged `golden_*` predicates and `PREDICATES_FROZEN.json`; `rif-generation64/execute.py` invokes the retained comparator in `harness.py`. `rif-interface67/verify.py`, `policy-preserved/verify.py` and their `outputs/` retain official API adapters, originals and ordered-report checks; `rif-reductions75/outputs/*/derived.c` retains explicit operand/masked-suffix repairs. One root/500 inputs/one seed, RV32GV ilp32d, VLEN128/ELEN64. Golden operation equality and ordered reports/exit0 are checked; initialization reports are vacuous, helper opcodes coupled. |

RIF cohort receipts are1,624 Task64 +1,932 Task65 +2,444 Task67 O2 interface
+2,172 Task67 O0 policy-preserved correction +432 Task75 repaired scalar endpoints.
All are raw PASS observations, but the543 O2 ELFs /2,172 receipts stay quarantined;
O0 receipts are distinct corrected executions. Task75's original108 source errors
remain blocked, and its repaired endpoints do not establish independent form
checks (host scalar model reads uninitialized allocation;24 absorbing-zero checks
lack target dependence). Final RIF direct forms200 and coupled endpoints125
overlap; do not sum them. Same-ELF QEMU registrations are611 O2 diagnostic,
543 corrected and108 repaired-endpoint receipts. The old1,370 reference registration
field additionally included108 compiler stdout records with reference_status
NOT_RUN; this report excludes them without rewriting immutable inputs.

References are incomplete registrations. CHIPS primary **DUT executions** comprise
**11,532 positive + 212 controls per candidate** (clean961 and historical2af5),
already included in the DUT partitions above. These are not reference executions
or crosschecks. The ledger's **60 explicit additional reference receipts** are
separate; producer reference counts are not inferred. CHIPS full local scope also
has Task47 supplements and Task54 outputs/profiles. Do not replace those cohorts
with primary-package counts or count the primary DUT executions twice. See [primary inspection](chips-review-task93/README.md)
and its `RECEIPT_MAPPING.json`, `SOURCE_CHAIN.json` and retained
`tools/runner.original.py` (`classify`). Original upstream TEST_CASE expected words,
selected destination/store/CSR checks, stage1/stage2 sources, captured patches and
pspike/merger commands are preserved. ELEN64 adaptations and storage derivatives
retain distinct identities; eight original unsafe stores have 32 prelaunch
BLOCKED DUT cells, not calls. Other producer/capture references are not inferred.

Top-level `ACTUAL_FORM_VALIDATION_SUMMARY.json.DUT_calls = 0` (and reference/compiler
calls zero) means that **this offline integration made zero new calls**. It does
not erase prior executions. No suite/stage totals or unsupported percentages are
added; direct target checks and coupled endpoints overlap. Raw PASS observations
include diagnostic/quarantined results that cannot enlarge accepted form sets.

## Exact reproduction

Run the following Python block on xbd with Python 3; it reads only canonical
ledger/bindings/projection/summary metadata, never bulk raw stdout, ELFs or source.
From a checkout, extract and send this block using:

```sh
python3 - <<'EXTRACT' | ssh xbd python3 - > /tmp/suite-execution-summary.json
from pathlib import Path
s = Path('docs/rvv-validation/suite-execution-summary.md').read_text()
print(s.split('```python\n', 1)[1].split('\n```', 1)[0])
EXTRACT
cmp docs/rvv-validation/suite-execution-summary.json /tmp/suite-execution-summary.json
```

```python
import collections, csv, hashlib, json
from pathlib import Path

root = Path('/home/vick/rvv-task90/task90')
names = ['CHIPS', 'ACT', 'RVV-ATG', 'Ara', 'SiFive RIF']
csv.field_size_limit(64 * 1024 * 1024)
unknown = {'', 'UNKNOWN', '待查', 'not executed'}
def locator(s):
    return 'artifacts/' + s.split('/artifacts/', 1)[1] if '/artifacts/' in s else s
def numeric(s):
    try:
        int(s)
        return True
    except (ValueError, TypeError):
        return False
def digest(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()
inputs = ['SUITE_RUN_MANIFEST.csv', 'ACTUAL_FORM_VALIDATION_BINDINGS.csv',
          'ACTUAL_FORM_VALIDATION_SUMMARY.json', 'compact-input.json']
summary = json.loads((root / inputs[2]).read_text())
e = json.loads((root / inputs[3]).read_text())['ara_evidence']
rows = list(csv.DictReader((root / inputs[0]).open()))
selected = {r['row_id']: r for r in rows if r['suite'] in names}
assert len(selected) == sum(r['suite'] in names for r in rows)
bindings = collections.defaultdict(collections.Counter)
for b in csv.DictReader((root / inputs[1]).open()):
    if b['suite'] in names:
        assert b['ledger_row_id'] in selected
        bindings[b['suite']][b['binding']] += 1
calls = {}
def add(suite, cohort, candidate, arm, vlen, status, raw, pointer):
    role = 'reference' if candidate.startswith('reference:') or arm.startswith('reference') else 'DUT'
    key = (suite, role, locator(raw))
    record = dict(suite=suite, cohort=cohort, candidate=candidate, role=role,
                  arm=arm, VLEN=vlen, status=status, pointer=pointer)
    if key in calls:
        assert calls[key]['status'] == status, ('conflicting receipt', key)
    else:
        calls[key] = record
observations = collections.defaultdict(collections.Counter)
for r in selected.values():
    observations[(r['suite'], r['cohort'], r['candidate'], r['row_kind'])][r['dut_status']] += 1
    support = (r['row_kind'] == 'SOURCE_SUPPORT'
               and r['reference_identity'].startswith('QEMU11.1-same-ELF:')
               and r['reference_status'] != 'NOT_RUN'
               and '/qemu/' in r['raw_stdout'])
    if r['row_kind'] not in {'EXECUTION', 'HARNESS_CONTROL'} and not support:
        continue
    if r['raw_stdout'] in unknown or not numeric(r['returncode']):
        continue
    pointer = {k: r[k] for k in ['row_id', 'source_file', 'adapter', 'checker_identity',
                                'raw_stdout', 'result_evidence']}
    add(r['suite'], r['cohort'] + (':controls' if r['row_kind']=='HARNESS_CONTROL' else ''),
        'reference:QEMU-same-ELF' if support else r['candidate'],
        'reference' if support else r['arm'], r['VLEN'],
        r['reference_status'] if support else r['dut_status'], r['raw_stdout'], pointer)
for b in e['bindings']:
    if 'raw_root' not in b:
        assert b['scope'] == 'TEST_CASE1_2_ONLY'
        assert b['original_binding']['ledger_row_id'] in selected
        continue  # Existing failing whole-file receipts, scoped recheck only.
    raw = b['raw_result']
    assert numeric(raw['returncode'])
    status = raw.get('status', b['result'].get('status'))
    add('Ara', b['task'] + ':' + b['scope'],
        'reference:Spike-overlay' if b['arm']=='reference' else 'clean961',
        b['arm'], str(raw.get('VLEN', 'UNKNOWN')), status,
        b['raw_root'] + '/stdout',
        dict(identity=b['identity'], source={k:b['source'][k] for k in
             ['source_file','source_lines','source_sha256','file','functions'] if k in b['source']},
             adapter=b.get('artifacts', {}).get('adapter'),
             checker=b['checker'], config=b['config'], raw_root=b['raw_root']))
for h in e['ara89']['failed_history']:
    add('Ara', 'ara89:PRELIMINARY_REFERENCE_HISTORY', 'reference:Spike-overlay',
        'reference', 'UNKNOWN', h['result']['status'], h['root'] + '/stdout',
        dict(raw_root=h['root'], classification=h['classification']))
groups = collections.defaultdict(list)
for c in calls.values():
    groups[(c['suite'], c['cohort'], c['candidate'], c['role'])].append(c)
result = dict(canonical=str(root), new_calls=0,
    original_suite_universes={s: 'UNKNOWN' for s in names},
    input_sha256={n: digest(root/n) for n in inputs},
    receipt_groups=[dict(suite=k[0], cohort=k[1], candidate=k[2], role=k[3],
        distinct_receipts=len(g), statuses=dict(sorted(collections.Counter(c['status'] for c in g).items())),
        arms=sorted({c['arm'] for c in g}), VLEN=sorted({c['VLEN'] for c in g}),
        example=g[0]['pointer']) for k,g in sorted(groups.items())],
    ledger_observation_groups=[dict(suite=k[0], cohort=k[1], candidate=k[2], row_kind=k[3],
        statuses=dict(sorted(v.items()))) for k,v in sorted(observations.items())],
    binding_groups={s: dict(sorted(bindings[s].items())) for s in names},
    form_counts={s['suite']: s['counts'] for s in summary['suites'] if s['suite'] in names},
    historical_summary_registrations={s['suite']: {k:s[k] for k in ['ledger_rows',
        'registered_dut_receipt_rows','registered_reference_receipt_rows']}
        for s in summary['suites'] if s['suite'] in names},
    ara_audits=e['batch_counts'], ara89_unique_calls=e['ara89']['unique_calls'],
    ara89_parser_controls=e['ara89']['review']['negative_parser_controls'],
    limitations=['Receipt groups are registered observations, not exhaustive producer/reference calls.',
        'CHIPS primary 11,532 positive + 212 controls per candidate are DUT executions, already counted; 60 explicit additional reference receipts are separate. Producer reference counts are not inferred.',
        'Ara85 separate 8 DUT/2 Spike reproductions are outside these overlay bindings; do not guess joins.',
        'SOURCE_SUPPORT compiler stdout is excluded; explicit same-ELF QEMU requires reference status and /qemu/ locator.',
        'SCOPED_ACCEPTANCE and source/status rows are not additional calls.',
        'Raw PASS is not necessarily accepted direct form evidence.'])
print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
```
