"""Accepted Ara overlay for the existing compact scope exporter; offline only.

Frozen source inventories and raw outcomes are inputs, never output targets.
"""
import collections
import csv
import hashlib
import json
import re
from pathlib import Path

ARMS = {'reference', 'B', 'M1', 'M2', 'BOTH'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unique(rows, key):
    out = {}
    for row in rows:
        identity = key(row)
        if identity in out:
            raise ValueError('duplicate identity: ' + str(identity))
        out[identity] = row
    return out


def positive(rows):
    return {r['arm'] for r in rows} == ARMS and all(
        r.get('status', r.get('result', {}).get('status')) == 'PASS' for r in rows)


def integrate(data, root, canonical):
    csv.field_size_limit(64 * 1024 * 1024)
    inputs = {}
    def read(path):
        path = Path(path)
        inputs[str(path)] = sha(path)
        return json.loads(path.read_text())
    def rows(path):
        inputs[str(path)] = sha(path)
        with path.open(newline='') as f:
            return list(csv.DictReader(f))
    reviews = {n: read(root / f'ara{n}/MAIN_REVIEW.json') for n in range(82, 87)}
    read(root / 'ara86/CASE_CONTEXT_AUDIT.json')
    inputs[str(root / 'ara85/MAIN_SOURCE_REVIEW.md')] = sha(root / 'ara85/MAIN_SOURCE_REVIEW.md')
    changes = unique(read(root / 'ara86/CHANGED_CASES.json'), lambda r: r['name'])
    contexts = unique(read(root / 'ara86/CASE_CONTEXT_AUDIT.json'), lambda r: r['name'])
    maps = {}
    for task in ('ara84', 'ara85'):
        maps.update({name: (task, value) for name, value in unique(
            read(root / task / 'BLOCK_MAP.json'), lambda r: r['name']).items()})
    if len(maps) != 293 or set(maps) != set(contexts) or len(changes) != 16:
        raise ValueError('context/block identity mismatch')
    bindings = []
    def binding(task, name, arm, form, source, result, scope):
        # Keep exact producer records as well as locators and content identities.
        raw = result.get('raw_root') or result.get('raw_path')
        if not raw and result.get('raw_stdout'):
            raw = str(Path(result['raw_stdout']).parent)
        if not raw:
            raw = str(root / task / ('raw' if arm == 'reference' else 'remote-raw') / name / arm)
        base = Path(raw)
        if not (base / 'stdout').exists():
            base = root / task / 'raw' / name / arm
        for f in ('stdout', 'stderr', 'result.json'):
            if not (base / f).exists():
                raise ValueError('missing raw join: ' + str(base / f))
            inputs[str(base / f)] = sha(base / f)
        counters = re.findall(rb'multi_member_runs=(\d+)', (base / 'stderr').read_bytes())
        if any(int(x) for x in counters):
            raise ValueError('unexpected multi-member-M1 admission: ' + str(base))
        detail = read(base / 'result.json')
        retained = {}
        for f in ('command.json', 'IDENTITY.json', 'IDENTITY_AFTER.json', 'observations.json', 'case-results.json'):
            if (base / f).exists():
                retained[f] = read(base / f)
        for f in ('CONFIGS.json', 'BUILD_COMMANDS.json', 'REFERENCE_IDENTITY.json', 'COMPILER_RUNTIME_IDENTITY.json'):
            if (root / task / f).exists():
                inputs[str(root / task / f)] = sha(root / task / f)
        artifacts = {}
        for label, path in [('adapter',root / task / 'adapter' / (name+'.c')), ('elf',root / task / 'bin' / (name+'.elf'))]:
            if path.exists():
                artifacts[label] = dict(path=str(path), sha256=sha(path))
        if 'elf' in artifacts and detail.get('elf_sha256') and artifacts['elf']['sha256'] != detail['elf_sha256']:
            raise ValueError('ELF/raw identity mismatch: '+name)
        bindings.append(dict(artifacts=artifacts, identity=[task, name, arm, form], suite='Ara', task=task,
                             case=name, arm=arm, form=form, source=source, scope=scope,
                             result=result, raw_result=detail, retained_runtime=retained,
                             raw_root=str(base), raw_sha256={f: inputs[str(base / f)] for f in ('stdout','stderr','result.json')},
                             checker=str(root / task / 'checker.py'), checker_sha256=sha(root / task / 'checker.py'),
                             config=str(root / task / 'CONFIGS.json'), build=str(root / task / 'BUILD_COMMANDS.json'),
                             positive=result.get('status', result.get('result', {}).get('status')) == 'PASS' and scope != 'INVALID_CONTEXT_HISTORY',
                             multi_member_M1_counters=[int(x) for x in counters], multi_member_M1_admission=0))
    fp_outcomes = {}
    reused = unique(read(root / 'ara86/REUSED_RESULTS.json'), lambda r: r['name'])
    corrected = read(root / 'ara86/AUDITED_RESULTS.json')
    unique(corrected, lambda r: (r['case'], r['arm']))
    corrected_by = collections.defaultdict(list)
    for r in corrected:
        corrected_by[r['case']].append(r)
    if set(reused) & set(changes) or set(reused) | set(changes) != set(maps):
        raise ValueError('invalid-context/reuse partition')
    added = set()
    for name, (original_task, source) in maps.items():
        if name in changes:
            task, outcomes = 'ara86', corrected_by[name]
        else:
            task = reused[name]['task']
            outcomes = [dict(x['result'], arm=x['arm'], raw_root=str(Path(x['result_file']).parent)) for x in reused[name]['results']]
            for receipt in reused[name]['results']:
                p = Path(receipt['result_file'])
                if sha(p) != receipt['result_sha256'] or sha(p.parent / 'stdout') != receipt['stdout_sha256'] or sha(p.parent / 'stderr') != receipt['stderr_sha256']:
                    raise ValueError('reused raw binding changed')
        if len(outcomes) != 5 or {r['arm'] for r in outcomes} != ARMS:
            raise ValueError('missing/duplicate arm: ' + name)
        form = source['target']['form']
        fp_outcomes[name] = positive(outcomes)
        if fp_outcomes[name]: added.add(form)
        for result in outcomes:
            binding(task, name, result['arm'], form, source, result, 'EXTRACTED_FP32_64_BLOCK')
            bindings[-1]['positive'] = fp_outcomes[name]
    if sum(fp_outcomes.values()) != 291:
        raise ValueError('expected 291 valid all-five blocks')
    for name in changes:
        task, source = maps[name]
        for arm in sorted(ARMS):
            base = root / task / ('raw' if arm == 'reference' else 'remote-raw') / name / arm
            result = read(base / 'result.json')
            binding(task, name, arm, source['target']['form'], source, result, 'INVALID_CONTEXT_HISTORY')
    legacy_targets = read(root / 'ara83/TARGET_INSTRUCTIONS.json')
    legacy_results = read(root / 'ara83/EXECUTION_RESULTS.json')
    unique(legacy_results, lambda r: (r['case'], r['arm']))
    groups = unique(read(root / 'ara83/GROUPS.json'), lambda r: r['name'])
    for target in legacy_targets:
        form = target['emitted_opcode']
        if form == 'vpopc.m': form = 'vcpop.m'
        outcomes = [r for r in legacy_results if r['case'] == target['case']]
        if positive(outcomes): added.add(form)
        for result in outcomes:
            # Multiple functions of one form share a receipt, retain source group.
            identity = ['ara83', result['case'], result['arm'], form]
            if not any(b['identity'] == identity for b in bindings):
                binding('ara83', result['case'], result['arm'], form, dict(group=groups[result['case']], targets=[t for t in legacy_targets if t['case']==result['case']]), result, 'LEGACY_MACRO_DERIVATIVE')
    reduction_results = read(root / 'ara82/EXECUTION_RESULTS.json')
    reduction_groups = unique(read(root / 'ara82/GROUPS.json'), lambda r: r['name'])
    targets = rows(canonical / 'ara/ASSERTION_TARGETS.csv')
    for result in reduction_results:
        g = reduction_groups[result['case']]
        forms = {t['form'] for t in targets if Path(t['path']).stem == g['file'] and t['function'] in g['functions'] and t['role']=='assertion_target'}
        for form in forms:
            binding('ara82', result['case'], result['arm'], form, g, result, 'ORIGINAL_FULL_FILE_MISSING_CONFIG')
    # Scoped MAC forms come from assertion targets, never from case names.
    old_bindings = rows(canonical / 'ACTUAL_FORM_VALIDATION_BINDINGS.csv')
    for reviewed in reviews[82]['scoped_mac_recheck']:
        matches = [b for b in old_bindings if b['suite']=='Ara' and b['source_case']==reviewed['case'] and b['arm']==reviewed['arm']]
        if len(matches) != 1: raise ValueError('MAC ledger join: '+str(reviewed))
        b = matches[0]
        file = Path(b['source_file']).stem
        selected = [t for t in targets if Path(t['path']).stem==file and t['function'] in reviewed['accepted_functions'] and t['role']=='assertion_target']
        if not selected: raise ValueError('missing scoped MAC target')
        for form in {t['form'] for t in selected}:
            added.add(form)
            # Original raw files remain FAIL; acceptance is function scoped.
            bindings.append(dict(identity=['ara82_scoped_mac',b['ledger_row_id'],form], suite='Ara',form=form,scope='TEST_CASE1_2_ONLY', positive=True, whole_file=reviewed['whole_file'], preserved_failures='TEST_CASE3/4', source_targets=selected, original_binding=b, review=reviewed, multi_member_M1_admission=0))
    unique(bindings, lambda b: tuple(b['identity']))
    suite = next(s for s in data['suites'] if s['suite']=='Ara')
    old = set(suite['result_checked'])
    names = {r['form'] for r in data['forms'] if r['applicability']=='REQUIRED'}
    if added - names: raise ValueError('unknown/excluded joined form: '+str(added-names))
    new = old | added
    suite['result_checked'] = sorted(new)
    frozen_source = {r['form'] for r in rows(root / 'ara82/FORM_RECONCILIATION.csv')}
    # Versioned derived correction: frozen inventory incorrectly gates gather16
    # as setup_explicit despite the immediate destination comparison.
    outside = read(root / 'ara82/ACCEPTED_OUTSIDE_SOURCE_SET.json')
    gather = outside['opcode_records']
    source_path = canonical / 'ara/raw/source' / gather[0]['path']
    inputs[str(source_path)] = sha(source_path)
    source_lines = source_path.read_text().splitlines()
    if 'vrgatherei16.vv' not in source_lines[112] or 'VCMP_U32' not in source_lines[113]:
        raise ValueError('gather source/checker adjacency changed')
    if not gather: raise ValueError('missing gather source classification proof')
    source = frozen_source | {'vrgatherei16.vv'}
    dispositions = []
    reconciliation = {r['form']:r for r in rows(root / 'ara82/FORM_RECONCILIATION.csv')}
    for form in sorted(source - old):
        r = reconciliation.get(form, {})
        disposition = 'ACCEPTED_SCOPED' if form in new else r.get('category','SOURCE_BLOCKED')
        remaining = r.get('next_action')
        if form == 'vfwadd.wv':
            disposition = 'RESERVED_SOURCE_EEW_OVERLAP'
            remaining = 'Two extracted e32 blocks rejected by DUT; Spike PASS is not arithmetic PASS. Original FP16 mixed file remains blocked.'
        elif form in new:
            remaining = 'Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded.'
        dispositions.append(dict(form=form, disposition=disposition,
                                 source_statuses=r.get('source_statuses'), source_lines=r.get('source_lines'),
                                 remaining=remaining, bindings=[i for i,b in enumerate(bindings) if b['form']==form and b['positive']],
                                 whole_file_pass=False))
    summary = read(canonical / 'ACTUAL_FORM_VALIDATION_SUMMARY.json')
    ledger = rows(canonical / 'SUITE_RUN_MANIFEST.csv')
    suite_counts = []
    for s in summary['suites']:
        selected = [r for r in ledger if r['suite']==s['suite']]
        stages = next(x for x in data['suites'] if x['suite']==s['suite'])
        suite_counts.append(dict(suite=s['suite'], form_denominator=595, result_checked_forms=len(stages['result_checked']), coupled_endpoint_forms=len(stages['coupled_endpoint']),
                                source_case_rows=s['source_case_rows'], registered_DUT_receipt_rows=s['registered_dut_receipt_rows'], registered_reference_receipt_rows=s['registered_reference_receipt_rows'],
                                ledger_rows=len(selected), ledger_status_rows=dict(collections.Counter(r['dut_status'] for r in selected)),
                                original_upstream_case_denominator='UNKNOWN; ledger SOURCE_CASE rows are scoped registrations, not upstream suite totals',
                                accepted_overlay_receipt_bindings=sum(b['suite']==s['suite'] for b in bindings),
                                units='forms; SOURCE_CASE ledger rows; registered receipt rows; status ledger rows; overlay form/receipt bindings (not unique calls)'))
    diff = dict(old=sorted(old), new=sorted(new), added=sorted(new-old), removed=sorted(old-new), frozen_source_forms=len(frozen_source), derived_source_forms=len(source), source_only_old=sorted(source-old), source_only_new=sorted(source-new), accepted_only_new=sorted(new-source))
    batch_counts = {str(n): read(root / f'ara{n}/AUDIT.json') for n in range(82,87)}
    data['snapshot'] = 'Task87 accepted Ara overlay on Task76 / recorded October 7 routes'
    data['ara_evidence'] = dict(batch_counts=batch_counts, diff=diff, bindings=bindings, dispositions=dispositions, suite_counts=suite_counts, inputs=inputs,
        source_mapping=dict(version=87, form='vrgatherei16.vv', classification='setup_explicit → assertion_target; destination v4 compared by VCMP_U32 at line114 after target at113', frozen_inventory_modified=False, original_targets=gather),
        fp_blocks=dict(total=293, all_five_pass=291, reserved_overlap_failures=sorted(k for k,v in fp_outcomes.items() if not v), invalid_context_history_blocks=16, invalid_context_history_receipts=80),
        limitations=['No mixed FP16 whole-file PASS', 'Legacy adapters are explicit derivatives', 'MAC TEST_CASE3/4 failures retained', 'Zero multi-member-M1 admission', 'Form union is not configuration completeness', 'Masked FP source blocks may overread two-byte mask objects; no access-suppression proof'],
        new_DUT_executions=0)
    return data


def render_evidence(e):
    d=e['diff']
    lines=[f"# Accepted Ara evidence integration (Task{e.get('version',87)})", '',
           f"Ara checked forms: {len(d['old'])} → {len(d['new'])}; added {len(d['added'])}; removed {len(d['removed'])}.", '',
           'Exact additions: '+', '.join('`'+f+'`' for f in d['added']), '',
           'Frozen source set '+str(d['frozen_source_forms'])+'; version87 derived source set '+str(d['derived_source_forms'])+'. Frozen inventory is unchanged.', '',
           '293 extracted FP blocks: 291 all-five PASS; two reserved source-EEW-overlap failures. The 16 old RTZ-omitted blocks / 80 receipts remain invalid-context history.', '',
           '\n'.join(e['limitations']), '',
           'Bindings and content identities are in compact-input.json → ara_evidence. Accepted Ara raw/source inspection is packaged in [Task91 review bundle](../ara-review-task91/README.md); its BINDINGS.json supplies package-relative navigation. Historical absolute paths remain provenance. Canonical full-suite archives remain separate.', '',
           '| Suite | Checked forms /595 | Endpoint forms /595 | Source-case rows | Registered DUT receipts | Registered reference receipts | Ledger rows |',
           '|---|---:|---:|---:|---:|---:|---:|']
    for s in e['suite_counts']:
        lines.append(f"| {s['suite']} | {s['result_checked_forms']} | {s['coupled_endpoint_forms']} | {s['source_case_rows']} | {s['registered_DUT_receipt_rows']} | {s['registered_reference_receipt_rows']} | {s['ledger_rows']} |")
    lines += ['', '| Task | Recorded new DUT calls | Recorded new reference calls | Audit denominator |', '|---|---:|---:|---|']
    for task,a in e['batch_counts'].items():
        dut=a.get('DUT_calls',a.get('actual_DUT_calls',a.get('new_calls')))
        ref=a.get('reference_calls',a.get('actual_reference_calls',0))
        denominator=a.get('eligible_blocks',a.get('planned_blocks',a.get('changed_blocks',a.get('original_build_obligations','three original full files'))))
        lines.append(f'| {task} | {dut} | {ref} | {denominator} |')
    lines += ['', 'Task83 denominator: 20 function obligations / six files; eight functions executed in four derivative programs. Tasks84/85/86: extracted blocks. Task85 includes invalid-context history; Task86 repairs 16 blocks. Task82 reuses six B/Spike receipts. Task85 also retains separate 8 DUT/2 Spike reproductions.', '', '| Suite | Status unit | Denominator | Exact recorded status counts |', '|---|---|---:|---|']
    for s in e['suite_counts']:
        lines.append('| '+s['suite']+' | original ledger rows (all row kinds) | '+str(s['ledger_rows'])+' | '+json.dumps(s['ledger_status_rows'],sort_keys=True)+' |')
    lines += ['', 'Upstream suite case denominators are UNKNOWN. Source-case/receipt/status rows are different units. Overlay bindings are scoped acceptance records, not new call totals.', '', '| Source-only relative to old accepted set | Finite disposition | Source status | Remaining source obligation |', '|---|---|---|---|']
    for r in e['dispositions']:
        lines.append('| '+' | '.join(str(r.get(k) or 'See frozen source record').replace('|','\\|') for k in ('form','disposition','source_statuses','remaining'))+' |')
    if 'ara89' in e:
        a=e['ara89']
        lines += ['', 'Task90 checkpoint: Ara396 →422; exactly26 additions, no removals. Task87 cumulative baseline remains301.', '',
                  'Ara89:166 original blocks /39 programs;830 block/arm bindings share195 valid receipts (156 DUT +39 reference). Eight failed preliminary Spike calls remain separate:47 actual references,203 total recorded calls. Zero new calls in this integration.', '',
                  'Ara89 exact additions: '+', '.join('`'+f+'`' for f in a['checkpoint_diff']['added']), '',
                  'Main reviewed166 preserved blocks,195 raw receipts and390 rejection controls. These controls are reused, not rerun by Task90. Whole-file PASS, multi-member M1 and M2 fast admission are not established.', '',
                  'M2 target admission: UNOBSERVED/null. RVV_FAST reads rvv_fast::g_fast (dbt/elfrun.cpp:2071); the distinct RVV_ACTIVE_CHUNKS census (2144) was not enabled. Zero FAST counters cannot establish zero M2 runtime-bounds admission.', '',
                  'All247 finite block dispositions, including81 exclusions and source limitations, and eight preliminary build identities are retained in compact-input.json → ara_evidence.ara89.']
    return '\n'.join(lines)+'\n'


def validate_evidence(data):
    e=data['ara_evidence']
    unique(e['bindings'], lambda b:tuple(b['identity']))
    invalid=[b for b in e['bindings'] if b['scope']=='INVALID_CONTEXT_HISTORY']
    if len(invalid)!=80 or any(b['positive'] for b in invalid):
        raise ValueError('invalid-context evidence admitted')
    failed=set(e['fp_blocks']['reserved_overlap_failures'])
    if any(b['positive'] for b in e['bindings'] if b.get('case') in failed):
        raise ValueError('reserved overlap counted as arithmetic PASS')
    if any(b['multi_member_M1_admission'] for b in e['bindings']):
        raise ValueError('multi-member admission claim')
    old=set(e['diff']['old'])
    new=old | {b['form'] for b in e['bindings'] if b['positive']}
    if new!=set(e['diff']['new']) or new-old!=set(e['diff']['added']):
        raise ValueError('form/binding join mismatch')
    if 'ara89' in e:
        a=e['ara89']; checkpoint=a['checkpoint_diff']
        selected=[b for b in e['bindings'] if b.get('task')=='ara89']
        remaining={'vfwadd.wv','vnsra.wv','vnsrl.wv','vssseg3e8.v','vssseg3e32.v'}
        if (len(checkpoint['old']),len(checkpoint['new']),len(checkpoint['added']),len(selected)) != (396,422,26,830):
            raise ValueError('Ara89 exact additions/bindings mismatch')
        if set(checkpoint['new']) != new:
            raise ValueError('Ara89 cumulative/checkpoint mismatch')
        if checkpoint['removed'] or set(checkpoint['new']) != set(checkpoint['old']) | set(checkpoint['added']):
            raise ValueError('Ara89 checkpoint removal/join mismatch')
        if set(e['diff']['source_only_new'])!=remaining or remaining & new:
            raise ValueError('Ara89 source-only exclusion violated')
        if len(a['failed_history'])!=8 or any(h['positive'] for h in a['failed_history']):
            raise ValueError('Ara89 failed history admitted')
        if any(b.get('whole_file_pass') or b.get('M2_fast_admission') is not None or b.get('M2_target_admission_status') != 'UNOBSERVED' for b in selected) or a.get('M2_fast_admission') is not None or a.get('M2_target_admission_status') != 'UNOBSERVED':
            raise ValueError('Ara89 whole-file/optimized admission claim')
        grouped=collections.defaultdict(list)
        for b in selected: grouped[b['source']['block']].append(b)
        if len(grouped)!=166 or any(len(v)!=5 or {b['arm'] for b in v}!=ARMS or not all(b['positive'] for b in v) for v in grouped.values()):
            raise ValueError('Ara89 incomplete five-arm block bindings')
        if len({b['raw_root'] for b in selected})!=195 or {b['form'] for b in selected} != set(checkpoint['added']):
            raise ValueError('Ara89 call/form join mismatch')
    ara=next(s for s in data['suites'] if s['suite']=='Ara')
    if set(ara['result_checked'])!=new:
        raise ValueError('suite membership mismatch')


def export_canonical(data, canonical, output):
    """Derived edition of the existing ledger/bindings/table schemas."""
    csv.field_size_limit(64*1024*1024)
    e=data['ara_evidence']
    def load_csv(name):
        with (canonical/name).open(newline='') as f: return list(csv.DictReader(f))
    def write_csv(name, records):
        with (output/name).open('w',newline='') as f:
            w=csv.DictWriter(f,list(records[0]),lineterminator='\n')
            w.writeheader(); w.writerows(records)
    old=load_csv('ACTUAL_FORM_VALIDATION_BINDINGS.csv')
    fields=list(old[0]); overlay=[]
    version=e.get('version',87)
    export_bindings=[b for b in e['bindings'] if b.get('task')=='ara89'] if version==90 else e['bindings']
    for index,b in enumerate(e['bindings']):
        if version==90 and b.get('task')!='ara89':
            continue
        link='compact-input.json#ara_evidence.bindings['+str(index)+']'
        base=b.get('raw_root'); result=b.get('raw_result',{}); source=b.get('source',{})
        r={k:'UNKNOWN' for k in fields}
        r.update(ledger_row_id=hashlib.sha256(json.dumps(b['identity']).encode()).hexdigest(), ledger_row_kind='SCOPED_ACCEPTANCE',suite='Ara',candidate='clean961',
                 source_case=b.get('case',b.get('original_binding',{}).get('source_case')),arm=b.get('arm',b.get('original_binding',{}).get('arm')),
                 source_file=source.get('source_file',link+'.source'),source_status=b['scope'],adapter=b['scope'],target_forms=b['form'],emitted_forms=b['form'],
                 result_checked_forms=b['form'] if b['positive'] else '',coupled_endpoint_forms='',result=result.get('status',b.get('whole_file','UNKNOWN')),
                 acceptance='INVALID_CONTEXT_HISTORY' if b['scope']=='INVALID_CONTEXT_HISTORY' else 'ACCEPTED_SCOPED' if b['positive'] else 'ORIGINAL_FAILURE_OR_BLOCKER',
                 binding=b['scope'],observed_state='Original typed equality predicates; finite scoped observations',checker_scope=b['scope'],remaining='; '.join(e['limitations']),
                 configuration_known_json=json.dumps(source.get('vsets',{}),sort_keys=True),configuration_evidence=link,command_evidence=link+'.retained_runtime',
                 checker_identity=b.get('checker','ara82/MAIN_REVIEW.json#scoped_mac_recheck'),elf_sha256=result.get('elf_sha256','UNKNOWN'),
                 result_evidence=base+'/result.json' if base else b['original_binding']['result_evidence'],
                 raw_stdout=base+'/stdout' if base else b['original_binding']['raw_stdout'],raw_stderr=base+'/stderr' if base else b['original_binding']['raw_stderr'])
        if 'original_binding' in b:
            for k in ('executable_sha256','library_sha256','elf_sha256','flags_json','reference_identity','configuration_known_json'):
                r[k]=b['original_binding'][k]
        if b.get('task')=='ara89':
            r['adapter']=b['artifacts']['adapter']['path']
            r['configuration_known_json']=json.dumps(dict(runtime=b['configuration'], profile=source['profile'], target=source['target']),sort_keys=True)
        runtime=b.get('retained_runtime',{}); identities=runtime.get('IDENTITY.json',{}); command=runtime.get('command.json',[])
        if isinstance(command,list) and command:
            r['executable_sha256']=identities.get(command[0],'UNKNOWN'); r['flags_json']=json.dumps(command[1:])
        libraries=[value for path,value in identities.items() if Path(path).name=='libdbtjitshared.so']
        if len(libraries)==1: r['library_sha256']=libraries[0]
        r['reference_identity']=link+'.retained_runtime; pinned same-ELF reference'
        overlay.append(r)
    old.extend(overlay); unique(old,lambda r:r['ledger_row_id'])
    write_csv('ACTUAL_FORM_VALIDATION_BINDINGS.csv',old)
    with (canonical/'SUITE_RUN_MANIFEST.csv').open(newline='') as src, (output/'SUITE_RUN_MANIFEST.csv').open('w',newline='') as dst:
        reader=csv.DictReader(src); writer=csv.DictWriter(dst,reader.fieldnames,lineterminator='\n'); writer.writeheader(); writer.writerows(reader)
        for b in overlay:
            row={k:b.get(k,'UNKNOWN') for k in reader.fieldnames}
            row.update(row_kind='SCOPED_ACCEPTANCE',row_id=b['ledger_row_id'],revision='Task87 derived accepted Tasks82–86' if version==87 else 'Task90 derived accepted Ara89 scoped bindings',cohort='accepted Ara integration',dut_status=b['result'],
                       accepted_historical_result=b['acceptance'],original_command=b['command_evidence'],source_inventory='compact-input.json#ara_evidence',
                       method_admission='zero multi-member-M1 admission; target-specific optimization UNOBSERVED',applicability='REQUIRED',checked_state=b['observed_state'],
                       next_command='portable full-file and actual M1/Both sequence replay',blocker=b['remaining'],owner=f'Task{version}',last_update='2026-10-12')
            writer.writerow(row)
    summary=json.loads((canonical/'ACTUAL_FORM_VALIDATION_SUMMARY.json').read_text()); ara=next(s for s in summary['suites'] if s['suite']=='Ara')
    ara['forms']['result_checked']=e['diff']['new']; ara['counts']['result_checked']=len(e['diff']['new'])
    for stage in ('source_present','compiled_source','emitted','program_executed'):
        ara['forms'][stage]=sorted(set(ara['forms'][stage]) | {b['form'] for b in e['bindings'] if b['scope']!='INVALID_CONTEXT_HISTORY'})
        ara['counts'][stage]=len(ara['forms'][stage])
    ara['forms']['failed_or_blocked']=sorted(set(ara['forms']['failed_or_blocked']) | {b['form'] for b in e['bindings'] if b['scope']=='EXTRACTED_FP32_64_BLOCK' and not b['positive']})
    ara['counts']['failed_or_blocked']=len(ara['forms']['failed_or_blocked'])
    stages={k:set() for k in ara['forms']}
    for b in export_bindings:
        if b['scope']=='INVALID_CONTEXT_HISTORY':
            stages['diagnostic_only'].add(b['form'])
            continue
        for stage in ('source_present','compiled_source','emitted','program_executed'):
            stages[stage].add(b['form'])
        stages['result_checked' if b['positive'] else 'failed_or_blocked'].add(b['form'])
    ara['candidates'].append(dict(candidate='clean961:accepted Tasks82–86 scoped bindings' if version==87 else 'clean961:Task90 accepted Ara89 scoped bindings',forms={k:sorted(v) for k,v in stages.items()},counts={k:len(v) if v else None for k,v in stages.items()}))
    ara['forms']['diagnostic_only']=sorted(set(ara['forms']['diagnostic_only']) | stages['diagnostic_only'])
    ara['counts']['diagnostic_only']=len(ara['forms']['diagnostic_only']) if ara['forms']['diagnostic_only'] else None
    ara['accepted_overlay']=dict(binding_rows=len(e['bindings']),positive_binding_rows=sum(b['positive'] for b in e['bindings']),registered_historical_counts_unchanged=True,fp_blocks=e['fp_blocks'])
    summary['derived_edition']=dict(task=version,original_summary_sha256=sha(canonical/'ACTUAL_FORM_VALIDATION_SUMMARY.json'),form_union_is_not_configuration_completeness=True)
    (output/'ACTUAL_FORM_VALIDATION_SUMMARY.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
    forms=load_csv('COMPLETE_FORM_SUITE_INVENTORY.csv')
    for r in forms:
        for stage,values in ara['forms'].items():
            if r['form'] in values: r['Ara_'+stage]='YES'
        r['Ara_actual_evidence']=f'ACTUAL_FORM_VALIDATION_BINDINGS.csv; historical rows plus version{version} scoped acceptance; compact-input.json#ara_evidence'
    write_csv('COMPLETE_FORM_SUITE_INVENTORY.csv',forms)
    (output/'ACTUAL_SUITE_FORM_LISTS.md').write_text(render_evidence(e))


def integrate89(data, root, canonical):
    """Join only reviewed Ara89 inputs onto the immutable Task87 snapshot."""
    e = data['ara_evidence']
    if e.get('version', 87) != 87:
        raise ValueError('Ara89 requires the Task87 input, not an already joined view')
    root = Path(root) / 'ara89'
    inputs = {}
    def pin(path):
        path = Path(path)
        inputs[str(path)] = sha(path)
        return path
    def read(name):
        return json.loads(pin(root / name).read_text())
    review = read('MAIN_REVIEW.json')
    sets = read('SCOPED_FORM_SETS.json')
    baseline = pin(Path(canonical) / 'compact-input.json')
    if sha(baseline) != sets['prior_compact_sha256']:
        raise ValueError('Ara89 immutable Task87 input identity mismatch')
    for header in sorted((root/'upstream').glob('*.h')):
        pin(header)
    for checker in ('checker.py','exact_check.py','initializer_check.py','extraction_guard.py'):
        pin(root/checker)
    queue = read('EXECUTED_BLOCK_QUEUE.json')
    dispositions = read('FINITE_BLOCK_DISPOSITIONS.json')
    detail_by = unique(dispositions, lambda r: r['id'])
    outcomes = read('AUDITED_RESULTS.json')
    audited = unique(outcomes, lambda r: (r['program'], r['arm']))
    reviewed = unique(review['rows'], lambda r: (r['program'], r['arm']))
    groups = unique(read('GROUPS.json'), lambda r: r['name'])
    preservation = unique(read('PRESERVATION.json'), lambda r: r['name'])
    configs = unique(read('CONFIGS.json'), lambda r: (r['case'], r['arm']))
    for name in ('RESULT.md', 'BUILD_COMMANDS.json', 'BUILD_IDENTITY.json', 'REFERENCE_IDENTITY.json',
                 'DUT_LAUNCH_COMMANDS.json', 'SOURCE_MAIN_AUDIT.json', 'COMPILED_INITIALIZATION_AUDIT.json',
                 'ASSEMBLY_SCALAR_AUDIT.json', 'INITIALIZATION_CHECK_CONTROLS.json',
                 'METHOD_ADMISSION.json', 'AGGREGATE_ADMISSION.json', 'BLOCKED_BLOCKS.md'):
        pin(root / name)
    old = set(next(s for s in data['suites'] if s['suite'] == 'Ara')['result_checked'])
    added = set(review['scoped_forms'])
    if (len(old), len(added), len(queue), len(audited), len(groups)) != (396, 26, 166, 195, 39):
        raise ValueError('Ara89 review cardinality mismatch')
    if old != set(sets['prior_accepted_forms']) or added & old or added != {b['form'] for b in queue}:
        raise ValueError('Ara89 prior/new form partition mismatch')
    if set(audited) != set(reviewed) or not all(r['original_predicates_pass'] for r in reviewed.values()):
        raise ValueError('Ara89 main review join mismatch')
    receipts = {}
    for key, outcome in audited.items():
        program, arm = key
        base = Path(outcome['raw_root'])
        raw_hashes = {f: sha(pin(base / f)) for f in ('stdout', 'stderr', 'result.json')}
        raw = json.loads((base / 'result.json').read_text())
        if not (outcome['status'] == raw['status'] == 'PASS' and raw['returncode'] == 0
                and outcome['same_ELF'] and outcome['original_checker_accepted']
                and outcome['exact_configurations_assertions_summary'] and outcome['identity_before_after_equal']):
            raise ValueError('Ara89 receipt not accepted: ' + str(key))
        for f in ('stdout', 'stderr'):
            if raw_hashes[f] != outcome[f + '_sha256']:
                raise ValueError('Ara89 raw hash mismatch')
        retained = {f: json.loads(pin(base / f).read_text()) for f in
                    ('command.json', 'IDENTITY.json', 'IDENTITY_AFTER.json', 'observations.json',
                     'case-results.json', 'initialization.json', 'exact-check.json') if (base / f).exists()}
        artifacts = {label: dict(path=str(pin(root / folder / (program + suffix))),
                                sha256=sha(root / folder / (program + suffix)))
                     for label, folder, suffix in [('adapter', 'adapter', '.c'), ('elf', 'bin', '.elf')]}
        if not (artifacts['elf']['sha256'] == outcome['elf_sha256'] == raw['elf_sha256']
                == configs[key]['elf_sha256'] == preservation[program]['elf_sha256']):
            raise ValueError('Ara89 ELF/build identity mismatch')
        if artifacts['adapter']['sha256'] != preservation[program]['source_sha256']:
            raise ValueError('Ara89 compiled source mismatch')
        counters = [int(x) for x in re.findall(rb'multi_member_runs=(\d+)', (base / 'stderr').read_bytes())]
        if any(counters): raise ValueError('unexpected Ara89 multi-member admission')
        receipts[key] = dict(artifacts=artifacts, raw_root=str(base), raw_result=raw, raw_sha256=raw_hashes,
                             retained_runtime=retained, result=outcome, configuration=configs[key],
                             preservation=preservation[program], multi_member_M1_counters=counters)
    bindings = []
    for block in queue:
        program = block['program']
        if not positive([audited[program, arm] for arm in ARMS]):
            raise ValueError('incomplete Ara89 five-arm block')
        source = Path(block['source_file'])
        if sha(pin(source)) != block['source_sha256']:
            raise ValueError('Ara89 immutable source mismatch')
        frozen = Path(detail_by[block['block']]['target']['source_absolute'])
        if sha(pin(frozen)) != block['source_sha256']:
            raise ValueError('Ara89 frozen source view mismatch')
        start, end = block['source_lines']
        text = ''.join(source.read_text().splitlines(keepends=True)[start-1:end])
        if hashlib.sha256(text.encode()).hexdigest() != block['block_sha256']:
            raise ValueError('Ara89 source range mismatch')
        for arm in sorted(ARMS):
            receipt = receipts[program, arm]
            if block['elf_sha256'] != receipt['artifacts']['elf']['sha256']:
                raise ValueError('Ara89 block/ELF mismatch')
            bindings.append(dict(receipt, identity=['ara89', block['block'], arm, block['form']],
                suite='Ara', task='ara89', case=program, arm=arm, form=block['form'],
                source=dict(block, target=detail_by[block['block']]['target'],
                            original_block=detail_by[block['block']]['original_block'],
                            group={k:groups[program][k] for k in ('name','file','functions','source_row_ids')}),
                scope='EXTRACTED_ORIGINAL_ARA89_BLOCK', positive=True, whole_file_pass=False,
                checker=str(root/'checker.py'), checker_sha256=sha(pin(root/'checker.py')),
                config=str(root/'CONFIGS.json'), build=str(root/'BUILD_COMMANDS.json'),
                multi_member_M1_admission=0, M2_fast_admission=None, M2_target_admission_status="UNOBSERVED"))
    history = read('HISTORY_CLASSIFICATION.json')
    historical_sources = read('HISTORICAL_SOURCE_IDENTITY.json')
    for h in history:
        base = Path(h['root'])
        h['raw_sha256'] = {f: sha(pin(base/f)) for f in ('stdout','stderr','result.json')}
        h['raw_result'] = json.loads((base/'result.json').read_text())
        h['positive'] = False
        h['compiled_historical_source'] = next(x for x in historical_sources if x['case']==h['result']['case'])
        name = h['result']['case']
        h['artifacts'] = {f: dict(path=str(pin(root/folder/(name+suffix))), sha256=sha(root/folder/(name+suffix)))
                          for f,folder,suffix in [('elf','bin','.elf')]}
        if h['raw_sha256']['stdout'] != h['stdout_sha256']:
            raise ValueError('Ara89 failed raw history changed')
        if h['artifacts']['elf']['sha256'] != h['result']['elf_sha256'] or h['raw_result']['returncode'] != 1:
            raise ValueError('Ara89 failed build identity mismatch')
    if len(history) != 8: raise ValueError('missing preliminary Spike history')
    new = old | added
    remaining = set(sets['remaining_source_only_forms'])
    if set(e['diff']['source_only_new']) - added != remaining or len(new) != 422:
        raise ValueError('Ara89 source-only partition mismatch')
    e['bindings'].extend(bindings)
    e['version'] = 90
    e['ara89'] = dict(review=review, audit=read('AUDIT.json'), historical_sources=historical_sources,
        failed_history=history, block_dispositions=dispositions, inputs=inputs,
        checkpoint_diff=dict(old=sorted(old), new=sorted(new), added=sorted(added), removed=[]),
        unique_calls=dict(programs=39, valid_DUT=156, valid_reference=39, failed_preliminary_reference=8,
                          actual_reference=47, valid_receipts=195, actual_receipts=203),
        block_arm_bindings=len(bindings), whole_file_pass=False, multi_member_M1_admission=0, M2_fast_admission=None, M2_target_admission_status="UNOBSERVED")
    e['diff'].update(new=sorted(new), added=sorted(new-set(e['diff']['old'])), source_only_new=sorted(remaining))
    e['batch_counts']['89'] = e['ara89']['audit']
    for row in e['dispositions']:
        if row['form'] in added:
            row.update(disposition='ACCEPTED_SCOPED', remaining='Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained.',
                       bindings=[i for i,b in enumerate(e['bindings']) if b['form']==row['form'] and b['positive']])
        elif row['form'] in remaining:
            blocked = [b for b in dispositions if b['target']['form']==row['form'] and b['blocker']]
            row.update(disposition='SOURCE_BLOCKED', remaining='; '.join(dict.fromkeys(b['blocker'] for b in blocked)),
                       exact_blockers=blocked)
    for suite in data['suites']:
        if suite['suite']=='Ara': suite['result_checked']=sorted(new)
    for suite in e['suite_counts']:
        if suite['suite']=='Ara':
            suite['result_checked_forms']=422
            suite['accepted_overlay_receipt_bindings']=len(e['bindings'])
    e['limitations'].extend(review['limits'])
    data['snapshot']='Task90 reviewed Ara89 overlay on immutable Task87 / recorded October 7 routes'
    validate_evidence(data)
    return data
