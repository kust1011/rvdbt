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
    lines=['# Accepted Ara evidence integration (Task87)', '',
           f"Ara checked forms: {len(d['old'])} → {len(d['new'])}; added {len(d['added'])}; removed {len(d['removed'])}.", '',
           'Exact additions: '+', '.join('`'+f+'`' for f in d['added']), '',
           'Frozen source set '+str(d['frozen_source_forms'])+'; version87 derived source set '+str(d['derived_source_forms'])+'. Frozen inventory is unchanged.', '',
           '293 extracted FP blocks: 291 all-five PASS; two reserved source-EEW-overlap failures. The 16 old RTZ-omitted blocks / 80 receipts remain invalid-context history.', '',
           '\n'.join(e['limitations']), '',
           'Bindings and content identities are in compact-input.json → ara_evidence. Raw locators require the retained research archive; these are not public downloads.', '',
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
    for index,b in enumerate(e['bindings']):
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
            row.update(row_kind='SCOPED_ACCEPTANCE',row_id=b['ledger_row_id'],revision='Task87 derived accepted Tasks82–86',cohort='accepted Ara integration',dut_status=b['result'],
                       accepted_historical_result=b['acceptance'],original_command=b['command_evidence'],source_inventory='compact-input.json#ara_evidence',
                       method_admission='zero multi-member-M1 admission; target-specific optimization UNOBSERVED',applicability='REQUIRED',checked_state=b['observed_state'],
                       next_command='portable full-file and actual M1/Both sequence replay',blocker=b['remaining'],owner='Task87',last_update='2026-10-12')
            writer.writerow(row)
    summary=json.loads((canonical/'ACTUAL_FORM_VALIDATION_SUMMARY.json').read_text()); ara=next(s for s in summary['suites'] if s['suite']=='Ara')
    ara['forms']['result_checked']=e['diff']['new']; ara['counts']['result_checked']=len(e['diff']['new'])
    for stage in ('source_present','compiled_source','emitted','program_executed'):
        ara['forms'][stage]=sorted(set(ara['forms'][stage]) | {b['form'] for b in e['bindings'] if b['scope']!='INVALID_CONTEXT_HISTORY'})
        ara['counts'][stage]=len(ara['forms'][stage])
    ara['forms']['failed_or_blocked']=sorted(set(ara['forms']['failed_or_blocked']) | {b['form'] for b in e['bindings'] if b['scope']=='EXTRACTED_FP32_64_BLOCK' and not b['positive']})
    ara['counts']['failed_or_blocked']=len(ara['forms']['failed_or_blocked'])
    stages={k:set() for k in ara['forms']}
    for b in e['bindings']:
        if b['scope']=='INVALID_CONTEXT_HISTORY':
            stages['diagnostic_only'].add(b['form'])
            continue
        for stage in ('source_present','compiled_source','emitted','program_executed'):
            stages[stage].add(b['form'])
        stages['result_checked' if b['positive'] else 'failed_or_blocked'].add(b['form'])
    ara['candidates'].append(dict(candidate='clean961:accepted Tasks82–86 scoped bindings',forms={k:sorted(v) for k,v in stages.items()},counts={k:len(v) if v else None for k,v in stages.items()}))
    ara['forms']['diagnostic_only']=sorted(set(ara['forms']['diagnostic_only']) | stages['diagnostic_only'])
    ara['counts']['diagnostic_only']=len(ara['forms']['diagnostic_only']) if ara['forms']['diagnostic_only'] else None
    ara['accepted_overlay']=dict(binding_rows=len(overlay),positive_binding_rows=sum(b['positive'] for b in e['bindings']),registered_historical_counts_unchanged=True,fp_blocks=e['fp_blocks'])
    summary['derived_edition']=dict(task=87,original_summary_sha256=sha(canonical/'ACTUAL_FORM_VALIDATION_SUMMARY.json'),form_union_is_not_configuration_completeness=True)
    (output/'ACTUAL_FORM_VALIDATION_SUMMARY.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
    forms=load_csv('COMPLETE_FORM_SUITE_INVENTORY.csv')
    for r in forms:
        for stage,values in ara['forms'].items():
            if r['form'] in values: r['Ara_'+stage]='YES'
        r['Ara_actual_evidence']='ACTUAL_FORM_VALIDATION_BINDINGS.csv; historical rows plus version87 scoped acceptance; compact-input.json#ara_evidence'
    write_csv('COMPLETE_FORM_SUITE_INVENTORY.csv',forms)
    (output/'ACTUAL_SUITE_FORM_LISTS.md').write_text(render_evidence(e))
