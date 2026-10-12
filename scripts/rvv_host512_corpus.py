"""Offline exact-call Task128/129 evidence union; never execute guests/references."""
import collections
import csv
import gzip
import hashlib
import json
import re
from pathlib import Path

ELFRUN = '849e6dd0a11e78d19319a2d04b93a644f4dd04e9fbc86dd8b350288392d655a3'
LIBRARY = '79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af'
REMOTE128 = '/home/vick/rvdbt-host512-task128'
REMOTE129 = '/home/vick/rvdbt-host512-task129'
RAW128 = Path('/home/user/research/materials/task128-host512-raw-20261013')
RAW129 = Path('/home/user/research/materials/task129-host512-raw-20261013')


def read(path):
    path = Path(path)
    return json.loads(gzip.decompress(path.read_bytes()) if path.suffix == '.gz' else path.read_bytes())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def identity(call):
    return json.dumps(call, sort_keys=True, separators=(',', ':'))


def require(ok, message):
    if not ok:
        raise ValueError(message)


def partition(original, prior, remaining):
    sets = [{identity(c) for c in q} for q in (original, prior, remaining)]
    require(all(len(s) == len(q) for s, q in zip(sets, (original, prior, remaining))), 'duplicate full call')
    require(not sets[1] & sets[2], 'Task128/129 overlap')
    require(sets[1] | sets[2] == sets[0], 'original exact-call union differs')
    return dict(original=len(sets[0]), task128=len(sets[1]), task129=len(sets[2]), intersection=0)


def validate_record(record, local, elfrun=ELFRUN, executable=REMOTE128 + '/build/bin/elfrun'):
    """Authenticate raw joins without fabricating timestamps or rerunning code."""
    pins = record['executable_pins']
    require(sorted(pins.values()) == sorted([elfrun, LIBRARY]), 'candidate identity')
    require(record['command'][0] == executable, 'pinned executable path')
    require(read(local/'IDENTITY.json') == pins, 'per-call identity')
    require(read(local/'command.json') == record['command'], 'raw command join')
    result = record['result']
    require(read(local/'result.json') == result, 'raw result join')
    for stream in ('stdout', 'stderr'):
        require(sha(local/stream) == result[stream+'_sha256'], 'stream identity')
    call = record['original_call']
    require(result['elf_sha256'] == call['elf_sha256'], 'ELF identity')
    flags = []
    for flag in record['command'][1:]:
        if flag.startswith('--fsroot='): flag = '--fsroot={WORK}/fs'
        elif flag.startswith('--cache='): flag = '--cache={WORK}/cache'
        elif flag.startswith(('--dump-tbmap=', '--dump-tbcode=')): continue
        flags.append(flag)
    require(flags == call.get('flags', call.get('normalized_flags')), 'original full flags')
    if record['suite'] == 'chips':
        require(read(local/'case.json') == call, 'CHIPS call identity')
        require(result['control'] == call['control'], 'CHIPS control identity')
        if result['status'] == 'PASS':
            require(result['returncode'] == call['expected_returncode'] and
                    (local/'stdout').read_bytes() == call['expected_stdout'].encode(), 'CHIPS predicate')
    elif record['suite'] == 'act':
        require(result['original_predicate_pass'] == (result['status'] == 'PASS'), 'ACT predicate disposition')
    else:
        scoped = call['scope'] == 'TEST_CASE1_2_ONLY'
        require(result['whole_file_pass'] == (result['accepted_scope_pass'] and not scoped), 'Ara whole-file scope')
        if scoped:
            require(result['status'] == 'SCOPED_PASS' and not result['whole_file_pass'], 'Ara scoped MAC')
        require(sha(local/'observer.json') == result['observer_sha256'], 'Ara observer identity')
    for name, digest in record['files'].items():
        require(sha(local/name) == digest, 'receipt file identity: '+name)


def write_readable_summary(summary, records, output):
    lines = ['# Exact Task128 host512 retained external corpus', '',
             '21,316 original calls = 5,904 actual Task128 receipts + 15,412 actual Task129 receipts. Full call identities are disjoint; Task128 calls were not repeated. All use the unchanged executable 849e6dd0… and matching library 79d0ba2a….', '',
             '| Suite | Original calls | Whole-file/registered PASS | Scoped PASS | Checked forms |',
             '|---|---:|---:|---:|---:|']
    for suite in ('chips','act','ara'):
        values=summary['counts'][suite]
        lines.append('|'+suite+'|'+str(summary['partition'][suite]['original'])+'|'+str(values.get('PASS',0))+'|'+str(values.get('SCOPED_PASS',0))+'|'+str(summary['checked_forms'][suite])+'|')
    lines += ['', 'The checked-form union is 595. CHIPS includes 11,532 positives and 212 separate controls. Ara includes 1,888 whole-file passes and the original 16 TEST_CASE1/2 MAC outcomes, each with whole_file_pass=false. ACT’s two original reference-blocked outputs remain outside its 7,668 accepted calls. Mismatch/crash/timeout/runner-error/unattempted accepted calls: zero.', '',
              'Each arm has 2,936 CHIPS calls (2,883 positives + 53 controls), 1,917 ACT calls, and 476 Ara calls (472 whole-file + four scoped). See [form navigation](FORMS.md) and [reader instructions](../README.md).', '',
              '| Suite | Actual guest VLEN command settings: distinct calls |', '|---|---|']
    for suite in ('chips','act','ara'):
        counts=collections.Counter(r['guest_vlen'] for r in records if r['suite']==suite)
        lines.append('|'+suite+'|'+'; '.join(str(v)+'='+str(n) for v,n in sorted(counts.items()))+'|')
    lines += ['', 'These VLEN settings are concrete commands, not a Cartesian set of observed runtime tuples. Original source SEW/LMUL/requested-VL/mask/tail/vstart literals and source/checker windows remain source evidence; current printed VL/vtype/scalar/CSR/checker observations stay separate. Missing runtime dimensions remain UNKNOWN.', '',
              'Enabled direct/M1/M2 flags, aggregate counters and program acceptance do not establish individual target-native admission. Task128’s specific target-PC observations retain guarded native, scalar and helper routes with their original limits. Its 14 focused host tests and eight exit-only helper controls are separate evidence, adding no external credit.', '',
              'This finishes the finite retained corpus on the exact build. It does not establish every semantic combination, complete state/suppression/history, general overlap/restart or unexpected native host-fault recovery. No guest handler return, mapping repair, same-PC retry, P4-04/equivalent or new reference was executed. Earlier failures/exclusions remain separately attributed; no production changes, push or issue closure.']
    (output/'SUMMARY.md').write_text('\n'.join(lines)+'\n')


def generate(docs, output, raw128=RAW128, raw129=RAW129):
    docs = Path(docs)
    original_paths = {'chips': docs/'host512-task129/original-chips-queue.json.gz',
                      'act': docs/'current-production-task121/QUEUE.json.gz',
                      'ara': docs/'current-production-task122/QUEUE.json.gz'}
    originals = {s: read(p) for s, p in original_paths.items()}
    ara_scope = read(docs/'current-production-task122/scope.json.gz')
    reviewed_ara = collections.defaultdict(set)
    for f in ara_scope['per_form']:
        for b in f['current_Ara']:
            reviewed_ara[b['id']].update(b['forms'].split(';'))
    receipts = read(docs/'host512-task128/RECEIPTS.json.gz') + read(docs/'host512-task129/RECEIPTS.json.gz')
    by_suite = collections.defaultdict(list)
    for r in receipts:
        by_suite[r['suite']].append(r)
    counts = {}; forms = collections.defaultdict(lambda: collections.defaultdict(list))
    bindings = {'chips': collections.defaultdict(list), 'act': collections.defaultdict(list)}
    csv.field_size_limit(64*1024*1024)
    for suite, task in [('chips',120),('act',121)]:
        with gzip.open(docs/f'current-production-task{task}/replay-receipts.csv.gz','rt') as f:
            for b in csv.DictReader(f):
                key = b['cell_id'] if suite=='chips' else (b['case'],b['arm'])
                bindings[suite][key].append(b)
    records = []; seen_receipts = set()
    for suite, original in originals.items():
        key = 'cells' if suite == 'chips' else 'calls'
        prior = read(docs/f'host512-task128/{suite}-queue.json.gz')[key]
        remaining = read(docs/f'host512-task129/{suite}-queue.json.gz')[key]
        counts[suite] = partition(original[key],prior,remaining)
        require({identity(r['original_call']) for r in by_suite[suite]} == {identity(c) for c in original[key]}, 'receipt union')
        require(len(by_suite[suite]) == len(original[key]), 'duplicate receipt call')
        for r in by_suite[suite]:
            remote = r['receipt']; task = 128 if remote.startswith(REMOTE128+'/') else 129
            prefix = REMOTE128 if task == 128 else REMOTE129
            require(remote.startswith(prefix+'/'), 'unknown raw root')
            local = (raw128 if task == 128 else raw129)/Path(remote).relative_to(prefix)
            require(remote not in seen_receipts, 'duplicate raw receipt'); seen_receipts.add(remote)
            validate_record(r,local)
            c = r['original_call']; arm = r['arm']
            if suite == 'chips':
                source_bindings = bindings[suite][c['id']]
                checked_forms = sorted({b['form'] for b in source_bindings if b['control']=='False'})
                require(source_bindings, 'CHIPS source/assertion join')
            elif suite == 'act':
                source_bindings = bindings[suite][c['case'],arm]
                checked_forms = sorted({b['form'] for b in source_bindings})
                require(source_bindings, 'ACT source/checker join')
            else:
                source_bindings = c['bindings']
                checked_forms = sorted({f for b in source_bindings for f in b['result_checked_forms'].split(';') if f})
                if not checked_forms:
                    # Task122 explicitly preserved three canonical Task52 B rows
                    # whose checked-form fields are empty; reviewed Task82 full-file
                    # bindings supply their accepted forms, without a new call.
                    require(c['case'] in ('context_original_vredsum','context_original_vwredsum','context_original_vwredsumu') and arm=='B', 'unexpected empty Ara binding')
                    checked_forms = sorted(reviewed_ara[c['id']])
                require(set(checked_forms) == set(c['forms']), 'Ara checked-form join')
            flags = c.get('flags',c.get('normalized_flags'))
            vlen = int(next(f.split('=')[1] for f in flags if f.startswith('--vlen=')))
            runtime = read(local/'observer.json') if suite=='ara' else {'target_SEW_LMUL_VL_mask_tail_vstart':'UNKNOWN; original checker completion is not a runtime tuple census'}
            row = dict(suite=suite,task=task,call_identity_sha256=hashlib.sha256(identity(c).encode()).hexdigest(),
                       id=c.get('id',c.get('case')),case=c.get('case'),arm=arm,guest_vlen=vlen,
                       control=c.get('control',False),forms=checked_forms,receipt=remote,local_receipt=str(local),
                       command=r['command'],result=r['result'],executable_pins=r['executable_pins'],
                       original_call=c,original_source_checker_bindings=source_bindings,
                       reviewed_Ara_scope_locator=('current-production-task122/scope.json.gz#'+c['id']) if suite=='ara' else None,
                       source_configuration_literals=([dict(selector=b.get('configuration_selector'),historical_known_configuration=json.loads(b['original_bindings_json'])) for b in source_bindings] if suite=='chips' else [dict(source_sew=b['sew'],literal_sites=b['literal_checker_sites']) for b in source_bindings] if suite=='act' else dict(vsets=c['metadata'].get('vsets',[]),assertions=c['metadata'].get('assertions',[]))),
                       observed_runtime=runtime,
                       configuration_interpretation='Guest VLEN is an actual command setting. Source configuration literals and historical binding fields remain source/historical evidence; absent runtime dimensions are UNKNOWN.',
                       admission='No per-target optimized admission inferred from flags, program PASS or aggregate route counters. Bounded target evidence remains Task128 TARGET_CODE.json.gz.')
            i=len(records);records.append(row)
            for form in checked_forms:
                forms[form][suite].append(i)
    require(len(records)==21316,'total calls')
    require(sum(r['control'] for r in records)==212,'CHIPS original controls')
    require(sum(r['result']['status']=='SCOPED_PASS' for r in records)==16,'original 16 MAC outcomes')
    blocked=[e for e in originals['act']['entries'] if e['original_status']=='REFERENCE_ERROR']
    require({e['case'] for e in blocked}=={'Vf32-vfmv.f.s','Vf64-vfmv.f.s'},'ACT original blockers')
    summary = dict(total=21316,task128=5904,task129=15412,partition=counts,
                   counts={s:dict(collections.Counter(r['result']['status'] for r in by_suite[s])) for s in originals},
                   per_arm={s:{a:dict(collections.Counter(r['result']['status'] for r in by_suite[s] if r['arm']==a)) for a in ('B','M1','M2','BOTH')} for s in originals},
                   control_counts=dict(collections.Counter(r['result']['status'] for r in records if r['control'])),
                   checked_forms={s:len({f for r in records if r['suite']==s for f in r['forms']}) for s in originals},
                   checked_union=len(forms),whole_file_mac_pass=0,scoped_mac=16,
                   new_guest_executions_by_this_reporter=0,unattempted=0,
                   local_host_tests='Separate Task128 FOCUSED_RESULTS.json; no external call credit',
                   limits='Finite retained cases, not every semantic combination; no native fault recovery, guest handler return/repair/retry or P4-04/equivalent validation.')
    index = dict(summary=summary,records=records,per_form={f:dict(v) for f,v in sorted(forms.items())},
                 original_ACT_reference_blockers=blocked,
                 source_context_files={name:sha(docs/'host512-task129'/name) for name in ('chips-source-geometry.csv.gz','chips-literal-config-contexts.json.gz')},
                 inputs={str(p):sha(p) for p in original_paths.values()})
    output.mkdir(parents=True,exist_ok=False)
    (output/'navigation.json.gz').write_bytes(gzip.compress(json.dumps(index,separators=(',',':')).encode(),mtime=0))
    lines = ['# Retained host512 forms', '', 'Counts below are distinct accepted call receipts attributed by original source/checker bindings. They are not semantic combination counts. CHIPS controls are excluded from form credit; scoped Ara outcomes retain their scope.', '', 'Use `rvv_scope_report.py --host512-corpus navigation.json.gz --form FORM --output NEW` to resolve all source/checker/configuration/result records for a row.', '', '| Form | CHIPS calls | ACT calls | Ara calls | Example actual receipt |', '|---|---:|---:|---:|---|']
    for form, groups in sorted(forms.items()):
        sample = records[next(iter(groups.values()))[0]]
        lines.append('|`'+form+'`|'+'|'.join(str(len(groups.get(s,[]))) for s in ('chips','act','ara'))+'|Task'+str(sample['task'])+' `'+sample['suite']+'/'+str(sample['id'])+'/'+sample['arm']+'`|')
    (output/'FORMS.md').write_text('\n'.join(lines)+'\n')
    (output/'SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n')
    write_readable_summary(summary,records,output)
    return summary


def select(path, form=None, suite=None, case=None, arm=None):
    index = read(path)
    rows = index['records']
    if form is not None:
        require(form in index['per_form'],'unknown form')
        indices = {i for values in index['per_form'][form].values() for i in values}
        rows = [index['records'][i] for i in sorted(indices)]
    rows = [r for r in rows if
        (suite is None or r['suite']==suite) and (case is None or r['case']==case or any(b.get('case')==case for b in r['original_source_checker_bindings'])) and
        (arm is None or r['arm']==arm)]
    source_hashes = {b['source_sha256'] for r in rows if r['suite']=='chips' for b in r['original_source_checker_bindings']}
    contexts = collections.defaultdict(list)
    literal_contexts = []
    if source_hashes:
        for name, digest in index['source_context_files'].items():
            source = Path(path).parent.parent/name
            require(sha(source)==digest,'source context identity')
            if name.endswith('.csv.gz'):
                with gzip.open(source,'rt') as f:
                    for context in csv.DictReader(f):
                        if context['source_sha256'] in source_hashes:
                            contexts[context['source_sha256']].append(context)
            else:
                literal_contexts = [r for r in read(source) if r['source_sha256'] in source_hashes]
    return dict(summary=index['summary'],records=rows,
                selected_CHIPS_source_geometry=dict(contexts),selected_CHIPS_literal_contexts=literal_contexts,
                literal_interpretation='Original source lines/requested geometry in passing files; never substituted for actual runtime tuples.',
                original_ACT_reference_blockers=index['original_ACT_reference_blockers'])


def generate_current(docs, output, raw=Path('/home/user/research/materials/task138-host512-raw-20261013')):
    """Reuse original bindings; credit only fresh Task138 authenticated receipts."""
    docs, output, raw = Path(docs), Path(output), Path(raw)
    current = docs/'host512-task138'
    historical_path = docs/'host512-task129/combined/navigation.json.gz'
    historical = read(historical_path)
    templates = {identity(r['original_call']):r for r in historical['records']}
    require(len(templates)==21316, 'historical original binding uniqueness')
    require(read(raw/'IDENTITY_BEFORE.json')==read(raw/'IDENTITY_AFTER.json'), 'current before/after pins')
    pilots=read(raw/'PILOT_CALLS.json')
    for suite,key in (('chips','cells'),('act','calls'),('ara','calls')):
        calls=read(raw/suite/'QUEUE.json')[key]
        original={identity(r['original_call']) for r in historical['records'] if r['suite']==suite}
        full={identity(c) for c in calls}; pilot={identity(pilots[suite])}
        require(len(full)==len(calls) and full==original and pilot<=full, 'same-build original pilot/full equality')
        require(len(full-pilot)==len(calls)-1, 'same-build disjoint remainder')
    require(read(current/'PARTITION.json')==read(raw/'PARTITION.json'), 'partition raw join')
    receipts = read(current/'RECEIPTS.json.gz')
    require(len(receipts)==21316, 'current receipt count')
    require({identity(r['original_call']) for r in receipts}==set(templates), 'complete original call equality')
    require(len({r['receipt'] for r in receipts})==21316, 'current raw uniqueness')
    remote='/home/vick/rvdbt-host512-task138'
    executable='/home/vick/rvdbt-goldens-task137/current/build/bin/elfrun'
    digest='da5209ae488403f3eb2a15af8bf0376df4844eefb46b9525c8a0834f8e3f4d5e'
    records=[]; forms=collections.defaultdict(lambda:collections.defaultdict(list))
    for receipt in receipts:
        require(receipt['receipt'].startswith(remote+'/'), 'current raw root')
        local=raw/Path(receipt['receipt']).relative_to(remote)
        validate_record(receipt,local,elfrun=digest,executable=executable)
        require(receipt['result']['status'] in ('PASS','SCOPED_PASS'), 'current failed call')
        row=dict(templates[identity(receipt['original_call'])])
        row.update(task=138,receipt=receipt['receipt'],local_receipt=str(local),
            command=receipt['command'],result=receipt['result'],executable_pins=receipt['executable_pins'],
            observed_runtime=read(local/'observer.json') if receipt['suite']=='ara' else
                {'target_SEW_LMUL_VL_mask_tail_vstart':'UNKNOWN; original checker completion is not a runtime tuple census'},
            admission='No per-target current native admission inferred from flags, program PASS or aggregate route counters. Task128 target evidence remains historical.',
            routes=receipt['routes'],direct=receipt['direct'])
        stats=re.findall(r'^RVV_STATS (.*)$',(local/'stderr').read_text(errors='replace'),re.M)
        row['observed_runtime']['RVV_STATS']=stats
        row['observed_runtime']['host_chunk_bytes']=sorted({int(n) for line in stats for n in re.findall(r'chunk_bytes=(\d+)',line)})
        require(not row['observed_runtime']['host_chunk_bytes'] or row['observed_runtime']['host_chunk_bytes']==[64], 'observed host chunk')
        i=len(records);records.append(row)
        for form in row['forms']: forms[form][row['suite']].append(i)
    summary=dict(historical['summary'])
    summary.update(task128=0,task129=0,task138=21316,prior_build_credit=0,
        partition=read(current/'PARTITION.json')['suites'],
        counts={s:dict(collections.Counter(r['result']['status'] for r in records if r['suite']==s)) for s in ('chips','act','ara')},
        per_arm={s:{a:dict(collections.Counter(r['result']['status'] for r in records if r['suite']==s and r['arm']==a)) for a in ('B','M1','M2','BOTH')} for s in ('chips','act','ara')},
        control_counts=dict(collections.Counter(r['result']['status'] for r in records if r['control'])),
        guest_vlen_commands={s:dict(collections.Counter(r['guest_vlen'] for r in records if r['suite']==s)) for s in ('chips','act','ara')},
        observed_host_chunks={s:dict(collections.Counter(','.join(map(str,r['observed_runtime']['host_chunk_bytes'])) or 'UNKNOWN' for r in records if r['suite']==s)) for s in ('chips','act','ara')},
        local_host_tests='Task135/136/137 checks remain separate; no new fault/restart or local fixture execution in Task138')
    require(summary['counts']=={'chips':{'PASS':11744},'act':{'PASS':7668},'ara':{'PASS':1888,'SCOPED_PASS':16}}, 'suite counts')
    require(sum(r['control'] for r in records)==212, 'control count')
    require(len(forms)==595, 'checked form union')
    index=dict(summary=summary,records=records,per_form={f:dict(v) for f,v in sorted(forms.items())},
        original_ACT_reference_blockers=historical['original_ACT_reference_blockers'],
        source_context_files=historical['source_context_files'],
        inputs={str(historical_path):sha(historical_path),str(current/'RECEIPTS.json.gz'):sha(current/'RECEIPTS.json.gz')})
    output.mkdir(parents=True,exist_ok=False)
    (output/'navigation.json.gz').write_bytes(gzip.compress(json.dumps(index,separators=(',',':')).encode(),mtime=0))
    (output/'SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n')
    lines=['# Task138 final retained host512 forms','','Counts are distinct current-build receipts joined to unchanged original source/checker bindings. Controls earn no positive form credit; Ara scoped acceptances retain their scope.','','Use `rvv_scope_report.py --host512-corpus navigation.json.gz --form FORM --output NEW`.','','| Form | CHIPS calls | ACT calls | Ara calls | Example current receipt |','|---|---:|---:|---:|---|']
    for form,groups in sorted(forms.items()):
        sample=records[next(iter(groups.values()))[0]]
        lines.append('|`'+form+'`|'+'|'.join(str(len(groups.get(s,[]))) for s in ('chips','act','ara'))+'|Task138 `'+sample['suite']+'/'+str(sample['id'])+'/'+sample['arm']+'`|')
    (output/'FORMS.md').write_text('\n'.join(lines)+'\n')
    (output/'SUMMARY.md').write_text('# Task138 complete retained corpus on exact Task137 final build\n\nAll 21,316 calls have fresh Task138 receipts on da5209ae…; prior-build credit: zero. Three unchanged pilots plus 21,313 disjoint remaining calls.\n\n| Suite | Positives / whole-file PASS | Controls PASS | Scoped PASS |\n|---|---:|---:|---:|\n| CHIPS | 11,532 | 212 | 0 |\n| ACT | 7,668 | 0 | 0 |\n| Ara | 1,888 | 0 | 16 |\n\nEach B/M1/M2/BOTH arm: CHIPS 2,883 positives + 53 controls; ACT 1,917; Ara 472 whole-file + 4 scoped. Two ACT reference blockers remain outside the queue. Checked-form union: 595. See [forms](FORMS.md), [counts](SUMMARY.json) and [reader instructions](../README.md).\n\nGuest VLEN/flags are actual command settings. Source SEW/LMUL/requested VL/mask/tail/vstart literals remain source evidence; unprinted runtime dimensions remain UNKNOWN. Enabled flags and aggregate counters are not a target-native census. No guest handler return, mapping repair, same-PC retry, new reference, fault/restart or performance campaign was executed. Earlier target-admission observations remain attributed to their original build.\n')
    return summary
