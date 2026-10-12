#!/usr/bin/env python3
"""Render a frozen canonical stage index; no test, compiler or generator runs."""
import argparse
import csv
import json
from pathlib import Path
from rvv_tests import digest

STAGES = ('source_present', 'compiled_source', 'emitted', 'program_executed',
          'executed_without_independent_form_check', 'result_checked',
          'coupled_endpoint', 'diagnostic_only', 'failed_or_blocked')


def report(forms, summary, selected=None):
    def applicability(row):
        # The delivered compact forms.csv retains the same values under a shorter header.
        if 'rv32_elen64_applicability' in row:
            value = row['rv32_elen64_applicability']
            if 'applicability' in row and row['applicability'] != value:
                raise ValueError('conflicting applicability: ' + row['form'])
            return value
        return row['applicability']

    names = {r['form'] for r in forms}
    if len(names) != len(forms):
        raise ValueError('duplicate form')
    if selected is not None and selected not in names:
        raise ValueError('unknown form: ' + selected)
    suites = summary['suites']
    if len({s['suite'] for s in suites}) != len(suites):
        raise ValueError('duplicate suite')
    checked = set()
    counts = []
    for s in suites:
        for stage in STAGES:
            values = s['forms'][stage]
            if len(set(values)) != len(values) or set(values) - names:
                raise ValueError('invalid stage forms: ' + s['suite'] + '/' + stage)
        checked.update(s['forms']['result_checked'])
        counts.append({'suite': s['suite'], **{k: len(s['forms'][k]) for k in STAGES}})
    per_form = []
    for r in forms:
        if selected is not None and r['form'] != selected:
            continue
        per_form.append({'form': r['form'], 'applicability': applicability(r),
                         'suites': [{'suite': s['suite'], **{
                             k: True if r['form'] in s['forms'][k] else None for k in STAGES}}
                             for s in suites]})
    return {'scope': summary['scope'], 'forms': len(names),
            'applicable_forms': sum(applicability(r) == 'REQUIRED' for r in forms),
            'checked_union': len(checked), 'suite_counts': counts,
            'per_form': per_form, 'candidate_scopes': [{'suite': s['suite'], 'candidates': s.get('candidates', [])} for s in suites],
            'interpretation': 'null means no established stage join; never infer opcode execution or influence from program completion',
            'new_DUT_executions': 0}


def package_index(roots):
    """Project existing package selectors; original records stay in their packages."""
    packages = {}
    for label, root in roots.items():
        manifest = json.loads((root / 'FILES.json').read_text())
        def load(name, csv_file=False):
            path = root / name
            if digest(path) != manifest[name]['sha256']:
                raise ValueError('package index identity: ' + label + '/' + name)
            return list(csv.DictReader(path.open())) if csv_file else json.loads(path.read_text())
        name = 'NAVIGATION.csv' if label == 'CHIPS' else 'BINDINGS.json' if label == 'Ara' else 'CASES.json'
        records = load(name, label == 'CHIPS')
        packages[label] = {'selector_file': name, 'selector_sha256': manifest[name]['sha256'],
                           'manifest_sha256': digest(root / 'FILES.json'), 'records': records}
    return packages


def navigation(forms, bindings, packages, identity):
    """An index into existing ledgers, not a new acceptance ledger."""
    names = {r['form'] for r in forms}
    selectors = {f: {} for f in names}
    for label, package in packages.items():
        for i, row in enumerate(package['records']):
            if row['form'] in names:
                selectors[row['form']].setdefault(label, []).append(i)
    canonical = []
    seen = set()
    for row in bindings:
        if row['suite'] not in ('CHIPS', 'Ara', 'ACT'):
            continue
        key = json.dumps(row, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        i = len(canonical)
        canonical.append(row)
        for f in set(row['result_checked_forms'].split(';')) & names:
            selectors[f].setdefault('Task90', []).append(i)
    rows = []
    for f in forms:
        applicable = f.get('rv32_elen64_applicability', f.get('applicability'))
        refs = selectors[f['form']]
        if applicable == 'REQUIRED' and not refs.get('CHIPS'):
            raise ValueError('missing retained CHIPS form: ' + f['form'])
        if applicable == 'REQUIRED' and not refs.get('Task90'):
            raise ValueError('missing canonical checked binding: ' + f['form'])
        rows.append({'form': f['form'], 'family': f['family'], 'applicability': applicable,
                     'selectors': refs})
    return {'format': 'existing-scope-navigation-1', 'canonical_identity': identity,
            'forms': rows, 'canonical_bindings': canonical, 'packages': packages,
            'new_guest_executions': 0,
            'scope': 'original selectors and bindings; setup is not runtime observation; historical results do not validate 37823dd'}


def selected_navigation(index, form, roots, case=None, candidate=None, arm=None):
    matches = [r for r in index['forms'] if r['form'] == form]
    if len(matches) != 1:
        raise ValueError('unknown form: ' + form)
    result = dict(matches[0])
    result['canonical_bindings'] = [index['canonical_bindings'][i] for i in result['selectors'].get('Task90', [])]
    result['package_records'] = {}
    result['literal_source_checks'] = {}
    for label, indices in result['selectors'].items():
        if label == 'Task90':
            continue
        records = [index['packages'][label]['records'][i] for i in indices]
        records = [r for r in records if (case is None or r.get('case') == case)
                   and (candidate is None or r.get('candidate', candidate) == candidate)
                   and (arm is None or r.get('arm', arm) == arm)]
        result['package_records'][label] = records
        if label not in roots:
            continue
        root = roots[label]
        manifest = json.loads((root / 'FILES.json').read_text())
        if digest(root / 'FILES.json') != index['packages'][label]['manifest_sha256']:
            raise ValueError('package identity changed: ' + label)
        def payload(name):
            from verify_rvv_ara_bundle import package_path
            path = package_path(root, name)
            if name not in manifest or digest(path) != manifest[name]['sha256']:
                raise ValueError('payload identity: ' + name)
            return path
        if label == 'CHIPS':
            from verify_rvv_chips_inspection import form_record
            result['literal_source_checks'][label] = form_record(root, records, manifest)
            continue
        sources = {}
        details = {}
        for row in records:
            if row.get('result'):
                original_result = json.loads(payload(row['result']).read_text())
                details[row['case']] = {'original_result': original_result, 'receipts': {}}
                for receipt in original_result.get('DUT', []) + original_result.get('reference', []):
                    raw = (Path(row['result']).parent / receipt['raw']).as_posix()
                    details[row['case']]['receipts'][raw] = {
                        'original_command': json.loads(payload(raw+'/command.json').read_text()),
                        'original_result': json.loads(payload(raw+'/result.json').read_text()),
                        'stdout_sha256': digest(payload(raw+'/stdout')),
                        'stderr_sha256': digest(payload(raw+'/stderr'))}

                base = Path(row['result']).parent
                for name in ('SCOPE_AUDIT.json', 'CHECKER_SCOPE.json', 'CHECKER_SCOPE_CORRECTED.json', 'TARGET_EXECUTION_AUDIT.json'):
                    relative = (base / name).as_posix()
                    if relative in manifest:
                        details[row['case']][name] = {'path': relative, 'sha256': manifest[relative]['sha256'],
                                                     'record': json.loads(payload(relative).read_text())}
                for field in ('checker_scope', 'source_scope', 'oracle', 'expected', 'capture'):
                    if row.get(field):
                        path = payload(row[field])
                        details[row['case']][field] = {'path': row[field], 'sha256': manifest[row[field]]['sha256']}
                        if field.endswith('scope') or field == 'oracle':
                            details[row['case']][field]['record'] = json.loads(path.read_text())
            elif row.get('raw'):
                details[row['raw']] = {'original_result': json.loads(payload(row['raw']+'/result.json').read_text()),
                                       'original_command': json.loads(payload(row['raw']+'/command.json').read_text()),
                                       'stdout_sha256': digest(payload(row['raw']+'/stdout')),
                                       'stderr_sha256': digest(payload(row['raw']+'/stderr'))}
                for field in ('config', 'build'):
                    if row.get(field):
                        value = json.loads(payload(row[field]).read_text())
                        selected = [v for v in value if isinstance(v, dict) and v.get('case', v.get('name')) == row['case']] if isinstance(value, list) else []
                        details[row['raw']][field] = {'path': row[field], 'exact_case_records': selected}
        result.setdefault('original_case_details', {})[label] = details
        for row in records:
            source = row.get('source')
            if not source or source in sources:
                continue
            lines = payload(source).read_text().splitlines()
            # Literal sites/windows only. Macro expansion/runtime history is not inferred.
            import re
            sites = []
            for n, line in enumerate(lines, 1):
                if re.search(r'(?<![\w.])' + re.escape(form) + r'(?![\w.])', line) or re.search(r'\b(?:VCMP\w*|RVTEST_SIGUPD\w*|check_fflags|CHECK\w*)\s*\(', line):
                    sites.append({'line': n, 'text': line, 'window_first_line': max(1, n-8),
                                  'window': lines[max(0,n-9):n+3]})
            sources[source] = {'sha256': manifest[source]['sha256'], 'literal_sites': sites}
        result['literal_source_checks'][label] = sources
    result['new_guest_executions'] = 0
    return result


def write_navigation(index, output):
    import gzip
    data = json.dumps(index, sort_keys=True, separators=(',', ':')).encode()
    compressed = bytearray(gzip.compress(data, mtime=0))
    compressed[9] = 255  # Stable gzip OS header across Python versions.
    (output / 'navigation.json.gz').write_bytes(compressed)
    lines = ['# Original external cases by instruction form', '',
             '627 forms; 595 applicable. Counts are selectors, never executions or semantic depth.',
             'Select any row with `rvv_scope_report.py --navigation navigation.json.gz --form FORM --output NEW`.',
             'Supply retained package roots for literal checks. See [reader instructions](README.md).', '',
             '| Form | Family | Applicable | Original CHIPS case (selector) | CHIPS | ACT c3e | ACT db2 | Ara overlay | Task90 |',
             '|---|---|---|---|---:|---:|---:|---:|---:|']
    for row in index['forms']:
        s = row['selectors']
        chips = s.get('CHIPS', [])
        i = next((i for i in chips if index['packages']['CHIPS']['records'][i]['candidate']=='clean961'), None)
        case = index['packages']['CHIPS']['records'][i] if i is not None else None
        example = ('`'+case['batch']+'/'+case['case']+'` (#'+str(i)+')') if case else 'profile N/A'
        lines.append('|`'+row['form']+'`|'+row['family']+'|'+row['applicability']+'|'+example+'|'+
                     '|'.join(str(len(s.get(k,[]))) for k in ('CHIPS','ACT','ACT-db2','Ara','Task90'))+'|')
    (output / 'forms.md').write_text('\n'.join(lines)+'\n')
    counts = {'forms':len(index['forms']), 'applicable':sum(r['applicability']=='REQUIRED' for r in index['forms']),
              'canonical_bindings':len(index['canonical_bindings']),
              'packages':{k:{'records':len(v['records']), 'forms':len({r['form'] for r in v['records']}),
                             'distinct_sources':len({r.get('source') for r in v['records']} - {None}),
                             'distinct_direct_raw_locators':len({r.get('receipt', r.get('raw')) for r in v['records']} - {None})}
                          for k,v in index['packages'].items()},
              'new_guest_executions':0}
    (output / 'COUNTS.json').write_text(json.dumps(counts,indent=2,sort_keys=True)+'\n')
    families = {}
    for row in index['forms']:
        group = families.setdefault(row['family'], {'forms': [], 'bindings': set()})
        group['forms'].append(row['form'])
        group['bindings'].update(row['selectors'].get('Task90', []))
    lines = ['# Family evidence and original remaining obligations', '',
             'This table groups the original Task90 bindings, including their remaining fields.',
             'Select a form to retrieve every original checked-output/CSR scope and remaining statement.',
             'A statement count is not a missing-obligation count; later scoped reconciliation is in [obligations.md](obligations.md).', '',
             '| Family | Forms | Bindings | Distinct original remaining statements | Example original checked scope |',
             '|---|---:|---:|---:|---|']
    for family, group in sorted(families.items()):
        bindings = [index['canonical_bindings'][i] for i in sorted(group['bindings'])]
        remaining = {b['remaining'] for b in bindings if b.get('remaining')}
        example = next((b.get('observed_state','') for b in bindings if b.get('observed_state')), 'none applicable')
        lines.append('|'+family+'|'+str(len(group['forms']))+'|'+str(len(bindings))+'|'+str(len(remaining))+'|'+example[:240].replace('|','\\|').replace('\n',' ')+'|')
    (output / 'families.md').write_text('\n'.join(lines)+'\n')


def chips_replay(index, raw, original_manifest, output, original_runner=None):
    """Join a new build's receipts to retained CHIPS selectors and predicates."""
    from collections import Counter, defaultdict
    from rvv_tests import load_manifest, classify
    original = load_manifest(original_manifest)
    manifest = load_manifest(raw / 'manifest.json')
    if manifest['cells'] != original['cells'] or manifest['timeout_seconds'] != original['timeout_seconds']:
        raise ValueError('original CHIPS cells/ELFs/inputs/predicates changed')
    cells = {c['id']: c for c in manifest['cells']}
    invocation = json.loads((raw / 'invocation.json').read_text())
    summary = json.loads((raw / 'summary.json').read_text())
    if invocation['manifest_sha256'] != digest(raw / 'manifest.json'):
        raise ValueError('invoked manifest identity mismatch')
    if original_runner is not None and invocation['runner_sha256'] != digest(original_runner):
        raise ValueError('original runner identity mismatch')
    if set(invocation['selected_cases']) != set(cells) or not summary['candidate_unchanged']:
        raise ValueError('incomplete selection or changed candidate')
    build = manifest['candidate']['build']
    identities = invocation['engine_files_before']
    if identities != summary['engine_files_after'] or not set(build.values()) <= set(identities.values()):
        raise ValueError('candidate identity mismatch')
    results = json.loads((raw / 'results.json').read_text())
    if len(results) != len(cells) or {r['id'] for r in results} != set(cells):
        raise ValueError('missing/duplicate result')
    selectors = defaultdict(list)
    for row in index['packages']['CHIPS']['records']:
        if row['candidate'] == 'clean961':
            selectors[row['cell_id']].append(row)
    bindings = defaultdict(list)
    for b in index['canonical_bindings']:
        if b['suite'] == 'CHIPS' and b['candidate'] == 'clean961':
            bindings[b['elf_sha256'], b['arm'], b['source_case']].append(b)
    records = []
    statuses = Counter()
    control_statuses = Counter()
    positive_statuses = Counter()
    for r in results:
        cell = cells[r['id']]
        directory = raw / r['id']
        if json.loads((directory / 'case.json').read_text()) != cell or json.loads((directory / 'result.json').read_text()) != r:
            raise ValueError('receipt/cell mismatch: ' + r['id'])
        stdout, stderr = (directory / 'stdout').read_bytes(), (directory / 'stderr').read_bytes()
        if digest(directory / 'stdout') != r['stdout_sha256'] or digest(directory / 'stderr') != r['stderr_sha256']:
            raise ValueError('stream identity: ' + r['id'])
        status = classify(r['returncode'], stdout, cell, timed_out=r['status'] == 'TIMEOUT', error=r['error'])
        if status != r['status'] or r['elf_sha256'] != cell['elf_sha256'] or r['control'] != cell['control']:
            raise ValueError('original predicate/result mismatch: ' + r['id'])
        command = json.loads((directory / 'command.json').read_text())
        if command[0] not in identities or identities[command[0]] != build['stage/elfrun']:
            raise ValueError('command executable identity')
        if command[1:] != [f.replace('{WORK}', str(directory / 'work')) for f in cell['flags']]:
            # Downloaded receipts retain the original remote work path.
            remote_work = next(f[len('--fsroot='):-len('/fs')] for f in command if f.startswith('--fsroot='))
            if command[1:] != [f.replace('{WORK}', remote_work) for f in cell['flags']]:
                raise ValueError('original flags changed: ' + r['id'])
        statuses[status] += 1
        (control_statuses if cell['control'] else positive_statuses)[status] += 1
        if not selectors[r['id']]:
            raise ValueError('missing original source selector: ' + r['id'])
        for n in selectors[r['id']]:
            if n['elf_sha256'] != cell['elf_sha256'] or n['VLEN'] != str(cell['vlen']):
                raise ValueError('source selector ELF/configuration mismatch')
            matches = [b for b in bindings[cell['elf_sha256'], n['arm'], n['case']]
                       if n['form'] in b['result_checked_forms'].split(';') and json.loads(b['flags_json']) == cell['flags']]
            if not cell['control'] and not matches:
                raise ValueError('missing retained target/checker binding: ' + str(n))
            records.append(dict(n, candidate=manifest['candidate'].get('production_head', build['stage/elfrun']),
                                prior_candidate=n['candidate'], prior_receipt=n['receipt'], receipt=str(directory),
                                result=status, returncode=r['returncode'], flags_json=json.dumps(cell['flags']),
                                executable_sha256=build['stage/elfrun'], library_sha256=build['stage/libdbtjitshared.so'],
                                checker=r['checker'], original_bindings_json=json.dumps(matches, sort_keys=True)))
    forms = []
    for f in index['forms']:
        rows = [r for r in records if r['form'] == f['form'] and r['control'] == 'False']
        passed = [r for r in rows if r['result'] == 'PASS']
        forms.append(dict(form=f['form'], applicability=f['applicability'], family=f['family'],
                          source_cases=sorted({r['batch'] + '/' + r['case'] for r in rows}),
                          tested_configurations=sorted({(r['arm'], int(r['VLEN'])) for r in rows}),
                          checked=bool(passed), counts=dict(Counter(r['result'] for r in rows)),
                          receipts=sorted({r['receipt'] for r in rows})))
    checked = sorted(f['form'] for f in forms if f['checked'])
    by_arm = defaultdict(Counter)
    for r in results:
        by_arm[cells[r['id']]['aliases'][0]['arm']][r['status']] += 1
    result = dict(candidate=manifest['candidate'], counts=dict(statuses), positive_counts=dict(positive_statuses),
                  control_counts=dict(control_statuses), total=len(cells), unattempted=0,
                  counts_by_arm={arm: dict(counts) for arm, counts in by_arm.items()},
                  checked_union=checked, checked_union_count=len(checked), per_form=forms,
                  inputs={str(p): digest(p) for p in (original_manifest, raw/'manifest.json', raw/'invocation.json', raw/'results.json')},
                  scope='New-build original CHIPS predicates only; source setup is not runtime geometry or per-PC admission; fault/restart and complete semantic obligations remain separate.')
    if original_runner is not None:
        result['inputs'][str(original_runner)] = digest(original_runner)
    output.mkdir(parents=True, exist_ok=False)
    with (output / 'replay-receipts.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, list(records[0]), lineterminator='\n')
        writer.writeheader(); writer.writerows(records)
    (output / 'scope.json').write_text(json.dumps(result, indent=2) + '\n')
    return result



def act_db2_replay(index, raw, package, prior, output):
    """Join new-build original ACT selfchecks to frozen source/signature navigation."""
    import collections
    import gzip
    from verify_rvv_act_db2 import original_predicates, require
    def read(p):
        return json.loads(p.read_text())
    manifest = read(package / 'FILES.json')
    require(digest(package / 'FILES.json') == index['packages']['ACT-db2']['manifest_sha256'], 'db2 package identity')
    def payload(name):
        p = package / name
        require(digest(p) == manifest[name]['sha256'], 'altered original: ' + name)
        return p
    queue = read(raw / 'QUEUE.json')
    original = json.loads(payload('records/EXACT_QUEUE.json').read_text())
    require(queue['original_queue_sha256'] == digest(payload('records/EXACT_QUEUE.json')), 'queue identity')
    require(queue['original_runner_sha256'] == digest(payload('records/execute109.py')), 'original runner identity')
    launch = json.loads(payload('records/LAUNCH_REGISTRATION.json').read_text())
    require(queue['original_launch_sha256'] == digest(payload('records/LAUNCH_REGISTRATION.json')), 'original launch identity')
    predicate = original_predicates(payload('records/execute109.py').read_text())[2]
    identities = read(raw / 'IDENTITY_BEFORE.json')
    require(identities == read(raw / 'IDENTITY_AFTER.json') == queue['counts']['executable_pins'], 'candidate changed')
    require(read(raw / 'PRODUCTION_EQUALITY.json')['production_matches'], 'production equality')
    require(digest(raw / 'run121.py') == queue['launcher_sha256'], 'invoked launcher changed')
    full = {r['original']: r for r in json.loads(payload('FULL_RAW_INDEX.json').read_text())}
    prior_manifest = {r['path']: r for r in read(prior / 'FILES_104.json')}
    seal = read(prior / 'SEAL_104.json')
    require(digest(prior / 'FILES_104.json') == seal['file_index_sha256'], 'Task104 seal')
    def prior_payload(p):
        relative = str(p.relative_to(prior))
        require(digest(p) == prior_manifest[relative]['sha256'], 'Task104 identity: ' + relative)
        return p
    entries = {e['case']: e for e in queue['entries']}
    require(len(entries) == len(queue['entries']) == len(original) == 1919, 'output denominator')
    comparisons = {c['case']: c for c in json.loads(gzip.decompress((raw / 'comparison.json.gz').read_bytes()))}
    literal_sites = {c['case']: c for c in json.loads(gzip.decompress((raw / 'comparison-sites.json.gz').read_bytes()))}
    require(set(literal_sites) == set(entries), 'literal comparison denominator')
    require(set(entries) == set(comparisons), 'comparison denominator')
    selectors = {r['case']: (i, r) for i, r in enumerate(index['packages']['ACT-db2']['records'])}
    original_outputs = {q['output']['case']: q for q in original}
    for n, e in entries.items():
        q = original_outputs[n]
        require(e['source_sha256'] == q['output']['sha256'] and e['form'] == q['input']['form'] and e['sew'] == q['input']['sew'], 'original source selection')
        for field in ('source', 'expected', 'capture', 'checker', 'elf'):
            require(digest(Path(e[field])) == e[field + '_sha256'], 'retained original changed: ' + field)
        import re
        sites = [dict(line=i, text=line) for i, line in enumerate(Path(e['source']).read_text().splitlines(), 1)
                 if re.search(r'\bRVTEST_SIGUPD\w*\s*\(', line)]
        require(literal_sites[n]['source_sha256'] == e['source_sha256'] and literal_sites[n]['literal_checker_sites'] == sites, 'literal destination/CSR sites changed')
        c = comparisons[n]
        require(c['source_sha256'] == e['source_sha256'] and c['expected_sha256'] == e['expected_sha256'], 'comparison binding')
        if e['prior_task'] == 104:
            require(n == 'Vls32-vluxei32.v' and q['output']['disposition'] == 'TASK104_ACCEPTED', 'Task104 selection')
            base = prior / 'pilot' / n
            for field, suffix in [('source', '.S'), ('expected', '.results'), ('capture', '.sig'), ('elf', '.elf')]:
                require(digest(prior_payload(base / (n + suffix))) == e[field + '_sha256'], 'Task104 ' + field)
            expected = prior_payload(base / (n + '.results'))
            scope = read(prior_payload(prior / 'CHECKER_SCOPE_104.json'))
            require(e['oracle'] == read(prior_payload(base / 'ORACLE.json')) and e['preservation'] == read(prior_payload(base / 'PRESERVATION.json')), 'Task104 oracle/preservation')
            prior_payload(prior / 'common-final2/user_env/signature.h')
        else:
            _, s = selectors[n]
            for field in ('source', 'expected', 'capture', 'checker'):
                require(digest(payload(s[field])) == e[field + '_sha256'], 'original ' + field + ': ' + n)
            expected = payload(s['expected'])
            r = json.loads(payload(s['result']).read_text())
            require(e['original_status'] == r['status'] and e['elf_sha256'] == r['elf_sha256'] == full[e['elf']]['sha256'], 'ELF/status identity')
            scope_name = 'CHECKER_SCOPE_CORRECTED.json' if r['status'] == 'PASS' else 'CHECKER_SCOPE.json'
            scope = json.loads(payload(str(Path(s['result']).parent / scope_name)).read_text())
            require(e['oracle'] == json.loads(payload(s['oracle']).read_text()) and e['preservation'] == json.loads(payload(str(Path(s['result']).parent / 'PRESERVATION.json')).read_text()), 'original oracle/preservation')
        words = [line.split('0x')[1].lower() for line in expected.read_text().splitlines() if line.startswith('.word 0x')]
        require(words == c['signature_words_hex'] and len(words) * 4 == c['embedded_bytes'] == e['preservation']['embedded_signature_bytes'], 'signature words changed')
        require(scope == c['original_checker_scope'], 'destination/CSR checker scope changed')
    cells = {(c['case'], c['arm']): c for c in queue['calls']}
    require(len(cells) == len(queue['calls']) == 7668, 'call denominator')
    blocked = {n for n, e in entries.items() if e['original_status'] == 'REFERENCE_ERROR'}
    require(blocked == {'Vf32-vfmv.f.s', 'Vf64-vfmv.f.s'}, 'blocker classification')
    require(set(cells) == {(n, a) for n in set(entries) - blocked for a in ('B', 'M1', 'M2', 'BOTH')}, 'selected arms')
    records = []; counts = collections.Counter(); by_arm = collections.defaultdict(collections.Counter)
    for (n, arm), cell in cells.items():
        e = entries[n]; d = raw / 'raw' / n / arm
        r = read(d / 'result.json'); command = read(d / 'command.json')
        require(read(d / 'IDENTITY.json') == read(d / 'IDENTITY_AFTER.json') == identities, 'case candidate changed')
        require(command[0] in identities, 'unregistered executable')
        original_command = cell['original_command']
        if e['prior_task'] == 104:
            old_command = read(prior_payload(prior / 'pilot' / n / 'raw' / ('DUT-' + arm) / 'command.json'))
        else:
            old_command = json.loads(payload('records/cases/' + n + '/raw/DUT-' + arm + '/command.json').read_text())
        require(original_command == old_command, 'original command changed')
        def normalize(cmd):
            return ['--fsroot={WORK}/fs' if a.startswith('--fsroot=') else '--cache={WORK}/cache' if a.startswith('--cache=') else '--dump-tbmap={WORK}/tbmap.txt' if a.startswith('--dump-tbmap=') else '--dump-tbcode={WORK}/tbcode.txt' if a.startswith('--dump-tbcode=') else a for a in cmd[1:]]
        require(normalize(command) == normalize(old_command) and cell['timeout'] == launch['timeout'] == 300, 'flags/timeout changed')
        for field in ('source', 'expected', 'elf'):
            require(r[field + '_sha256'] == cell[field + '_sha256'] == e[field + '_sha256'], 'case identity')
        require(digest(d / 'stdout') == r['stdout_sha256'] and digest(d / 'stderr') == r['stderr_sha256'], 'altered stream')
        text = (d / 'stdout').read_text(errors='replace') + (d / 'stderr').read_text(errors='replace')
        ok = eval(predicate, {'__builtins__': {}}, dict(rc=r['returncode'], raw=text, N=n, sig=None))
        status = 'TIMEOUT' if r['timeout'] else 'PASS' if ok else 'CRASH' if r['returncode'] < 0 else 'RESULT_MISMATCH'
        require(status == r['status'] and ok == r['original_predicate_pass'], 'original predicate classification')
        counts[status] += 1; by_arm[arm][status] += 1
        records.append(dict(case=n, form=e['form'], sew=e['sew'], arm=arm, VLEN=1024, XLEN=32, ELEN=64,
                            prior_task=e['prior_task'], original_selector=selectors[n][0] if n in selectors else 'TASK104_JOIN.json#0',
                            source=e['source'], source_sha256=e['source_sha256'], elf=e['elf'], elf_sha256=e['elf_sha256'],
                            expected=e['expected'], expected_sha256=e['expected_sha256'], checker=e['checker'], checker_sha256=e['checker_sha256'],
                            literal_checker_sites=str(raw / 'comparison-sites.json.gz') + '#' + n,
                            signature_words=len(comparisons[n]['signature_words_hex']), comparison=str(raw / 'comparison.json.gz') + '#' + n,
                            original_receipt=cell['original_raw'], receipt=str(d), result=status, returncode=r['returncode'],
                            executable_sha256=identities[command[0]], flags_json=json.dumps(command[1:]),
                            stdout_sha256=r['stdout_sha256'], stderr_sha256=r['stderr_sha256']))
    require(dict(counts) == read(raw / 'EXECUTION_COUNTS.json'), 'execution count mismatch')
    forms = []
    for f in index['forms']:
        rows = [r for r in records if r['form'] == f['form']]
        forms.append(dict(form=f['form'], applicability=f['applicability'], family=f['family'], original_selectors=f['selectors'],
                          source_cases=sorted({r['case'] for r in rows}), tested_configurations=sorted({(r['arm'], r['VLEN']) for r in rows}),
                          checked=any(r['result'] == 'PASS' for r in rows), counts=dict(collections.Counter(r['result'] for r in rows)),
                          comparisons=sorted({r['comparison'] for r in rows}),
                          literal_checker_sites=sorted({r['literal_checker_sites'] for r in rows}), receipts=sorted({r['receipt'] for r in rows}),
                          blocked_original_sources=sorted(n for n in blocked if entries[n]['form'] == f['form'])))
    result = dict(total=7668, counts=dict(counts), counts_by_arm={a: dict(c) for a, c in by_arm.items()},
                  unattempted=0, original_reference_blocked_outputs=2, withheld_blocked_arm_slots=8,
                  blocked_cases=sorted(blocked), new_reference_calls=0, tested_original_outputs=1917,
                  checked_union_count=sum(f['checked'] for f in forms), per_form=forms,
                  comparison_sha256=digest(raw / 'comparison.json.gz'), comparison_sites_sha256=digest(raw / 'comparison-sites.json.gz'),
                  inputs={str(p): digest(p) for p in (raw / 'QUEUE.json', package / 'FILES.json', prior / 'FILES_104.json')},
                  scope='Original destination/CSR/signature predicates on retained data only. Static source setup is not runtime geometry; signature words are frozen expectations, not complete actual snapshots. General semantic obligations and per-PC optimized admission remain untested.')
    output.mkdir(parents=True, exist_ok=False)
    with (output / 'replay-receipts.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, list(records[0]), lineterminator='\n'); writer.writeheader(); writer.writerows(records)
    (output / 'scope.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host512-corpus', type=Path, help='offline Task128/129 navigation, or validation docs root with --host512-build')
    p.add_argument('--host512-build', action='store_true', help='audit and merge exact retained host512 raw receipts')
    p.add_argument('--suite', choices=('chips','act','ara'))
    p.add_argument('--forms', type=Path)
    p.add_argument('--summary', type=Path)
    p.add_argument('--form')
    p.add_argument('--bindings', type=Path, help='optional canonical CSV; retain exact matching original rows')
    p.add_argument('--output', type=Path, required=True, help='new directory')
    p.add_argument('--case')
    p.add_argument('--candidate')
    p.add_argument('--arm')
    p.add_argument('--navigation', type=Path, help='select from compressed original-case index')
    p.add_argument('--ara-replay', type=Path, help='audit current-build original accepted Ara receipts')
    p.add_argument('--act-db2-replay', type=Path, help='audit current-build original ACT db2 selfchecks')
    p.add_argument('--act-prior-root', type=Path, help='retained Task104 sealed raw root')
    p.add_argument('--chips-replay', type=Path, help='audit new-build raw with retained CHIPS selectors')
    p.add_argument('--original-manifest', type=Path, help='unchanged sealed CHIPS manifest')
    p.add_argument('--original-runner', type=Path, help='retained unchanged CHIPS runner')
    p.add_argument('--canonical-manifest', type=Path, help='pin canonical Task90 generation inputs')
    p.add_argument('--all-records', action='store_true', help='index original Task90 and retained package selectors')
    for label in ('chips', 'act', 'act-db2', 'ara'):
        p.add_argument('--' + label + '-package', type=Path)
    a = p.parse_args()
    if a.host512_corpus:
        from rvv_host512_corpus import generate, select
        if a.host512_build:
            result = generate(a.host512_corpus,a.output)
        else:
            result = select(a.host512_corpus,a.form,a.suite,a.case,a.arm)
            a.output.mkdir(parents=True,exist_ok=False)
            (a.output/'record.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result.get('summary',result)))
        return
    roots = {k: v for k, v in [('CHIPS', a.chips_package), ('ACT', a.act_package),
                              ('ACT-db2', a.act_db2_package), ('Ara', a.ara_package)] if v}
    if a.navigation:
        import gzip
        if a.ara_replay:
            from rvv_ara_replay import audit
            index = json.loads(gzip.decompress(a.navigation.read_bytes()))
            result = audit(index, a.ara_replay, a.output)
            print(json.dumps({k: result[k] for k in ('total', 'counts', 'checked_union_count', 'unattempted')}))
            return
        if a.act_db2_replay:
            if not a.act_db2_package or not a.act_prior_root:
                p.error('--act-db2-replay requires --act-db2-package and --act-prior-root')
            index = json.loads(gzip.decompress(a.navigation.read_bytes()))
            result = act_db2_replay(index, a.act_db2_replay, a.act_db2_package, a.act_prior_root, a.output)
            result['inputs'][str(a.navigation)] = digest(a.navigation)
            (a.output / 'scope.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps({k: result[k] for k in ('total', 'counts', 'checked_union_count', 'unattempted')}))
            return
        if a.chips_replay:
            if not a.original_manifest or not a.original_runner:
                p.error('--chips-replay requires --original-manifest and --original-runner')
            index = json.loads(gzip.decompress(a.navigation.read_bytes()))
            result = chips_replay(index, a.chips_replay, a.original_manifest, a.output, a.original_runner)
            result['inputs'][str(a.navigation)] = digest(a.navigation)
            (a.output / 'scope.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps({k: result[k] for k in ('total', 'counts', 'checked_union_count', 'unattempted')}))
            return
        if not a.form:
            p.error('--navigation requires --form')
        index = json.loads(gzip.decompress(a.navigation.read_bytes()))
        selected = selected_navigation(index, a.form, roots, a.case, a.candidate, a.arm)
        a.output.mkdir(parents=True, exist_ok=False)
        (a.output / 'record.json').write_text(json.dumps(selected, indent=2) + '\n')
        return
    if not a.forms or not a.summary:
        p.error('--forms and --summary required for generation')
    csv.field_size_limit(64 * 1024 * 1024)
    with a.forms.open(newline='') as f:
        forms = list(csv.DictReader(f))
    result = report(forms, json.loads(a.summary.read_text()), a.form)
    result['inputs'] = {a.forms.name: digest(a.forms), a.summary.name: digest(a.summary)}
    if a.all_records:
        if not a.bindings or set(roots) != {'CHIPS', 'ACT', 'ACT-db2', 'Ara'}:
            p.error('--all-records requires bindings and all four retained packages')
        if a.canonical_manifest:
            pins = json.loads(a.canonical_manifest.read_text())['files']
            for path in (a.forms, a.summary, a.bindings):
                if digest(path) != pins[path.name]['sha256']:
                    raise ValueError('canonical identity: ' + path.name)
        with a.bindings.open() as stream:
            index = navigation(forms, csv.DictReader(stream), package_index(roots), result['inputs'] | {a.bindings.name: digest(a.bindings)})
        a.output.mkdir(parents=True, exist_ok=False)
        write_navigation(index, a.output)
        return
    if a.bindings and not a.form:
        p.error('--bindings requires --form')
    a.output.mkdir(parents=True, exist_ok=False)
    if a.bindings:
        fields = ('target_forms', 'emitted_forms', 'result_checked_forms', 'coupled_endpoint_forms')
        with a.bindings.open(newline='') as f, (a.output / 'bindings.csv').open('w', newline='') as out:
            rows = csv.DictReader(f)
            writer = csv.DictWriter(out, rows.fieldnames, lineterminator='\n')
            writer.writeheader()
            for row in rows:
                if any(a.form in row[k].split(';') for k in fields):
                    writer.writerow(row)
        result['inputs'][a.bindings.name] = digest(a.bindings)
    (a.output / 'scope.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(f"Exported frozen index: {result['forms']} forms; checked union {result['checked_union']}; no ISA executions")


if __name__ == '__main__':
    main()
