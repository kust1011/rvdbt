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



def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--forms', type=Path)
    p.add_argument('--summary', type=Path)
    p.add_argument('--form')
    p.add_argument('--bindings', type=Path, help='optional canonical CSV; retain exact matching original rows')
    p.add_argument('--output', type=Path, required=True, help='new directory')
    p.add_argument('--case')
    p.add_argument('--candidate')
    p.add_argument('--arm')
    p.add_argument('--navigation', type=Path, help='select from compressed original-case index')
    p.add_argument('--canonical-manifest', type=Path, help='pin canonical Task90 generation inputs')
    p.add_argument('--all-records', action='store_true', help='index original Task90 and retained package selectors')
    for label in ('chips', 'act', 'act-db2', 'ara'):
        p.add_argument('--' + label + '-package', type=Path)
    a = p.parse_args()
    roots = {k: v for k, v in [('CHIPS', a.chips_package), ('ACT', a.act_package),
                              ('ACT-db2', a.act_db2_package), ('Ara', a.ara_package)] if v}
    if a.navigation:
        import gzip
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
