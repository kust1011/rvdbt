#!/usr/bin/env python3
"""Project saved canonical scope into a compact index; never execute guests."""
import argparse
import csv
import json
from pathlib import Path

from rvv_scope_report import report
from rvv_tests import digest


def project(forms, summary, routes):
    # Reuse canonical frozen-renderer validation, including all stage names.
    report(forms, summary)
    names = {r['form'] for r in forms}
    route_rows = {}
    for row in routes:
        if row['form'] not in names or row['form'] in route_rows:
            raise ValueError('unknown or duplicate route form: ' + row['form'])
        route_rows[row['form']] = row
    projected = []
    for row in forms:
        route = route_rows.get(row['form'])
        implementations = None
        if route is not None:
            if route['applicability'] != row['rv32_elen64_applicability']:
                raise ValueError('route applicability mismatch: ' + row['form'])
            implementations = {k: {field: v[field] for field in ('direct_qir', 'helper')}
                               for k, v in json.loads(route['route_implementations']).items()}
            if set(implementations) != set(json.loads(route['decoder_routes'])):
                raise ValueError('route implementation mismatch: ' + row['form'])
        projected.append({'form': row['form'], 'family': row['family'],
                          'applicability': row['rv32_elen64_applicability'],
                          'recorded_routes': implementations,
                          'route_runtime_status': route['runtime_status'] if route else None})
    return {'schema': 1, 'snapshot': 'Task76 current membership / recorded October 7 static routes',
            'scope': summary['scope'], 'forms': projected,
            'suites': [{'suite': s['suite'], **{k: list(s['forms'][k]) for k in
                        ('result_checked', 'coupled_endpoint')}} for s in summary['suites']],
            'new_DUT_executions': 0}


def render(data):
    if 'ara_evidence' in data:
        from rvv_ara_accepted import validate_evidence
        validate_evidence(data)
    forms = data['forms']
    names = {r['form'] for r in forms}
    if len(names) != len(forms):
        raise ValueError('duplicate form')
    suites = data['suites']
    if len({s['suite'] for s in suites}) != len(suites):
        raise ValueError('duplicate suite')
    for suite in suites:
        for stage in ('result_checked', 'coupled_endpoint'):
            values = suite[stage]
            if len(set(values)) != len(values) or set(values) - names:
                raise ValueError('invalid membership: ' + suite['suite'])
    checked = set().union(*(set(s['result_checked']) for s in suites))
    applicable = {r['form'] for r in forms if r['applicability'] == 'REQUIRED'}
    if checked - applicable:
        raise ValueError('excluded form in checked union')
    counts = {'forms': len(forms), 'applicable': len(applicable),
              'excluded': len(forms) - len(applicable), 'checked_union': len(checked),
              'new_DUT_executions': 0}
    lines = ['# Current compact RVV scope', '',
             f"Generated saved index: **{len(forms)} forms / {len(applicable)} applicable / "
             f"{counts['excluded']} excluded; checked union {len(checked)}**.", '',
             data['snapshot'] + '; static implementation classes copied from the recorded October 7 route matrix.',
             'This compact index is not raw evidence, a new execution, or a measurement of semantic depth.',
             'Suite/stage sets overlap. A dash means no established membership in that saved set;',
             'it does not mean an instruction is unsupported. Candidate/configuration/checker/raw details',
             'remain in separately retained bindings. Runtime route and depth are not inferred.', '',
             'See [inputs, reproduction and retrieval limits](rvv-validation/current-scope/README.md)',
             'and the separate [Task80 real smoke](rvv-validation/smoke-task80/README.md).', '',
             '| Suite | Target/result checked | Coupled endpoint |', '|---|---:|---:|']
    lines += [f"| {s['suite']} | {len(s['result_checked'])} | {len(s['coupled_endpoint'])} |" for s in suites]
    lines += ['', '## Exact form membership', '',
              'Recorded route IDs refer to the static implementation-class legend below.', '',
              '| Form | Profile | Family | Checked suites | Endpoint suites | Recorded routes |',
              '|---|---|---|---|---|---|']
    rows = []
    legend = {}
    class_ids = {}
    for row in forms:
        routes = row['recorded_routes']
        labels = []
        for name, classes in sorted((routes or {}).items()):
            key = (name, classes['direct_qir'], classes['helper'])
            if key not in class_ids:
                number = 1 + sum(k[0] == name for k in class_ids)
                class_ids[key] = f'{name}/{number}'
                legend[class_ids[key]] = classes
            labels.append(class_ids[key])
        values = {'form': row['form'], 'applicability': row['applicability'], 'family': row['family'],
                  'checked_suites': ';'.join(s['suite'] for s in suites if row['form'] in s['result_checked']),
                  'endpoint_suites': ';'.join(s['suite'] for s in suites if row['form'] in s['coupled_endpoint']),
                  'recorded_routes': ';'.join(sorted(routes)) if routes is not None else '',
                  'route_runtime_status': row['route_runtime_status'] or '',
                  'implementation_classes_json': json.dumps(routes, sort_keys=True)}
        rows.append(values)
        cells = [values[k] or '—' for k in ('form', 'applicability', 'family', 'checked_suites',
                                          'endpoint_suites', 'recorded_routes')]
        cells[-1] = ';'.join(labels) or '—'
        lines.append('| ' + ' | '.join(c.replace('|', '\\|') for c in cells) + ' |')
    lines += ['', '## Recorded static implementation classes', '',
              'Route/number identifies an exact saved class variant; operand forms can differ within one route.',
              'These are literal saved classifications, not unconditional native-lowering or admission claims.',
              'A helper entry can first attempt direct lowering. Direct QIR can use scalar lanes.',
              'Refusal, guards, encoding, geometry and CPU predicates are outside this compact view.',
              'Runtime status remains per form in the input/CSV; no runtime route is established here.', '',
              '| Decoder route | Recorded direct QIR body | Recorded helper body |', '|---|---|---|']
    lines += [f"| {name} | {v['direct_qir']} | {v['helper']} |" for name, v in sorted(legend.items())]
    return '\n'.join(lines) + '\n', rows, counts


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, help='bundled compact-input.json; no historical archive needed')
    p.add_argument('--accepted-evidence', type=Path, help='accepted Tasks82–86 evidence root; offline overlay')
    p.add_argument('--canonical-tables', action='store_true', help='also emit versioned existing canonical table views')
    p.add_argument('--canonical', type=Path, help='existing canonical coverage directory')
    p.add_argument('--forms', type=Path)
    p.add_argument('--summary', type=Path)
    p.add_argument('--routes', type=Path)
    p.add_argument('--output', type=Path, required=True, help='new directory')
    a = p.parse_args()
    if a.input:
        if any((a.forms, a.summary, a.routes)):
            p.error('--input cannot be combined with canonical inputs')
        data = json.loads(a.input.read_text())
    else:
        if not all((a.forms, a.summary, a.routes)):
            p.error('supply --input or all of --forms --summary --routes')
        csv.field_size_limit(64 * 1024 * 1024)
        with a.forms.open(newline='') as f, a.routes.open(newline='') as r:
            data = project(list(csv.DictReader(f)), json.loads(a.summary.read_text()), list(csv.DictReader(r)))
        data['canonical_inputs'] = {path.name: {'bytes': path.stat().st_size, 'sha256': digest(path)}
                                    for path in (a.forms, a.summary, a.routes)}
    if a.accepted_evidence:
        if not a.canonical:
            p.error('--accepted-evidence requires --canonical')
        from rvv_ara_accepted import integrate
        data = integrate(data, a.accepted_evidence, a.canonical)
    markdown, rows, counts = render(data)
    a.output.mkdir(parents=True, exist_ok=False)
    (a.output / 'compact-input.json').write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    (a.output / 'rvv-current-scope.md').write_text(markdown)
    (a.output / 'counts.json').write_text(json.dumps(counts, indent=2) + '\n')
    with (a.output / 'forms.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, rows[0].keys(), lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)
    if 'ara_evidence' in data:
        from rvv_ara_accepted import render_evidence, export_canonical
        if a.canonical_tables:
            export_canonical(data, a.canonical, a.output)
        (a.output / 'ara-accepted-evidence.md').write_text(render_evidence(data['ara_evidence']))
        (a.output / 'ara-form-set-diff.json').write_text(json.dumps(data['ara_evidence']['diff'], indent=2) + '\n')
    print(json.dumps(counts))


if __name__ == '__main__':
    main()
