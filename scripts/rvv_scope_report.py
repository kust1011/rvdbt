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
        per_form.append({'form': r['form'], 'applicability': r['rv32_elen64_applicability'],
                         'suites': [{'suite': s['suite'], **{
                             k: True if r['form'] in s['forms'][k] else None for k in STAGES}}
                             for s in suites]})
    return {'scope': summary['scope'], 'forms': len(names),
            'applicable_forms': sum(r['rv32_elen64_applicability'] == 'REQUIRED' for r in forms),
            'checked_union': len(checked), 'suite_counts': counts,
            'per_form': per_form, 'candidate_scopes': [{'suite': s['suite'], 'candidates': s.get('candidates', [])} for s in suites],
            'interpretation': 'null means no established stage join; never infer opcode execution or influence from program completion',
            'new_DUT_executions': 0}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--forms', type=Path, required=True)
    p.add_argument('--summary', type=Path, required=True)
    p.add_argument('--form')
    p.add_argument('--bindings', type=Path, help='optional canonical CSV; retain exact matching original rows')
    p.add_argument('--output', type=Path, required=True, help='new directory')
    a = p.parse_args()
    csv.field_size_limit(64 * 1024 * 1024)
    with a.forms.open(newline='') as f:
        forms = list(csv.DictReader(f))
    result = report(forms, json.loads(a.summary.read_text()), a.form)
    result['inputs'] = {a.forms.name: digest(a.forms), a.summary.name: digest(a.summary)}
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
