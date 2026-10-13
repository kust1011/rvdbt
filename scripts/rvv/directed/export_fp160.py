#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Export compact full FP tables without transferring the corpus."""
import argparse
import collections
import csv
import gzip
import hashlib
import json
from pathlib import Path
import shutil


def read(path):
    return json.loads(path.read_text())


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def run(base, review, out):
    out.mkdir(parents=True, exist_ok=False)
    root = base / 'corpus'
    cases = read(root / 'manifest.json')['cases']
    ids = {c['id']: c for c in cases}
    audit = review / 'audit-parallel' / 'audit'
    a = read(audit / 'audit.json')
    counts = collections.Counter()
    geometry = collections.Counter()
    rounding = collections.Counter()
    seen = set()
    with gzip.open(audit / 'observed-checks.csv.gz', 'rt') as stream:
        for row in csv.DictReader(stream):
            c = ids[row['case']]
            key = row['case'], row['arm']
            assert key not in seen
            seen.add(key)
            kind = 'reserved-start-profile' if c['vstart'] >= c['vlmax'] else 'ordinary'
            form = c['mnemonic'] + '.' + c['form']
            counts[(form, row['arm'], kind, row['status'], row['semantic_status'])] += 1
            geometry[(c['vlen'], c['sew'], c['lmul'], row['arm'], kind, row['status'])] += 1
            rounding[(c['frm'], row['arm'], kind, row['status'])] += 1
    arms = ['Reference', 'B', 'M1', 'M2', 'BOTH']
    assert seen == {(c['id'], arm) for c in cases for arm in arms}
    assert len(seen) == a['executed_case_checks'] == len(cases) * 5
    tables = [
        ('PER_FORM.csv', ['form', 'arm', 'class', 'status', 'semantic_status', 'checks'], counts),
        ('PER_GEOMETRY.csv', ['vlen', 'sew', 'lmul', 'arm', 'class', 'status', 'checks'], geometry),
        ('PER_ROUNDING.csv', ['frm', 'arm', 'class', 'status', 'checks'], rounding),
    ]
    for name, fields, counter in tables:
        with (out / name).open('w') as stream:
            writer = csv.writer(stream)
            writer.writerow(fields)
            for key, count in sorted(counter.items()):
                writer.writerow([*key, count])
    anomalies = []
    execution_count = 0
    for unit in dict.fromkeys(c['unit'] for c in cases):
        for arm in arms:
            r = read(root / 'runs' / unit / arm / 'execution.json')
            execution_count += 1
            if r['returncode'] or r['timeout']:
                anomalies.append(dict(unit=unit, arm=arm, **r))
    declaration = read(base / 'DECLARATION.json')
    assert declaration['cases'] == len(cases) == 126062
    assert declaration['checks'] == len(seen) == 630310
    assert declaration['commands'] == execution_count == a['executed_commands'] == 45900
    assert read(root / 'identities-before.json') == read(root / 'identities-after.json')
    for source, name in [(audit / 'audit.json', 'AUDIT.json'),
                         (root / 'summary.json', 'RUNNER_SUMMARY.json'),
                         (base / 'STAGE_STATUS.json', 'ORIGINAL_STAGE_STATUS.json'),
                         (base / 'DECLARATION.json', 'DECLARATION.json'),
                         (review / 'audit-parallel' / 'parallel.json', 'PARALLEL.json'),
                         (review / 'audit-parallel' / 'workers.json', 'AUDIT_WORKERS.json'),
                         (review / 'controls-frozen' / 'summary.json', 'CONTROLS_FROZEN.json'),
                         (review / 'controls-geometry' / 'summary.json', 'CONTROLS_GEOMETRY.json'),
                         (review / 'STAGE_STATUS.json', 'STAGE_STATUS.json')]:
        shutil.copy2(source, out / name)
    shutil.copy2(audit / 'observed-checks.csv.gz', out / 'observed-checks.csv.gz')
    for folder in ['controls-frozen', 'controls-geometry']:
        for name in ['records.json', 'allowed.json', 'selected.json']:
            source = review / folder / name
            if source.exists():
                with gzip.GzipFile(filename=str(out / (folder + '-' + name + '.gz')), mode='wb', mtime=0) as dest:
                    dest.write(source.read_bytes())
    save(out / 'IDENTITIES.json', dict(before=read(root / 'identities-before.json'),
                                      after=read(root / 'identities-after.json'),
                                      runner=read(root / 'runner-identity.json')))
    save(out / 'EXECUTION_ANOMALIES.json', anomalies)
    save(out / 'VALIDATION.json', dict(cases=len(cases), checks=len(seen), commands=execution_count,
                                      ordinary_per_arm=sum(c['vstart'] < c['vlmax'] for c in cases),
                                      reserved_start_per_arm=sum(c['vstart'] >= c['vlmax'] for c in cases),
                                      raw_location='xbd:' + str(base), audit_location='xbd:' + str(review),
                                      acceptance='PENDING_MAIN_AUDIT_REVIEW_AND_FP_CHECKER_REVIEW',
                                      semantics='finite ordinary checks and separately labeled reserved-start observations; no full semantics proof',
                                      per_target_method_admission='NOT_CLAIMED'))
    save(out / 'EVIDENCE_SHA256.json', {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(out.iterdir()) if p.is_file()})
    print(json.dumps(read(out / 'VALIDATION.json')))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('base', type=Path)
    p.add_argument('review', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    run(a.base, a.review, a.output)
