#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Partition offline replay while retaining a snapshot's unchanged auditor.

Guest execution, semantic predicates and raw files are not modified. Each
subprocess receives a disjoint unit view accepted by the existing pilot filter.
The parent validates the original denominator before constructing these views.
"""
import argparse
import collections
import concurrent.futures
import csv
import gzip
import hashlib
import heapq
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ARMS = ('Reference', 'B', 'M1', 'M2', 'BOTH')


def read(path):
    return json.loads(path.read_text())


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_auditor(path):
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location('snapshot_audit', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_inputs(module, manifest, results):
    cases = manifest['cases']
    generated = module.v.manifest_cases(manifest.get('family', 'vadd145'))
    for i, case in enumerate(generated):
        case['ordinal'] = i
    if 'pilot_units' in manifest:
        selected = set(manifest['pilot_units'])
        if not selected <= {case['unit'] for case in generated}:
            raise ValueError('unknown original pilot unit')
        generated = [case for case in generated if case['unit'] in selected]
    if generated != cases:
        raise ValueError('original manifest differs from finite generator')
    ids = {case['id'] for case in cases}
    if len(ids) != len(cases) or not cases:
        raise ValueError('duplicate or empty original manifest')
    expected = {(case['id'], arm) for case in cases for arm in ARMS}
    observed = {(row['case'], row['arm']) for row in results}
    if observed != expected or len(results) != len(expected):
        raise ValueError('missing/duplicate original result')


def partition(cases, jobs, packet_size):
    units = collections.defaultdict(list)
    for case in cases:
        units[case['unit']].append(case)
    assignments = [set() for _ in range(min(jobs, len(units)))]
    loads = [0] * len(assignments)
    for unit, rows in sorted(units.items(), key=lambda pair:
                            len(pair[1]) * packet_size(pair[1][0]), reverse=True):
        i = min(range(len(loads)), key=loads.__getitem__)
        assignments[i].add(unit)
        loads[i] += len(rows) * packet_size(rows[0])
    return units, assignments, loads


def replay(task):
    script, view, output, log = task
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    start = time.monotonic()
    with log.open('wb') as stream:
        run = subprocess.run([sys.executable, str(script), str(view), str(output)],
                             stdout=stream, stderr=subprocess.STDOUT, env=env)
    return dict(view=str(view), output=str(output), log=str(log),
                returncode=run.returncode, seconds=time.monotonic() - start)


def merge_outputs(parts, target, cases):
    by_id = {case['id']: case for case in cases}
    unit_rank = {unit: i for i, unit in enumerate(dict.fromkeys(c['unit'] for c in cases))}
    arm_rank = {arm: i for i, arm in enumerate(ARMS)}
    def key(row):
        case = by_id[row['case']]
        return unit_rank[case['unit']], arm_rank[row['arm']], case['ordinal']

    streams = []
    counts = {arm: collections.Counter() for arm in ARMS}
    failures, adapters, pins = [], [], {}
    summaries = [read(part / 'audit.json') for part in parts]
    seen = set()
    try:
        streams = [gzip.open(part / 'observed-checks.csv.gz', 'rt') for part in parts]
        readers = [csv.DictReader(stream) for stream in streams]
        fields = readers[0].fieldnames
        if any(reader.fieldnames != fields for reader in readers):
            raise ValueError('shard CSV schemas differ')
        with gzip.open(target / 'observed-checks.csv.gz', 'wt') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            previous = None
            for row in heapq.merge(*readers, key=key):
                identity = row['case'], row['arm']
                current = key(row)
                if identity in seen or (previous is not None and current < previous):
                    raise ValueError('duplicate or unordered merged result')
                seen.add(identity)
                previous = current
                counts[row['arm']][row['status']] += 1
                writer.writerow(row)
    finally:
        for stream in streams:
            stream.close()
    expected = {(case['id'], arm) for case in cases for arm in ARMS}
    if seen != expected:
        raise ValueError('merged audit does not cover original denominator')
    total = dict(summaries[0])
    for field in ('planned_cases', 'executed_case_checks', 'planned_commands',
                  'executed_commands', 'aggregate_command_seconds', 'adapter_verified_units'):
        total[field] = sum(summary[field] for summary in summaries)
    for part, summary in zip(parts, summaries):
        failures.extend(summary['failures'])
        adapters.extend(read(part / 'adapter-verification.json'))
        incoming = read(part / 'guest-pins.json')
        if pins.keys() & incoming.keys():
            raise ValueError('duplicate guest pin across shards')
        pins.update(incoming)
        for path in part.glob('*-targets.json'):
            shutil.copy2(path, target / path.name)
    expected_counts = {arm: dict(sum((collections.Counter(s['counts'][arm])
                                     for s in summaries), collections.Counter()))
                       for arm in ARMS}
    for arm in ARMS:
        if collections.Counter(expected_counts[arm]) != counts[arm]:
            raise ValueError('merged row/summary counts differ')
    total['counts'] = {arm: {status: counts[arm][status] for status in
                            ('PASS', 'FAIL', 'ISA_ONLY_REFERENCE_BLOCKED')} for arm in ARMS}
    total['failures'] = failures
    if total['planned_cases'] != len(cases) or total['executed_case_checks'] != len(expected):
        raise ValueError('merged summary denominator mismatch')
    adapters.sort(key=lambda row: unit_rank[row['unit']])
    save(target / 'adapter-verification.json', adapters)
    save(target / 'guest-pins.json', pins)
    save(target / 'audit.json', total)
    return total


def run(root, out, script, jobs, retain_failures=False):
    if jobs < 1:
        raise ValueError('jobs must be positive')
    root, out, script = root.resolve(), out.resolve(), script.resolve()
    if out == root or root in out.parents:
        raise ValueError('write output outside the immutable corpus')
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    module = load_auditor(script)
    manifest_path, result_path = root / 'manifest.json', root / 'results.json'
    inputs = [manifest_path, result_path, root / 'build-commands.json']
    inputs += sorted(script.parent.glob('*.py'))
    before = {str(path): digest(path) for path in inputs}
    manifest, results = read(manifest_path), read(result_path)
    validate_inputs(module, manifest, results)
    # Configuration determinism spans units; retain its original whole-corpus audit.
    if manifest.get('family') in ('configuration147', 'configuration148'):
        jobs = 1
    if jobs == 1:
        receipt = replay((script, root, out / 'audit', out / 'serial.log'))
        save(out / 'workers.json', [receipt])
        if receipt['returncode']:
            raise RuntimeError('serial auditor failed; see serial.log')
        total = read(out / 'audit/audit.json')
        loads = []
    else:
        units, assignments, loads = partition(manifest['cases'], jobs, module.v.packet_size)
        builds = read(root / 'build-commands.json')
        owner = {unit: i for i, group in enumerate(assignments) for unit in group}
        case_owner = {case['id']: owner[case['unit']] for case in manifest['cases']}
        case_parts, result_parts, build_parts = ([[] for _ in assignments] for _ in range(3))
        for case in manifest['cases']:
            case_parts[owner[case['unit']]].append(case)
        for row in results:
            result_parts[case_owner[row['case']]].append(row)
        for row in builds:
            unit = Path(row['command'][-1]).parent.name
            if unit not in owner:
                raise ValueError('build receipt outside original manifest')
            build_parts[owner[unit]].append(row)
        tasks = []
        for i, group in enumerate(assignments):
            base = out / f'shard-{i:02d}'
            view = base / 'corpus'
            view.mkdir(parents=True)
            selected = dict(manifest, cases=case_parts[i], pilot_units=sorted(group),
                            units=len(group), planned_case_executions=len(case_parts[i]) * 5)
            save(view / 'manifest.json', selected)
            save(view / 'results.json', result_parts[i])
            save(view / 'build-commands.json', build_parts[i])
            os.symlink(root / 'runs', view / 'runs')
            for unit in group:
                os.symlink(root / unit, view / unit)
            tasks.append((script, view, base / 'audit', base / 'worker.log'))
        # Threads supervise independent Python processes; predicate work has no GIL sharing.
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as pool:
            receipts = list(pool.map(replay, tasks))
        save(out / 'workers.json', receipts)
        if any(row['returncode'] for row in receipts):
            raise RuntimeError('shard auditor failed; see workers.json and worker logs')
        target = out / 'audit'
        target.mkdir()
        total = merge_outputs([task[2] for task in tasks], target, manifest['cases'])
    after = {str(path): digest(path) for path in inputs}
    if before != after:
        raise ValueError('input or frozen checker changed during replay')
    save(out / 'parallel.json', dict(jobs=jobs, seconds=time.monotonic() - started,
                                     snapshot_auditor=str(script), inputs=before,
                                     estimated_packet_bytes_by_shard=loads,
                                     original_cases=len(manifest['cases']),
                                     executed_checks=total['executed_case_checks']))
    failures = any(row['FAIL'] or row['ISA_ONLY_REFERENCE_BLOCKED'] for row in total['counts'].values())
    if failures:
        if retain_failures:
            (out / 'ALL_ACCOUNTED_WITH_FAILURES').write_text('Complete unchanged predicates; semantic failures remain.\n')
            print(json.dumps(dict(original_cases=len(manifest['cases']),executed_checks=total['executed_case_checks'],counts=total['counts'],audit_complete=True,semantic_pass=False)))
            return 1
        raise RuntimeError('audited failures/reference blockers remain')
    (out / 'COMPLETE').write_text('All original cases and arms accounted for.\n')
    receipt = read(out / 'parallel.json')
    print(json.dumps({key: receipt[key] for key in
                      ('jobs', 'seconds', 'original_cases', 'executed_checks')}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--audit-script', required=True, type=Path)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--retain-failures', action='store_true', help='retain complete failed audit, return 1; never mark PASS')
    args = parser.parse_args()
    sys.exit(run(args.root, args.output, args.audit_script, args.jobs, args.retain_failures))
