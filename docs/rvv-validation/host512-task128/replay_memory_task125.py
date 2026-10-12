"""Replay only original manifest memory targets; run on retained xbd evidence tree.

No oracle is executed. Acceptance functions are imported unchanged from retained
Task120/121/122 runners; all calls use the new production executable identity.
"""
import collections
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import sys

R = Path(sys.argv[1]).resolve()
STAGE = R / 'build'
sys.path.insert(0, '/home/vick/ara-current122')


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


chips = module('original120', '/home/vick/chips-current120/runner.py')
act = module('original121', '/home/vick/act-current121/run121.py')
ara = module('original122', '/home/vick/ara-current122/run122.py')
save = act.save
sha = chips.digest
pins = {str(p): sha(p) for p in (STAGE/'bin/elfrun', STAGE/'lib/libdbtjitshared.so')}


def memory(form):
    return isinstance(form, str) and bool(re.match(
        r'^v[ls](?:e\d|se\d|[ou]xei|[ou]xseg|seg|sseg|m\.|[1248]r)', form))


resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
queues = {}
originals = {}
for suite, source in [('chips', '/home/vick/chips-current120/manifest.json'),
                      ('act', '/home/vick/act-current121/QUEUE.json'),
                      ('ara', '/home/vick/ara-current122/QUEUE.json')]:
    original = act.read(Path(source))
    originals[source] = sha(source)
    if suite == 'chips':
        calls = [c for c in original['cells'] if any(memory(a.get('form')) for a in c['aliases'])]
        original['prior_candidate_task120'] = original['candidate']
        original['candidate'] = {'build': {'stage/elfrun': pins[str(STAGE/'bin/elfrun')],
                                         'stage/libdbtjitshared.so': pins[str(STAGE/'lib/libdbtjitshared.so')]}}
        original['cells'] = calls
    else:
        entries = {e['case']: e for e in original.get('entries', [])}
        calls = [c for c in original['calls'] if any(memory(f) for f in
                 (c.get('forms') or [entries[c['case']]['form']]))]
        original['calls'] = calls
        if entries:
            original['entries'] = [e for e in original['entries'] if e['case'] in {c['case'] for c in calls}]
    d = R/suite
    d.mkdir()
    save(d/'QUEUE.json', original)
    queues[suite] = calls
    for producer in (act, ara):
        producer.STAGE = STAGE
        producer.PINS = pins
    if suite == 'act':
        act.R = d
    if suite == 'ara':
        ara.R = d
        os.symlink('/home/vick/ara-current122/observers', d/'observers')
    (d/'raw').mkdir()

# Authenticate selected source/checker/ELF and observer identities before guests.
checked = {}
for c in queues['chips']:
    p = Path('/home/vick/rvv_final_regression_20261007/inputs')/(c['elf_sha256']+'.elf')
    assert sha(p) == c['elf_sha256']
    checked[str(p)] = c['elf_sha256']
for e in act.read(R/'act/QUEUE.json')['entries']:
    for field in ('source', 'elf', 'checker', 'expected', 'capture'):
        assert sha(e[field]) == e[field+'_sha256'], e[field]
        checked[e[field]] = e[field+'_sha256']
for c in queues['ara']:
    for field in ('source', 'elf', 'adapter', 'runner'):
        p = ara.remote(c[field]) if field != 'runner' else ara.staged_observer(c[field])
        if not p.is_file():
            p = ara.staged_observer(c[field])
        if not p.is_file():
            p = R/'source-evidence'/c[field+'_sha256']
        assert sha(p) == c[field+'_sha256'], str(p)
        checked[str(p)] = c[field+'_sha256']
for p, h in act.read(R/'ara/QUEUE.json')['inputs'].items():
    local = ara.staged_observer(p)
    if local.is_file():
        assert sha(local) == h, str(local)
        checked[str(local)] = h
tools = {p: sha(p) for p in ('/home/vick/chips-current120/runner.py',
         '/home/vick/act-current121/run121.py', '/home/vick/rvv-task109/execute109.py',
         '/home/vick/ara-current122/run122.py', '/home/vick/ara-current122/rvv_ara_replay.py', __file__)}
save(R/'INPUT_AUDIT.json', checked)
save(R/'TOOLS.json', tools)
save(R/'IDENTITY_BEFORE.json', pins)
save(R/'SELECTION.json', dict(rule=memory.__doc__, regex=r'^v[ls](?:e\d|se\d|[ou]xei|[ou]xseg|seg|sseg|m\.|[1248]r)',
     original_manifests=originals, calls={s:len(q) for s,q in queues.items()}, workers=4,
     scope='Original memory targets only; unchanged flags and predicates; no new reference execution'))
print('QUEUE', {s:len(q) for s,q in queues.items()}, flush=True)
env = dict(os.environ, LD_LIBRARY_PATH=str(STAGE/'lib')+':/lib/x86_64-linux-gnu')


def execute(suite, c):
    assert all(sha(p) == h for p,h in pins.items())
    if suite == 'chips':
        result = chips.execute(c, STAGE/'bin/elfrun', Path('/home/vick/rvv_final_regression_20261007/inputs'),
                               R/'chips/raw', env, 120)
        save(R/'chips/raw'/c['id']/'IDENTITY.json', pins)
        status = result['status']
    else:
        status = (act if suite == 'act' else ara).run(c)
    return suite, status


counts = collections.defaultdict(collections.Counter)
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    work = [pool.submit(execute, s, c) for s,q in queues.items() for c in q]
    for f in concurrent.futures.as_completed(work):
        try:
            s, status = f.result()
            counts[s][status] += 1
        except Exception:
            import traceback
            counts['launcher']['RUNNER_ERROR'] += 1
            traceback.print_exc()
        if sum(sum(c.values()) for c in counts.values()) % 100 == 0:
            print('PROGRESS', dict(counts), flush=True)
assert all(sha(p) == h for p,h in pins.items())
assert all(sha(p) == h for p,h in tools.items())
save(R/'IDENTITY_AFTER.json', pins)
save(R/'EXECUTION_COUNTS.json', dict(counts))
print('COMPLETE', dict(counts), flush=True)
