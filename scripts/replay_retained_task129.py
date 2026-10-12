"""Execute the exact retained original-call remainder after Task128 on xbd.

The actual invoked version is retained in Task129 raw evidence. No oracle runs;
unchanged Task120/121/122 acceptance functions and original configurations are
used with the pinned Task128 executable. Never overwrite an execution root.
"""
import collections
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import threading
import traceback
import subprocess
import sys

R = Path(sys.argv[1]).resolve()
PREVIOUS = Path('/home/vick/rvdbt-host512-task128')
STAGE = PREVIOUS / 'build'
assert not R.exists(), 'never overwrite or repeat an execution root'
R.mkdir()
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


def identity(call):
    return json.dumps(call, sort_keys=True, separators=(',', ':'))

expected_pins = {
 str(STAGE/'bin/elfrun'): '849e6dd0a11e78d19319a2d04b93a644f4dd04e9fbc86dd8b350288392d655a3',
 str(STAGE/'lib/libdbtjitshared.so'): '79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af'}
assert pins == expected_pins
assert not os.environ.get('LD_PRELOAD') and not os.environ.get('LD_AUDIT')
partition = {}
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
queues = {}
originals = {}
for suite, source in [('chips', '/home/vick/chips-current120/manifest.json'),
                      ('act', '/home/vick/act-current121/QUEUE.json'),
                      ('ara', '/home/vick/ara-current122/QUEUE.json')]:
    original = act.read(Path(source))
    originals[source] = sha(source)
    key = 'cells' if suite == 'chips' else 'calls'
    prior = act.read(PREVIOUS/suite/'QUEUE.json')[key]
    complete = original[key]
    full = {identity(c) for c in complete}
    selected = {identity(c) for c in prior}
    assert len(full) == len(complete) and len(selected) == len(prior)
    assert selected <= full
    calls = [c for c in complete if identity(c) not in selected]
    remaining = {identity(c) for c in calls}
    assert not remaining & selected and remaining | selected == full
    expected = {'chips':(11744,1948,9796),'act':(7668,3828,3840),'ara':(1904,128,1776)}[suite]
    assert (len(full),len(selected),len(remaining)) == expected
    partition[suite] = dict(original=len(full),task128=len(selected),task129=len(remaining),
        intersection=0,union=len(full),original_manifest_sha256=sha(source),
        task128_queue_sha256=sha(PREVIOUS/suite/'QUEUE.json'),
        full_call_identities_sha256=__import__('hashlib').sha256('\n'.join(sorted(full)).encode()).hexdigest())
    original[key] = calls
    if suite == 'chips':
        original['prior_candidate_task120'] = original['candidate']
        original['candidate'] = {'build': {'stage/elfrun': pins[str(STAGE/'bin/elfrun')],
                                         'stage/libdbtjitshared.so': pins[str(STAGE/'lib/libdbtjitshared.so')]}}
    elif suite == 'act':
        original['entries'] = [e for e in original['entries'] if e['case'] in {c['case'] for c in calls}
                              or e['original_status'] == 'REFERENCE_ERROR']
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

save(R/'PARTITION.json', dict(suites=partition,original=21316,task128=5904,task129=15412,disjoint=True,identity='Complete original call object; canonical sorted-key JSON'))
# Authenticate selected source/checker/ELF and observer identities before guests.
checked = {}
for c in queues['chips']:
    p = Path('/home/vick/rvv_final_regression_20261007/inputs')/(c['elf_sha256']+'.elf')
    assert sha(p) == c['elf_sha256']
    checked[str(p)] = c['elf_sha256']
for e in act.read(R/'act/QUEUE.json')['entries']:
    if e['original_status'] == 'REFERENCE_ERROR':
        continue
    for field in ('source', 'elf', 'checker', 'expected', 'capture'):
        assert sha(e[field]) == e[field+'_sha256'], e[field]
        checked[e[field]] = e[field+'_sha256']
for c in queues['ara']:
    for field in ('source', 'elf', 'adapter', 'runner'):
        candidates = [ara.remote(c[field]) if field != 'runner' else ara.staged_observer(c[field]),
            ara.staged_observer(c[field]), PREVIOUS/'source-evidence'/c[field+'_sha256'],
            Path('/home/vick/task129-source-evidence')/c[field+'_sha256']]
        p = next((p for p in candidates if p.is_file() and sha(p) == c[field+'_sha256']),None)
        assert p is not None, c[field]
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
save(R/'PARTITION.json', dict(suites=partition,original=21316,task128=5904,task129=15412,disjoint=True,identity='Complete original call object; canonical sorted-key JSON'))
save(R/'SELECTION.json', dict(rule='Exact full-call subtraction of Task128 from original accepted queues',
     original_manifests=originals, calls={s:len(q) for s,q in queues.items()}, workers=4,
     scope='Remaining original accepted calls; unchanged flags and predicates; no new reference execution'))
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
# At most four in-flight calls. Stop only the failed suite; never schedule its
# remaining calls until diagnosis. Original scoped outcomes are accepted as scoped.
pending = {s:iter(q) for s,q in queues.items()}
stopped = set()
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    active = {}
    def submit():
        for s in pending:
            if s in stopped:
                continue
            c = next(pending[s], None)
            if c is not None:
                active[pool.submit(execute,s,c)] = (s,c)
                return True
        return False
    for _ in range(4):
        submit()
    while active:
        done,_ = concurrent.futures.wait(active,return_when=concurrent.futures.FIRST_COMPLETED)
        for f in done:
            suite,call = active.pop(f)
            try:
                s,status = f.result()
            except Exception:
                s,status = suite,'RUNNER_ERROR'
                save(R/(suite+'-runner-error-'+str(call.get('id',call.get('case')))+'-'+str(call.get('arm',''))+'.json'),
                     dict(call=call,traceback=traceback.format_exc()))
                traceback.print_exc()
            counts[s][status] += 1
            if status not in ('PASS','SCOPED_PASS'):
                stopped.add(s)
                save(R/'STOPPED.json',dict(suites=sorted(stopped),failure_suite=s,call=call,status=status))
                print('STOPPED',s,status,call.get('id',call.get('case')),flush=True)
            if sum(sum(c.values()) for c in counts.values()) % 100 == 0:
                print('PROGRESS',dict(counts),flush=True)
            submit()
assert all(sha(p) == h for p,h in pins.items())
assert all(sha(p) == h for p,h in tools.items())
assert all(sha(p) == h for p,h in originals.items())
save(R/'IDENTITY_AFTER.json',pins)
save(R/'EXECUTION_COUNTS.json',dict(counts))
save(R/'UNATTEMPTED.json',{s:[c for c in q if not (R/s/'raw'/(Path(c['case'])/c['arm'] if s=='act' else c['id'])/'result.json').exists()] for s,q in queues.items()})
print('COMPLETE',dict(counts),flush=True)
