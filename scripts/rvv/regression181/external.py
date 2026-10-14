"""Task181 replay of every retained original call on exact Task179 combined build.

The exact invoked snapshot is retained in Task181 raw evidence. No oracle runs;
unchanged Task120/121/122 acceptance functions and original configurations are
used with the pinned final Task179 executable. Never overwrite an execution root.
"""
import collections
import shutil
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
STAGE = Path('/home/vick/rvdbt-host512-task179-build/build')
assert not R.exists(), 'never overwrite or repeat an execution root'
R.mkdir()
import admission181 as admission, storage149 as storage
os.environ['RVV_COMPRESS']='1'
threading.Thread(target=admission.monitor,daemon=True).start()
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
sha = __import__('functools').lru_cache(maxsize=None)(chips.digest)
pins = {str(p): sha(p) for p in (STAGE/'bin/elfrun', STAGE/'lib/libdbtjitshared.so')}


def identity(call):
    return json.dumps(call, sort_keys=True, separators=(',', ':'))

assert pins == {str(STAGE/'bin/elfrun'):'8a468967852b8f16225b359fce99c0d22ab286d6314cb90a79934a7376207281',str(STAGE/'lib/libdbtjitshared.so'):'79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af'}
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
    complete = original[key]
    full = {identity(c) for c in complete}
    assert len(full) == len(complete)
    calls = complete
    assert len(calls) == {'chips':11744,'act':7668,'ara':1904}[suite]
    partition[suite] = dict(original=len(full),task178=len(full),prior_build_credit=0,
        original_manifest_sha256=sha(source),
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

save(R/'PARTITION.json', dict(suites=partition,original=21316,task178=21316,prior_build_credit=0,disjoint=True,identity='Complete original call object; canonical sorted-key JSON'))
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
save(R/'PARTITION.json', dict(suites=partition,original=21316,task178=21316,prior_build_credit=0,disjoint=True,identity='Complete original call object; canonical sorted-key JSON'))
save(R/'SELECTION.json', dict(rule='Complete original accepted queues; pilot exact-call subtraction within this build only',
     original_manifests=originals, calls={s:len(q) for s,q in queues.items()}, workers=2,
     scope='All original accepted calls; unchanged flags and predicates; no new reference execution'))
print('QUEUE', {s:len(q) for s,q in queues.items()}, flush=True)
env = dict(os.environ, LD_LIBRARY_PATH=str(STAGE/'lib')+':/lib/x86_64-linux-gnu')


def execute(suite,c):
    storage.reserve(R)
    d=R/suite/'raw'/(Path(c['case'])/c['arm'] if suite=='act' else c['id'])
    work=d/'work'; (work/'fs').mkdir(parents=True); (work/'cache').mkdir()
    elf=Path('/home/vick/rvv_final_regression_20261007/inputs')/(c['elf_sha256']+'.elf') if suite=='chips' else Path(c['elf']) if suite=='act' else ara.remote(c['elf'])
    assert sha(elf)==c['elf_sha256']
    os.symlink(elf,work/'fs/t.elf')
    if suite=='act':
        flags=[]
        for a in c['original_command'][1:]:
            if a.startswith('--dump-tbmap='):a='--dump-tbmap='+str(d/'tbmap.txt')
            elif a.startswith('--dump-tbcode='):a='--dump-tbcode='+str(d/'tbcode.txt')
            elif a.startswith('--fsroot='):a='--fsroot='+str(work/'fs')
            elif a.startswith('--cache='):a='--cache='+str(work/'cache')
            flags.append(a)
    else:flags=[x.replace('{WORK}',str(work)) for x in c['flags' if suite=='chips' else 'normalized_flags']]
    cmd=[str(STAGE/'bin/elfrun'),*flags]
    # storage.execute owns a new capture directory; work lives beside it.
    capture=d/'capture'
    rec=storage.execute(cmd,capture,env,c.get('timeout',120))
    for name in ('command.json','execution.json','stdout.gz','stderr.gz','stdout.storage.json','stderr.storage.json'):
        (capture/name).rename(d/name)
    capture.rmdir()
    out=storage.verify(d/'stdout');err=storage.verify(d/'stderr');rc=rec['returncode']
    detail=None
    with admission.predicate_slot():
     return classify_retained(suite,c,d,work,rec,out,err,rc)

def classify_retained(suite,c,d,work,rec,out,err,rc):
    detail=None
    if suite=='chips':status=chips.classify(rc,out,c,rec['timeout'])
    elif suite=='act':
        ok=eval(act.predicate,{'__builtins__':{}},dict(rc=rc,raw=(out+err).decode(errors='replace'),N=c['case'],sig=None))
        status='TIMEOUT' if rec['timeout'] else 'CRASH' if rc<0 else 'PASS' if ok else 'RESULT_MISMATCH'
    else:
        # One original parser reads stderr by path. Materialize only for its call.
        (d/'stderr').write_bytes(err);(d/'stdout').write_bytes(out)
        try:ok,detail=ara.observer(dict(c,_rawdir=d),rc,out,ara.staged_observer(c['producer']))
        finally:(d/'stderr').unlink();(d/'stdout').unlink()
        status='TIMEOUT' if rec['timeout'] else 'CRASH' if rc<0 else 'SCOPED_PASS' if ok and c['scope']=='TEST_CASE1_2_ONLY' else 'PASS' if ok else 'RESULT_MISMATCH'
        save(d/'observer.json',detail)
    result=dict(suite=suite,call=c,status=status,returncode=rc,timeout=rec['timeout'],elf_sha256=c['elf_sha256'],stdout_sha256=rec['stdout_sha256'],stderr_sha256=rec['stderr_sha256'],build=pins,whole_file_pass=status=='PASS' if suite=='ara' else None)
    save(d/'result.json',result)
    for name in ('tbmap.txt','tbcode.txt'):storage.compress(d/name)
    # Success-only caches and ELF links are regenerable scratch; never raw evidence.
    if status in ('PASS','SCOPED_PASS'):
        files=[dict(path=str(p),bytes=p.stat().st_size) for p in work.rglob('*') if p.is_file()]
        with admission.LOCK, (R/'CLEANUP.jsonl').open('a') as f:f.write(json.dumps(dict(reason='new successful regenerable work/cache only',files=files))+'\n')
        shutil.rmtree(work)
    if status not in ('PASS','SCOPED_PASS'):
        save(Path('/home/vick/rvv-task181/STOP_NEW_GUESTS.json'),result)
    return suite,status

counts=collections.defaultdict(collections.Counter)
pilots={'chips':next(c for c in queues['chips'] if not c['control']),
        'act':next(c for c in queues['act'] if c['case']=='Vls32-vle32.v' and c['arm']=='BOTH'),
        'ara':next(c for c in queues['ara'] if c['scope']!='TEST_CASE1_2_ONLY')}
save(R/'PILOT_CALLS.json',pilots)
for suite,c in pilots.items():
    s,status=execute(suite,c);counts[s][status]+=1
    save(R/('PILOT_'+s+'.json'),dict(call=c,status=status));print('PILOT',s,status,flush=True)
    assert status in ('PASS','SCOPED_PASS')
remaining=[(s,c) for s,q in queues.items() for c in q if identity(c)!=identity(pilots[s])]
assert len(remaining)+len(pilots)==sum(map(len,queues.values()))
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    for s,status in pool.map(lambda item:execute(*item),remaining):
        counts[s][status]+=1
        if sum(sum(c.values()) for c in counts.values())%100==0:print('PROGRESS',dict(counts),flush=True)
        if status not in ('PASS','SCOPED_PASS'):raise RuntimeError((s,status))
sha.cache_clear()
assert all(sha(p)==h for p,h in pins.items())
assert all(sha(p)==h for p,h in tools.items())
assert all(sha(p)==h for p,h in originals.items())
save(R/'IDENTITY_AFTER.json',pins);save(R/'EXECUTION_COUNTS.json',dict(counts))
(R/'COMPLETE').write_text('PASS\n');print('COMPLETE',dict(counts),flush=True)
