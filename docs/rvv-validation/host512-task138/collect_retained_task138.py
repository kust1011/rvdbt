"""Read-only original-predicate and raw-identity audit of the Task138 complete retained corpus."""
import collections
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys

root = Path(sys.argv[1]).resolve()
read = lambda p: json.loads(Path(p).read_text())
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
save = lambda p,x: Path(p).write_text(json.dumps(x, indent=2)+'\n')
pins = read(root/'IDENTITY_BEFORE.json')
assert all(sha(p) == h for p,h in read(root/'INPUT_AUDIT.json').items())
assert all(sha(p) == h for p,h in read(root/'TOOLS.json').items())
assert pins == read(root/'IDENTITY_AFTER.json')
assert all(sha(p) == h for p,h in pins.items())
previous = Path('/home/vick/rvdbt-goldens-task137/current')
source_equality = read('/home/vick/rvdbt-goldens-task137/SOURCE_EQUALITY.json')
save(root/'SOURCE_EQUALITY.json', source_equality)
import importlib.util
sys.path.insert(0,'/home/vick/ara-current122')
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
chips=module('original120','/home/vick/chips-current120/runner.py')
act=module('original121','/home/vick/act-current121/run121.py')
ara=module('original122','/home/vick/ara-current122/run122.py');ara.R=root/'ara'
records = []
counts = collections.defaultdict(collections.Counter)
arms = collections.defaultdict(collections.Counter)
forms = collections.defaultdict(set)
for suite, origin in [('chips','/home/vick/chips-current120/manifest.json'),
                      ('act','/home/vick/act-current121/QUEUE.json'),
                      ('ara','/home/vick/ara-current122/QUEUE.json')]:
    original = read(origin)
    selected = read(root/suite/'QUEUE.json')
    key = 'cells' if suite == 'chips' else 'calls'
    assert all(c in original[key] for c in selected[key]), 'changed original call'
    entries = {e['case']:e for e in selected.get('entries',[])}
    for c in selected[key]:
        d = root/suite/'raw'/(Path(c['case'])/c['arm'] if suite=='act' else c['id'])
        result, command = read(d/'result.json'), read(d/'command.json')
        assert command[0] in pins and read(d/'IDENTITY.json') == pins
        assert sha(d/'stdout') == result['stdout_sha256']
        assert sha(d/'stderr') == result['stderr_sha256']
        normalized = []
        for flag in command[1:]:
            if flag.startswith('--fsroot='): flag = '--fsroot={WORK}/fs'
            elif flag.startswith('--cache='): flag = '--cache={WORK}/cache'
            elif flag.startswith(('--dump-tbmap=','--dump-tbcode=')): continue
            normalized.append(flag)
        assert normalized == (c['flags'] if suite=='chips' else c['normalized_flags'])
        if suite == 'chips':
            assert chips.classify(result['returncode'],(d/'stdout').read_bytes(),c,
                result['status']=='TIMEOUT',result['error']) == result['status']
            assert read(d/'case.json') == c
        elif suite == 'act':
            ok = eval(act.predicate,{'__builtins__':{}},dict(rc=result['returncode'],
                raw=(d/'stdout').read_text(errors='replace')+(d/'stderr').read_text(errors='replace'),N=c['case'],sig=None))
            assert ok == result['original_predicate_pass']
        else:
            ok,detail = ara.observer(dict(c,_rawdir=d),result['returncode'],(d/'stdout').read_bytes(),ara.staged_observer(c['producer']))
            assert ok == result['accepted_scope_pass'] and json.loads(json.dumps(detail)) == read(d/'observer.json')
            assert result['whole_file_pass'] == (ok and c['scope'] != 'TEST_CASE1_2_ONLY')
        text = (d/'stderr').read_text(errors='replace')
        routes = {op:int(n) for op,n in re.findall(r'^RVV_ROUTE (\S+) handler_calls=(\d+)$',text,re.M)}
        direct = re.findall(r'^RVV_DIRECT (.*)$',text,re.M)
        caseforms = [a.get('form') for a in c['aliases']] if suite=='chips' else c.get('forms', [entries[c['case']]['form']] if suite=='act' else [])
        caseforms = sorted({f for f in caseforms if isinstance(f,str)})
        arm = c['aliases'][0]['arm'] if suite=='chips' else c['arm']
        counts[suite][result['status']] += 1
        arms[suite][arm] += 1
        forms[suite].update(caseforms)
        records.append(dict(suite=suite, id=c.get('id',c.get('case')), case=c.get('case'),
            arm=arm, forms=caseforms, receipt=str(d), command=command, result=result,
            routes=routes, direct=direct, executable_pins=pins, original_call=c,
            files={str(p.relative_to(d)):sha(p) for p in d.iterdir() if p.is_file()}))
assert {s:dict(c) for s,c in counts.items()} == read(root/'EXECUTION_COUNTS.json')
with gzip.open(root/'RECEIPTS.json.gz','wt') as out:
    json.dump(records,out,separators=(',',':'))
save(root/'AUDIT.json', dict(status='PASS', raw_calls=len(records),
    counts={s:dict(c) for s,c in counts.items()}, per_arm={s:dict(c) for s,c in arms.items()},
    forms={s:sorted(f) for s,f in forms.items()},
    checks='Original call membership, complete normalized flags, candidate before/after, per-call identity, stream/result hashes; acceptance is the original predicate executed by the retained runner',
    limitations='Aggregate direct counts do not identify target admission; other-vector merges families'))
print('AUDIT_PASS',len(records))
