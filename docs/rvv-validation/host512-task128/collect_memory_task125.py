"""Read-only receipt audit and identity collection on the isolated Task125 root."""
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
assert pins == read(root/'IDENTITY_AFTER.json')
assert all(sha(p) == h for p,h in pins.items())
head = read(root/'head-inputs.json')
different = [p for p,h in head.items() if sha(root/'source'/p) != h]
save(root/'SOURCE_EQUALITY.json', dict(inputs=len(head), differences=different,
     production_matches=not different, source_hashes=head))
assert not different
deps = {}
prior = Path('/home/vick/rvdbt-host-fault-task124/source/dbt/third_party')
for p in prior.rglob('*'):
    if p.is_file():
        rel = str(p.relative_to(prior))
        assert sha(p) == sha(root/'source/dbt/third_party'/rel), rel
        deps[rel] = sha(p)
save(root/'DEPENDENCY_EQUALITY.json', dict(prior=str(prior), equal_files=len(deps), hashes=deps))
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
save(root/'BUILD_IDENTITY.json', {str(p.relative_to(root)):dict(sha256=sha(p),bytes=p.stat().st_size)
    for p in sorted((root/'build/bin').iterdir()) if p.is_file()} | {
    'build/lib/libdbtjitshared.so':dict(sha256=sha(root/'build/lib/libdbtjitshared.so'),bytes=(root/'build/lib/libdbtjitshared.so').stat().st_size)})
print('AUDIT_PASS', len(records))
