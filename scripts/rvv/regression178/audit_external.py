"""Independent retained-stream audit using frozen external acceptance functions."""
import collections,concurrent.futures,fcntl,hashlib,importlib.util,json,sys
from pathlib import Path
import storage149 as storage
lock=open('/tmp/rvv-task178-offline.lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
B=Path('/home/vick/rvv-task178');R=B/'external';assert (R/'COMPLETE').exists()
sys.path.insert(0,'/home/vick/ara-current122')
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
chips=module('chips178','/home/vick/chips-current120/runner.py');act=module('act178','/home/vick/act-current121/run121.py');ara=module('ara178','/home/vick/ara-current122/run122.py')
ara.R=R/'ara'
read=lambda p:json.loads(Path(p).read_text());sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
pins=read(R/'IDENTITY_BEFORE.json');assert pins==read(R/'IDENTITY_AFTER.json')
assert all(sha(p)==h for p,h in pins.items())
assert all(sha(p)==h for p,h in read(R/'TOOLS.json').items())
queues={s:read(R/s/'QUEUE.json')['cells' if s=='chips' else 'calls'] for s in ('chips','act','ara')}
out=R/'audit';out.mkdir(exist_ok=False)
def check(item):
 suite,c=item;d=R/suite/'raw'/(Path(c['case'])/c['arm'] if suite=='act' else c['id']);r=read(d/'result.json');rec=read(d/'execution.json');cmd=read(d/'command.json')
 raw=storage.verify(d/'stdout');err=storage.verify(d/'stderr')
 assert hashlib.sha256(raw).hexdigest()==r['stdout_sha256']==rec['stdout_sha256']
 assert hashlib.sha256(err).hexdigest()==r['stderr_sha256']==rec['stderr_sha256']
 assert r['call']==c and r['build']==pins and cmd[0] in pins
 def normalize(xs):
  return ['--fsroot={WORK}/fs' if x.startswith('--fsroot=') else '--cache={WORK}/cache' if x.startswith('--cache=') else x for x in xs if not x.startswith(('--dump-tbmap=','--dump-tbcode='))]
 expected=c['flags'] if suite=='chips' else c['original_command'][1:] if suite=='act' else c['normalized_flags']
 assert normalize(cmd[1:])==normalize(expected)
 assert rec['returncode']==r['returncode'] and rec['timeout']==r['timeout']
 rc=r['returncode'];detail=None
 if suite=='chips':status=chips.classify(rc,raw,c,r['timeout'])
 elif suite=='act':
  ok=eval(act.predicate,{'__builtins__':{}},dict(rc=rc,raw=(raw+err).decode(errors='replace'),N=c['case'],sig=None));status='TIMEOUT' if r['timeout'] else 'CRASH' if rc<0 else 'PASS' if ok else 'RESULT_MISMATCH'
 else:
  # Preserve the original path-based parser without changing its expressions.
  (d/'stderr').write_bytes(err);(d/'stdout').write_bytes(raw)
  try:ok,detail=ara.observer(dict(c,_rawdir=d),rc,raw,ara.staged_observer(c['producer']))
  finally:(d/'stderr').unlink();(d/'stdout').unlink()
  assert json.loads(json.dumps(detail))==read(d/'observer.json')
  status='TIMEOUT' if r['timeout'] else 'CRASH' if rc<0 else 'SCOPED_PASS' if ok and c['scope']=='TEST_CASE1_2_ONLY' else 'PASS' if ok else 'RESULT_MISMATCH'
 assert status==r['status'] and status in ('PASS','SCOPED_PASS')
 return dict(suite=suite,id=c.get('id',c.get('case')),arm=c.get('arm'),status=status,control=c.get('control',False),scope=c.get('scope'),elf_sha256=c['elf_sha256'],command_sha256=sha(d/'command.json'),result_sha256=sha(d/'result.json'))
rows=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
 for r in pool.map(check,[(s,c) for s,q in queues.items() for c in q]):rows.append(r)
import gzip
(out/'EXACT_JOINS.json.gz').write_bytes(gzip.compress(json.dumps(rows,separators=(',',':')).encode(),mtime=0))
summary={s:dict(planned=len(q),completed=sum(r['suite']==s for r in rows),failed=0,blocked=0,counts=dict(collections.Counter(r['status'] for r in rows if r['suite']==s)),controls=sum(r['suite']==s and r['control'] for r in rows)) for s,q in queues.items()}
(out/'SUMMARY.json').write_text(json.dumps(dict(suites=summary,build=pins,original_blockers=read(R/'act/QUEUE.json')['counts']['blocked_cases'],new_reference_calls=0,exact_joins=len(rows)),indent=2)+'\n')
(out/'COMPLETE').write_text('PASS\n');print(summary,flush=True)
