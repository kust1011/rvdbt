"""Repair the compressed-stream adapter using original captured DUT calls only."""
import ast,os,shutil,collections,hashlib,importlib.util,json,sys
from pathlib import Path
import storage149 as storage,admission178 as admission
B=Path('/home/vick/rvv-task178');R=B/'external';sys.path.insert(0,'/home/vick/ara-current122')
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
chips=module('chips178','/home/vick/chips-current120/runner.py');act=module('act178','/home/vick/act-current121/run121.py');ara=module('ara178','/home/vick/ara-current122/run122.py');ara.R=R/'ara'
read=lambda p:json.loads(Path(p).read_text());sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
STAGE=Path('/home/vick/rvdbt-host512-task174-build/build');env=dict(os.environ,LD_LIBRARY_PATH=str(STAGE/'lib')+':/lib/x86_64-linux-gnu');os.environ['RVV_COMPRESS']='1'
source=Path(__file__).with_name('external_fixed.py').read_text();tree=ast.parse(source);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='execute');save=lambda p,x:Path(p).write_text(json.dumps(x,indent=2)+'\n');exec(compile(ast.Module(body=[node],type_ignores=[]),'external-fixed178','exec'),globals())
pins=read(R/'IDENTITY_BEFORE.json');assert all(sha(p)==h for p,h in pins.items());counts=collections.defaultdict(collections.Counter);recovered=[]
for suite in ('chips','act','ara'):
 q=read(R/suite/'QUEUE.json')
 for c in q['cells' if suite=='chips' else 'calls']:
  d=R/suite/'raw'/(Path(c['case'])/c['arm'] if suite=='act' else c['id'])
  if (d/'result.json').exists():counts[suite][read(d/'result.json')['status']]+=1;continue
  if not (d/'execution.json').exists():
   assert not d.exists(),str(d)
   _,status=execute(suite,c);counts[suite][status]+=1;recovered.append(dict(id=c.get('id',c.get('case')),status=status,new_dut_calls=1,reason='unattempted after original adapter exception cancelled pending futures'));continue
  rec=read(d/'execution.json');raw=storage.verify(d/'stdout');err=storage.verify(d/'stderr');rc=rec['returncode'];detail=None
  assert hashlib.sha256(raw).hexdigest()==rec['stdout_sha256'] and hashlib.sha256(err).hexdigest()==rec['stderr_sha256']
  assert suite=='ara','only original Ara parser path adaptation is authorized here'
  (d/'stdout').write_bytes(raw);(d/'stderr').write_bytes(err)
  try:ok,detail=ara.observer(dict(c,_rawdir=d),rc,raw,ara.staged_observer(c['producer']))
  finally:(d/'stdout').unlink();(d/'stderr').unlink()
  status='TIMEOUT' if rec['timeout'] else 'CRASH' if rc<0 else 'SCOPED_PASS' if ok and c['scope']=='TEST_CASE1_2_ONLY' else 'PASS' if ok else 'RESULT_MISMATCH'
  assert status in ('PASS','SCOPED_PASS'),(c,status)
  (d/'observer.json').write_text(json.dumps(detail,indent=2)+'\n')
  result=dict(suite=suite,call=c,status=status,returncode=rc,timeout=rec['timeout'],elf_sha256=c['elf_sha256'],stdout_sha256=rec['stdout_sha256'],stderr_sha256=rec['stderr_sha256'],build=pins,whole_file_pass=status=='PASS',adapter_recovery='original captured call, zero DUT reruns')
  (d/'result.json').write_text(json.dumps(result,indent=2)+'\n');counts[suite][status]+=1;recovered.append(dict(id=c['id'],status=status,execution_sha256=sha(d/'execution.json'),stdout_sha256=rec['stdout_sha256'],stderr_sha256=rec['stderr_sha256']))
assert sum(sum(c.values()) for c in counts.values())==21316
assert counts=={'chips':{'PASS':11744},'act':{'PASS':7668},'ara':{'PASS':1888,'SCOPED_PASS':16}},counts
(R/'RECOVERY.json').write_text(json.dumps(dict(recovered=recovered,new_dut_calls=sum(r.get('new_dut_calls',0) for r in recovered),new_reference_calls=0,tool_sha256=sha(__file__),fixed_adapter_sha256=sha(Path(__file__).with_name('external_fixed.py'))),indent=2)+'\n')
(R/'EXECUTION_COUNTS.json').write_text(json.dumps(dict(counts),indent=2)+'\n');(R/'IDENTITY_AFTER.json').write_text(json.dumps(pins,indent=2)+'\n');(R/'COMPLETE').write_text('PASS\n');print(dict(counts),'recovered',len(recovered),flush=True)
