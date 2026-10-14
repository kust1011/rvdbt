"""Replay or audit one frozen entry; original ELFs/references are never rebuilt."""
import argparse,collections,concurrent.futures,gzip,hashlib,importlib,json,os,shutil,sys,threading
from pathlib import Path
import admission178 as admission
import storage149 as storage
B=Path('/home/vick/rvv-task178');ENGINE=Path('/home/vick/rvdbt-host512-task174-build/build/bin/elfrun');LIB=ENGINE.parent.parent/'lib/libdbtjitshared.so'
PINS={str(ENGINE):'18521de85c7ba352b0dbc6155f26d96c25522b6a6bc81cb26fb38c4c0b1f79a4',str(LIB):'79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af'}
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
read=lambda p:json.loads(Path(p).read_text())
def save(p,x):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,indent=2)+'\n')
def gz(p,x):Path(p).write_bytes(gzip.compress(json.dumps(x,separators=(',',':')).encode(),mtime=0))
def pins():assert all(sha(p)==h for p,h in PINS.items())
p=argparse.ArgumentParser();p.add_argument('action',choices=['pilot','remaining','reuse','audit']);p.add_argument('entry');a=p.parse_args()
plan=read(B/'DIRECTED_PLAN.json');e=next(e for e in plan['entries'] if e['id']==a.entry)
original=Path(e['original']);tools=Path(e['tools']);sys.path.insert(0,str(tools))
import vadd as v
if not hasattr(v,'check_isa'):
 _decode=v.decode;_decoded=threading.local()
 def cached_decode(c,raw):
  cache=getattr(_decoded,'cache',None)
  if cache is None:_decoded.cache=cache={}
  key=(c['id'],raw)
  if key not in cache:
   if len(cache)>=4:cache.clear()
   cache[key]=_decode(c,raw)
  return cache[key]
 v.decode=cached_decode
 v.check_isa=lambda c,raw,rc=0,timeout=False:v.check(c,raw,rc,timeout)
 v.check_reference=lambda c,raw,ref:v.check(c,raw,0,False,ref)
if e['install']:importlib.import_module(e['install']).install(v)
os.environ['RVV_COMPRESS']='1';pins()
assert sha(original/'manifest.json')==e['manifest_sha256']
assert sha(original/'build-commands.json')==e['build_commands_sha256']
assert all(sha(p)==h for p,h in e['tool_pins'].items())
manifest=read(original/'manifest.json');allcases=manifest['cases'];accepted={allcases[i]['id']:allcases[i] for i in e['accepted_indices']}
groups=collections.defaultdict(list)
for i,c in enumerate(allcases):
 if c['unit'] in e['units']:groups[c['unit']].append((i,c))
# A bounded per-entry pilot includes both initialized-start and zero units,
# and at most one representative per owned form (maximum eight units).
selected=[]
for key in sorted(groups,key=lambda u:(allcases[groups[u][0][0]]['vlen'],u)):
 if any(c['id'] in accepted for _,c in groups[key]):
  if not selected or bool(groups[key][0][1]['vstart'])!=bool(groups[selected[0]][0][1]['vstart']):selected.append(key)
 if len(selected)>=2:break
if len(selected)<2:selected=list(groups)[:2]
output=B/'directed'/e['id'];output.mkdir(parents=True,exist_ok=True)
if a.action=='pilot':save(output/'PILOT_UNITS.json',selected)
elif a.action=='remaining':
 assert read(output/'pilot/summary.json')['failed']==0 and (output/'pilot/COMPLETE').exists()
 selected=[u for u in groups if u not in read(output/'PILOT_UNITS.json')]
else:selected=list(groups)
root=output/a.action
assert not root.exists();root.mkdir()
save(root/'LINEAGE.json',dict(entry=e,plan_sha256=sha(B/'DIRECTED_PLAN.json'),flags_sha256=sha(e['flags']),build=PINS,action=a.action,runner_sha256=sha(__file__),jobs=8 if a.action!='audit' else 2,reference_guest_calls=0,new_build_calls=0))
flags=read(e['flags']);assert set(flags)=={'B','M1','M2','BOTH'}
buildrows=read(original/'build-commands.json')
elfpins={Path(r['command'][-1]).parent.name:r['elf_sha256'] for r in buildrows if Path(r['command'][-1]).name=='test.elf'}
results=read(original/'results.json');oldrefs={r['case']:r for r in results if r['arm']=='Reference'}
oldarms={(r['case'],r['arm']):r for r in results}
CHECKLOCK=threading.Semaphore(2)
def validate(c,packet,ref,rec):
 with CHECKLOCK:
  v.check_isa(c,packet,rec['returncode'],rec['timeout']);v.check_reference(c,packet,ref)
def worker(unit):
 cs=groups[unit];size=v.packet_size(cs[0][1]);legal=[(j,c) for j,(_,c) in enumerate(cs) if c['id'] in accepted]
 elf=storage.verify(original/unit/'test.elf');assert hashlib.sha256(elf).hexdigest()==elfpins[unit]
 refs={};refpins={}
 for j,c in legal:
  r=oldrefs[c['id']];assert r['status']=='PASS',(c['id'],r)
  path=Path(r['raw']);key=str(path)
  if key not in refs:
   refs[key]=storage.verify(path);rec=read(path.parent/'execution.json');assert rec['returncode']==0 and not rec['timeout'];refpins[key]=hashlib.sha256(refs[key]).hexdigest()
  assert r['size']==size
  packet=refs[key][r['offset']:r['offset']+size]
  with CHECKLOCK:v.check_isa(c,packet,0,False)
 save(root/(unit+'-REUSE.json'),dict(elf_sha256=elfpins[unit],reference_packets=refpins,cases=len(legal)))
 rows=[]
 for arm,fsflags in flags.items():
  ref=None
  if a.action in ('reuse','audit'):
   if a.action=='reuse':
    sample=oldarms[(legal[0][1]['id'],arm)];d=Path(sample['raw']).parent
    identity=read(original/'identities-before.json')
    assert identity.get(str(ENGINE))==PINS[str(ENGINE)] and identity.get(str(LIB))==PINS[str(LIB)],identity
   else:
    d=next((output/stage/'runs'/unit/arm for stage in ('pilot','remaining','reuse') if (output/stage/'runs'/unit/arm/'execution.json').exists()),None)
    if d is None and e['reuse_same174']:d=Path(oldarms[(legal[0][1]['id'],arm)]['raw']).parent
    assert d is not None,unit
   rec=read(d/'execution.json');cmd=read(d/'command.json');raw=storage.verify(d/'packets.bin')
  else:
   d=root/'runs'/unit/arm;work=root/'work'/unit/arm;(work/'fs').mkdir(parents=True);(work/'cache').mkdir()
   # No persistent input copy: compressed old ELFs are materialized only in NEW scratch.
   guest=work/'fs/t.elf';guest.write_bytes(elf)
   cmd=[str(ENGINE),*[f'--vlen={cs[0][1]["vlen"]}' if f.startswith('--vlen=') else f for f in fsflags],f'--dump-tbmap={d}/tbmap',f'--fsroot={work}/fs',f'--cache={work}/cache','--','/t.elf']
   rec=storage.execute(cmd,d,dict(os.environ,LD_LIBRARY_PATH=str(LIB.parent)+':/home/vick/boost_vendor/lib'),120)
   raw=storage.verify(d/'stdout');storage.write(d/'packets.bin',raw,alias=d/'stdout');storage.compress(d/'tbmap')
  assert str(cmd[0])==str(ENGINE),(unit,cmd[0])
  normalized=[f for f in cmd[1:] if not f.startswith(('--dump-tbmap=','--dump-tbcode=','--fsroot=','--cache='))]
  expected=[f'--vlen={cs[0][1]["vlen"]}' if f.startswith('--vlen=') else f for f in fsflags]+['--','/t.elf']
  assert normalized==expected,(normalized,expected)
  checks=[]
  for j,c in legal:
   error=None;r=oldrefs[c['id']];reference=refs[str(Path(r['raw']))][r['offset']:r['offset']+size]
   try:
    assert len(raw)==size*len(cs),'packet extent'
    validate(c,raw[j*size:(j+1)*size],reference,rec)
   except (AssertionError,ValueError) as ex:error=str(ex)
   checks.append(dict(case=c['id'],form=c.get('mnemonic','vadd') if c.get('mnemonic','') in plan['owners'] else c.get('mnemonic','vadd')+'.'+c['form'],arm=arm,status='FAIL' if error else 'PASS',error=error,raw=str(d/'packets.bin'),offset=j*size,size=size,reference_raw=r['raw'],reference_offset=r['offset'],original_elf=str(original/unit/'test.elf'),elf_sha256=elfpins[unit],command_sha256=sha(d/'command.json'),execution_sha256=sha(d/'execution.json'),packet_sha256=hashlib.sha256(raw[j*size:(j+1)*size]).hexdigest()))
  gz(root/(unit+'-'+arm+'-checks.json.gz'),checks);rows.extend(checks)
  if a.action not in ('audit','reuse') and all(r['status']=='PASS' for r in checks):
   with admission.LOCK,(B/'CLEANUP.jsonl').open('a') as f:f.write(json.dumps(dict(reason='new successful regenerable work/cache only',files=[dict(path=str(p),bytes=p.stat().st_size) for p in work.rglob('*') if p.is_file()]))+'\n')
   shutil.rmtree(work)
 return rows
counts=collections.Counter();forms=collections.defaultdict(collections.Counter);failures=[];completed=0
with concurrent.futures.ThreadPoolExecutor(max_workers=2 if a.action=='audit' else 8) as pool:
 for unit,rows in zip(selected,pool.map(worker,selected)):
  completed+=1
  for r in rows:
   counts[r['status']]+=1;forms[r['form']][r['status']]+=1
   if r['status']!='PASS':failures.append(r)
  if completed%100==0:print(e['id'],a.action,completed,len(selected),dict(counts),flush=True)
pins();assert all(sha(p)==h for p,h in e['tool_pins'].items())
save(root/'summary.json',dict(accepted_cases=sum(sum(c['id'] in accepted for _,c in groups[u]) for u in selected),units=len(selected),completed=completed,checks=sum(counts.values()),counts=dict(counts),failed=len(failures),forms={f:dict(c) for f,c in forms.items()},build=PINS,new_dut_calls=len(selected)*4 if a.action not in ('audit','reuse') else 0))
save(root/'FAILURES.json',failures)
if failures:raise SystemExit(1)
(root/'COMPLETE').write_text('PASS\n')
print('COMPLETE',e['id'],a.action,dict(counts),flush=True)
