import os
"""Replay accepted page-edge, FOF exit-only and vill supplements in place."""
import collections,concurrent.futures,hashlib,importlib,json,os,shutil,sys
from pathlib import Path
import storage149 as storage,admission181 as admission
B=Path(os.environ.get('RVV_TASK181_ROOT','/home/vick/rvv-task181'));H=Path('/home/vick');ENGINE=H/'rvdbt-host512-task179-build/build/bin/elfrun';LIB=ENGINE.parent.parent/'lib/libdbtjitshared.so'
sha=lambda p:hashlib.sha256(storage.verify(p)).hexdigest()
read=lambda p:json.loads(Path(p).read_text())
def save(p,x):Path(p).parent.mkdir(parents=True,exist_ok=True);Path(p).write_text(json.dumps(x,indent=2)+'\n')
assert sha(ENGINE)=='8a468967852b8f16225b359fce99c0d22ab286d6314cb90a79934a7376207281'
assert sha(LIB)=='79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af'
import fcntl
lock=open('/tmp/rvv-task181-offline.lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
name=sys.argv[1];audit=len(sys.argv)>2 and sys.argv[2]=='audit';os.environ['RVV_COMPRESS']='1'
if name in ('guard165','guard166'):
 batch=int(name[-3:]);original=H/f'rvv-task{batch}/guard-pilot'
 sys.path.insert(0,str(H/'rvv-task168/tools' if batch==165 else H/'rvv-task166/w128/scripts'))
 if batch==166:sys.path.insert(0,str(H/'rvv-task166/tools'))
 g=importlib.import_module('guard_memory165' if batch==165 else 'guard_indexed166');isa=g.isa;reference=g.reference
else:
 batch=168;original=H/'rvv-task168'/name;sys.path.insert(0,str(H/'rvv-task168/tools'))
 import memory168 as m,vill_memory168 as vill
 isa=vill.check if name=='vill' else m.check_isa;reference=m.check_reference
m=read(original/'summary.json');records=m['records'];units=collections.defaultdict(list)
for r in records:
 key=r['case']['mnemonic']+'-'+r['kind'] if name.startswith('guard') else r['case']['id'];units[key].append(r)
root=B/'focused'/name/('audit' if audit else 'replay');assert not root.exists();root.mkdir(parents=True)
plan=dict(original=str(original),summary_sha256=sha(original/'summary.json'),records=records,build_sha256=sha(ENGINE),library_sha256=sha(LIB),tools={str(Path(x.__file__)):sha(x.__file__) for x in list(sys.modules.values()) if getattr(x,'__file__',None) and str(getattr(x,'__file__','')).startswith('/home/vick/rvv-') and Path(x.__file__).suffix=='.py'})
save(root/'PLAN.json',plan)
def worker(key):
 rs=units[key];c=rs[0]['case'];d=original/key;elf=d/'test.elf';assert sha(elf)==rs[0]['guest_sha256'];assert sha(d/'test.S')==rs[0]['source_sha256']
 ref=storage.verify(d/'Reference/packets.bin');negative=rs[0]['status']!='PASS'
 if not negative:
  with admission.predicate_slot():isa(c,ref,0,False)
 out=[]
 for arm in ('B','M1','M2','BOTH'):
  old=next(r for r in rs if r['arm']==arm);oldcmd=read(d/arm/'command.json')
  new=B/'focused'/name/'replay'/key/arm
  if audit:rec=read(new/'execution.json');raw=storage.verify(new/'packets.bin')
  else:
   work=root/'work'/key/arm;(work/'fs').mkdir(parents=True);(work/'cache').mkdir();(work/'fs/t.elf').write_bytes(storage.verify(elf))
   flags=[]
   for f in oldcmd[1:]:
    if f.startswith('--fsroot='):f=f'--fsroot={work}/fs'
    elif f.startswith('--cache='):f=f'--cache={work}/cache'
    elif f.startswith('--dump-tbmap='):f=f'--dump-tbmap={new}/tbmap'
    flags.append(f)
   cmd=[str(ENGINE),*flags];rec=storage.execute(cmd,new,dict(os.environ,LD_LIBRARY_PATH=str(LIB.parent)+':/home/vick/boost_vendor/lib'),30)
   raw=storage.verify(new/'stdout');storage.write(new/'packets.bin',raw,alias=new/'stdout');storage.compress(new/'tbmap')
  error=None
  try:
   with admission.predicate_slot():
    if negative:
     text=storage.text(new/'stderr')+raw.decode(errors='replace');assert rec['returncode']!=0 and not rec['timeout'] and any(x in text.lower() for x in ('fault','segmentation','trap'))
    else:isa(c,raw,rec['returncode'],rec['timeout']);reference(c,raw,ref)
  except (AssertionError,ValueError) as ex:error=str(ex)
  row=dict(batch=batch,form=old['form'],case=c,kind=old.get('kind'),arm=arm,status='FAIL' if error else 'EXPECTED_DENIAL_CONTROL' if negative else 'PASS',error=error,original_elf=str(elf),elf_sha256=sha(elf),reference_raw=str(d/'Reference/packets.bin'),reference_sha256=hashlib.sha256(ref).hexdigest(),raw=str(new/'packets.bin'),raw_sha256=hashlib.sha256(raw).hexdigest(),command_sha256=sha(new/'command.json'),execution_sha256=sha(new/'execution.json'))
  out.append(row)
  if error:
   save(B/'STOP_NEW_GUESTS.json',row);raise RuntimeError('focused failure; final scheduling stopped')
  if not audit and not error:
   with admission.LOCK,(B/'CLEANUP.jsonl').open('a') as f:f.write(json.dumps(dict(reason='new successful focused work/cache only',files=[dict(path=str(p),bytes=p.stat().st_size) for p in work.rglob('*') if p.is_file()]))+'\n')
   shutil.rmtree(work)
 save(root/(key+'-RESULTS.json'),out)
 return out
# Bounded first family unit proves both packet and original-command adapter.
items=list(units);rows=worker(items[0]);assert all(r['status']!='FAIL' for r in rows)
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
 for result in pool.map(worker,items[1:]):rows.extend(result)
counts=dict(collections.Counter(r['status'] for r in rows));forms=collections.defaultdict(collections.Counter)
for r in rows:forms[r['form']][r['status']]+=1
save(root/'summary.json',dict(cases=len(units),checks=len(rows),counts=counts,forms={f:dict(c) for f,c in forms.items()},failed=counts.get('FAIL',0),new_reference_calls=0))
assert not counts.get('FAIL'),counts
assert sha(ENGINE)==plan['build_sha256'] and sha(LIB)==plan['library_sha256']
(root/'COMPLETE').write_text('PASS\n');print(name,'audit' if audit else 'replay',counts,flush=True)
