"""Offline final Task133 queue/result and original-predicate audit; no guests."""
import collections,gzip,hashlib,importlib.util,json,os,re,shutil,sys
from pathlib import Path
R=Path(sys.argv[1]);B=Path('/home/vick/rvdbt-whole-native-task133');P=Path('/home/vick/rvdbt-host512-task128')
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
read=lambda p:json.loads(Path(p).read_text())
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
sys.path.insert(0,'/home/vick/ara-current122')
chips=module('chips134','/home/vick/chips-current120/runner.py');act=module('act134','/home/vick/act-current121/run121.py');ara=module('ara134','/home/vick/ara-current122/run122.py');ara.R=R/'ara'
pins=read(R/'IDENTITY_BEFORE.json');assert read(R/'IDENTITY_AFTER.json')==pins and all(sha(p)==h for p,h in pins.items())
credit={json.dumps(x['call'],sort_keys=True,separators=(',',':')):Path(x['raw']) for x in read(R/'CREDITED.json')}
records=[];counts=collections.defaultdict(collections.Counter);arms=collections.defaultdict(collections.Counter);new=collections.defaultdict(collections.Counter);vlens=collections.defaultdict(collections.Counter)
for suite in ['chips','act','ara']:
 key='cells' if suite=='chips' else 'calls';prior=read(P/suite/'QUEUE.json');selected=read(R/suite/'QUEUE.json'); executed={json.dumps(c,sort_keys=True,separators=(',',':')) for c in selected[key]}
 for c in prior[key]:
  ident=json.dumps(c,sort_keys=True,separators=(',',':'));credited=ident in credit and suite=='act';assert (ident in executed) != credited
  d=credit[ident] if credited else R/suite/'raw'/(Path(c['case'])/c['arm'] if suite=='act' else c['id'])
  rr=read(d/'result.json');cmd=read(d/'command.json');assert cmd[0] in pins and read(d/'IDENTITY.json')==pins
  for s in ['stdout','stderr']:assert sha(d/s)==rr[s+'_sha256']
  flags=[]
  for f in cmd[1:]:
   if f.startswith('--fsroot='):f='--fsroot={WORK}/fs'
   elif f.startswith('--cache='):f='--cache={WORK}/cache'
   elif f.startswith(('--dump-tbmap=','--dump-tbcode=')):continue
   flags.append(f)
  assert flags==(c['flags'] if suite=='chips' else c['normalized_flags'])
  assert '--aot=0' in flags and '--aot-use-llvm=0' in flags
  vlen=int(next(f.split('=')[1] for f in flags if f.startswith('--vlen=')));vlens[suite][vlen]+=1
  assert (d/'work/fs/t.elf').read_bytes()[4:6]==bytes([1,1]) # real ELF32 LE
  assert sha(d/'work/fs/t.elf')==c['elf_sha256']
  if suite=='chips':
   ok=chips.classify(rr['returncode'],(d/'stdout').read_bytes(),c,error=rr['error'])=='PASS'
   predicate={'checker':'original registered exit/exact stdout','expected_returncode':c['expected_returncode'],'expected_stdout':c['expected_stdout']}
   arm=c['aliases'][0]['arm']
  elif suite=='act':
   assert read(d/'IDENTITY_AFTER.json')==pins
   raw=(d/'stdout').read_text(errors='replace')+(d/'stderr').read_text(errors='replace')
   ok=eval(act.predicate,{'__builtins__':{}},dict(rc=rr['returncode'],raw=raw,N=c['case'],sig=None));assert ok==rr['original_predicate_pass']
   predicate={'checker':prior['original_DUT_predicate']};arm=c['arm']
  else:
   assert read(d/'IDENTITY_AFTER.json')==pins
   ok,detail=ara.observer(dict(c,_rawdir=d),rr['returncode'],(d/'stdout').read_bytes(),ara.staged_observer(c['producer']))
   assert detail==read(d/'observer.json') and ok==rr['accepted_scope_pass']
   predicate={'checker':'unchanged original Ara observer','raw_observer':detail};arm=c['arm']
  assert ok and rr['status']=='PASS' and rr['returncode']==0
  text=(d/'stderr').read_text(errors='replace')
  counts[suite][rr['status']]+=1;arms[suite][arm]+=1
  if not credited:new[suite][rr['status']]+=1
  records.append(dict(suite=suite,arm=arm,origin='Task133 credited' if credited else 'Task134 replay',original_call=c,call_sha256=hashlib.sha256(ident.encode()).hexdigest(),raw=str(d),command=cmd,result=rr,predicate=predicate,executable_pins=pins,raw_files={p.name:sha(p) for p in d.iterdir() if p.is_file()},routes={op:int(n) for op,n in re.findall(r'^RVV_ROUTE (\S+) handler_calls=(\d+)$',text,re.M)},direct=re.findall(r'^RVV_DIRECT (.*)$',text,re.M)))
assert len(records)==5904 and {s:dict(v) for s,v in new.items()}==read(R/'EXECUTION_COUNTS.json')
assert all(not q for q in read(R/'UNATTEMPTED.json').values())
for filename in ['INPUT_AUDIT.json','TOOLS.json']:
 assert all(sha(p)==h for p,h in read(R/filename).items())
source=read(R/'SOURCE_EQUALITY.pre.json');assert all(sha(B/'source'/p)==h for p,h in source['files'].items());save(R/'SOURCE_EQUALITY.post.json',source)
assert all(sha(p)==h for p,h in read(R/'BUILD_FILES.pre.json').items());save(R/'BUILD_FILES.post.json',read(R/'BUILD_FILES.pre.json'))
with gzip.open(R/'QUEUE_RESULT_INDEX.json.gz','wt') as f:json.dump(records,f,separators=(',',':'))
save(R/'AUDIT.json',dict(completed=5904,passed=5904,failed=0,unattempted=0,new_calls=5901,credited_calls=3,counts={s:dict(v) for s,v in counts.items()},per_arm={s:dict(v) for s,v in arms.items()},XLEN=32,ELEN=64,guest_VLEN_counts={s:dict(v) for s,v in vlens.items()},host_chunk_bits=512,predicates_recomputed=True,guest_instructions_in_audit=0,production=pins,limitations='Counters do not establish per-target SIMD; grouped QCG/LLVM whole SIMD remains disabled'))
# Retain raw credited evidence and scripts, without overwriting earlier roots.
for identity,d in credit.items():shutil.copytree(d,R/'credited'/d.parent.name/d.name,ignore=shutil.ignore_patterns('cache'))
for p in [Path('/home/vick/replay_memory_task134.py'),Path(__file__),Path('/home/vick/identity134.py'),Path('/home/vick/identity134.initial.py'),Path('/home/vick/identity134.second.py'),Path('/home/vick/focused134.py'),Path('/home/vick/task134-launcher.stdout'),Path('/home/vick/task134-launcher.stderr')]:
 if p.exists():shutil.copy2(p,R/p.name)
(R/'load.final.txt').write_text(Path('/proc/loadavg').read_text())
manifest={str(p.relative_to(R)):sha(p) for p in R.rglob('*') if p.is_file() and 'work/cache' not in str(p) and 'observers' not in p.relative_to(R).parts and p.name!='RAW_MANIFEST.json.gz'}
with gzip.open(R/'RAW_MANIFEST.json.gz','wt') as f:json.dump(manifest,f,separators=(',',':'))
print('OFFLINE_AUDIT_PASS',len(records),'raw files',len(manifest))
