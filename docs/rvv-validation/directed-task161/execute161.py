#!/usr/bin/env python3
"""Execute retained snapshots; serialize our offline work and check live capacity."""
import collections,csv,gzip,hashlib,json,os,shutil,subprocess,threading,time,traceback
from pathlib import Path
R=Path('/home/vick/rvv-directed-task161'); R.mkdir(exist_ok=True)
os.environ.update(PYTHONDONTWRITEBYTECODE='1',RVV_COMPRESS='1')
offline=threading.Lock()
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def read(p):return json.loads(p.read_text())
def live():
 rows=[]
 for p in Path('/proc').iterdir():
  if not p.name.isdecimal():continue
  try:a=(p/'cmdline').read_bytes().split(b'\0');s=b' '.join(a).decode(errors='replace')
  except OSError:continue
  if a and Path(a[0].decode(errors='replace')).name in ('python','python3') and len(a)>1:rows.append((int(p.name),s))
 return rows
def capacity(kind,out):
 while True:
  rows=live()
  other=[(p,s) for p,s in rows if p!=os.getpid() and (('audit.py' in s or 'reject_' in s or 'controls_' in s) if kind=='offline' else ('vadd.py build' in s))]
  save(out,dict(time=time.time(),kind=kind,other=other,our_workers=1 if kind=='offline' else 4,nice=10,affinity='none'))
  if (len(other)<4 if kind=='offline' else not other):return
  time.sleep(10)
def call(args,cwd,log):
 with log.open('wb') as f:
  rc=subprocess.call(args,cwd=cwd,stdout=f,stderr=subprocess.STDOUT)
 if rc:raise RuntimeError(str(args)+' rc='+str(rc)+' log='+str(log))
def freeze(base,out):call(['sha256sum','-c','FREEZE.sha256'],base,out)
def export(base,out):
 root=base/'corpus';m=read(root/'manifest.json');cases=m['cases'];ids={c['id']:c for c in cases};a=read(out/'audit/audit.json');e=out/'evidence';e.mkdir()
 counters=collections.Counter();geo=collections.Counter();seen=set()
 with gzip.open(out/'audit/observed-checks.csv.gz','rt') as f:
  for row in csv.DictReader(f):
   c=ids[row['case']];key=(row['case'],row['arm']);assert key not in seen;seen.add(key)
   kind='reserved-start-profile' if c['vstart']>=c['vlmax'] else 'ordinary'
   counters[(c['mnemonic']+'.'+c['form'],row['arm'],kind,row['status'],row['semantic_status'])]+=1
   geo[(c['vlen'],c['sew'],c['lmul'],row['arm'],kind,row['status'])]+=1
 assert seen=={(c['id'],arm) for c in cases for arm in ('Reference','B','M1','M2','BOTH')}
 assert len(seen)==a['executed_case_checks']
 for name,fields,counter in [('PER_FORM.csv',['form','arm','class','status','semantic_status','checks'],counters),('PER_GEOMETRY.csv',['vlen','sew','lmul','arm','class','status','checks'],geo)]:
  with (e/name).open('w') as f:
   w=csv.writer(f);w.writerow(fields)
   for key,n in sorted(counter.items()):w.writerow([*key,n])
 anomalies=[]
 for unit in dict.fromkeys(c['unit'] for c in cases):
  for arm in ('Reference','B','M1','M2','BOTH'):
   receipt=read(root/'runs'/unit/arm/'execution.json')
   if receipt['returncode'] or receipt['timeout']:anomalies.append(dict(unit=unit,arm=arm,**receipt))
 assert not anomalies,anomalies
 assert read(root/'identities-before.json')==read(root/'identities-after.json')
 for src,name in [(out/'audit/audit.json','AUDIT.json'),(out/'audit/observed-checks.csv.gz','observed-checks.csv.gz'),(root/'summary.json','RUNNER_SUMMARY.json'),(out/'controls/summary.json','CONTROLS.json'),(base/'FREEZE.sha256','FREEZE.sha256'),(out/'STAGE_STATUS.json','STAGE_STATUS.json')]:shutil.copy2(src,e/name)
 for n in ('identities-before.json','identities-after.json','runner-identity.json'):shutil.copy2(root/n,e/n)
 save(e/'VALIDATION.json',dict(cases=len(cases),checks=len(seen),units=m['units'],ordinary_per_arm=sum(c['vstart']<c['vlmax'] for c in cases),reserved_start_per_arm=sum(c['vstart']>=c['vlmax'] for c in cases),widths=sorted({c['vlen'] for c in cases}),raw='xbd:'+str(base),audit='xbd:'+str(out),reserved_encodings=m.get('reserved_encodings',m.get('reserved_declarations',[])),execution_anomalies=anomalies,main_review='PENDING'))
 with gzip.open(e/'manifest.json.gz','wt') as f:json.dump(m,f,separators=(',',':'))
 save(e/'SHA256.json',{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in e.iterdir() if p.is_file()})
def process(base,name,family,control,guests=True):
 out=R/name;out.mkdir();st={k:125 for k in ('build','run','audit','controls','export')};save(out/'STAGE_STATUS.json',st)
 try:
  freeze(base,out/'freeze-before.log')
  if guests:
   assert not (base/'corpus').exists(),'never overwrite retained corpus'
   assert shutil.disk_usage(base).free>=12*1024**3
   capacity('build',out/'BUILD_CAPACITY.json')
   args=['python3','scripts/vadd.py','build','--family',family,'--output','corpus','--compiler','clang-22','--build-jobs','4','--link','../user.ld']
   if (base/'UNITS.json').exists():args+=['--units-file','UNITS.json']
   call(args,base,out/'build.log');st['build']=0;save(out/'STAGE_STATUS.json',st)
   runners=[s for _,s in live() if 'vadd.py run' in s];save(out/'GUEST_CAPACITY.json',dict(other=runners,ours=8,total_limit=16))
   assert len(runners)<=1,runners
   call(['python3','scripts/vadd.py','run','--root',str(base/'corpus'),'--engine','/home/vick/rvdbt-host512-task142-build/build/bin/elfrun','--spike','/home/vick/rvv-directed-task145/deps/spike','--pk','/home/vick/rvv-directed-task145/deps/pk','--sail','/home/vick/rvv-act4-tools/bin/sail_riscv_sim','--flags','../FLAGS.json','--jobs','8'],base,out/'run.log');st['run']=0
  else:
   original=read(base/'STAGE_STATUS.json');assert original['build']==original['run']==0;st.update(build=0,run=0);save(out/'ORIGINAL_STAGE_STATUS.json',original)
  save(out/'STAGE_STATUS.json',st)
  with offline:
   capacity('offline',out/'OFFLINE_CAPACITY.json')
   call(['python3',str(base/'scripts/audit.py'),str(base/'corpus'),str(out/'audit')],base,out/'audit.log');st['audit']=0;save(out/'STAGE_STATUS.json',st)
   capacity('offline',out/'CONTROL_CAPACITY.json')
   call(['python3',str(base/'scripts'/control),str(base/'corpus'),str(out/'controls')],base,out/'controls.log');st['controls']=0
  freeze(base,out/'freeze-after.log');st['export']=0;save(out/'STAGE_STATUS.json',st);export(base,out)
  (out/'COMPLETE').write_text('success\n')
 except BaseException:
  (out/'ERROR.txt').write_text(traceback.format_exc());save(out/'STAGE_STATUS.json',st);raise
 return out
errors=[]
def guests():
 try:
  for name,family,ctrl in [('extend','extend156','reject_extend156.py'),('destchunk','wmac156chunk','reject_wmac156_chunk.py')]:
   p=process(Path('/home/vick/rvv-directed-task156')/(name+'-pilot'),name+'-pilot',family,ctrl)
   val=read(p/'evidence/VALIDATION.json');aud=read(p/'audit/audit.json');controls=read(p/'controls/summary.json')
   assert all(x['FAIL']==x['ISA_ONLY_REFERENCE_BLOCKED']==0 for x in aud['counts'].values())
   assert controls['controls']==controls['rejected']>0
   save(p/'PILOT_REVIEW.json',dict(accepted=True,review='Complete frozen manifest/encoding/ELF/adapter/full-state replay; effective retained-packet controls passed; ordinary and reserved-start separated',validation=val,controls={k:controls[k] for k in ('controls','rejected','allowed')}))
  process(Path('/home/vick/rvv-directed-task154/widen-full'),'widen-full','widen154','reject_widen154.py')
  for name,family,ctrl in [('extend','extend156','reject_extend156.py'),('destchunk','wmac156chunk','reject_wmac156_chunk.py')]:process(Path('/home/vick/rvv-directed-task156')/(name+'-full'),name+'-full',family,ctrl)
 except BaseException:errors.append(traceback.format_exc())
t=threading.Thread(target=guests);t.start()
try:process(Path('/home/vick/rvv-directed-task156/wmac-full2'),'wmac-full2','wmac156','reject_wmac156.py',False)
except BaseException:errors.append(traceback.format_exc())
t.join();save(R/'RESULT.json',dict(errors=errors));(R/('ERROR' if errors else 'COMPLETE')).write_text(time.ctime()+'\n')
