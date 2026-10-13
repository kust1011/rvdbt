#!/usr/bin/env python3
"""Focused179 replay; original ELF/reference reuse and one owner gate for every queue.
Run remotely with PYTHONPATH pointing to the retained177 tools and nice10.
The owner flock covers all guest/build/offline subprocess queues; max workers4/4/2.
"""
import collections,concurrent.futures,fcntl,hashlib,json,os,subprocess,sys,threading,time
from pathlib import Path
import vadd as v
import sequences177 as s
import resources164
B=Path(os.environ.get('RVV_TASK179_OUTPUT','/home/vick/rvv-directed-task179'));C=Path('/home/vick/rvdbt-host512-task179-build')
B.mkdir(exist_ok=True);os.environ['RVV_COMPRESS']='1'
assert os.getpriority(os.PRIO_PROCESS,0)==10
lock=open('/home/vick/rvv-directed-task179.own-semaphore','a');fcntl.flock(lock,fcntl.LOCK_EX)
mutex=threading.Lock()
def save(p,x):v.save(p,x)
def gate(kind):
 while True:
  with mutex:
   snap=resources164.snapshot()
   with (B/'RESOURCES.jsonl').open('a') as f:f.write(json.dumps(dict(kind=kind,own_controller=os.getpid(),**snap))+'\n')
   assert snap['free_bytes']>10*1024**3+64*1024**2
   if snap['guests']<=12 and snap['offline']<=2:return
  time.sleep(2)
def env():return dict(os.environ,LD_LIBRARY_PATH=str(C/'build/lib')+':/home/vick/boost_vendor/lib')
def identities():return {str(p):v.sha(p) for p in [C/'build/bin/elfrun',C/'build/lib/libdbtjitshared.so']}
selections={
 'integer':['liveout-zero','liveout-start','overwrite-zero','alias-zero','boundary-zero'],
 'fp':['chain-zero','chain-start','reject-tu-zero','reject-mask-zero'],
 'cache':['cache-zero'],'cache64':['cache-zero']}
def prepare(part,trace):
 old=Path('/home/vick/rvv-directed-task177')/part/'pilot'
 root=B/f'trace{trace}'/part;root.mkdir(parents=True,exist_ok=False)
 prefix=f'{part}-w1024-e32-m1-';units=[prefix+u for u in selections[part]]
 m=json.loads((old/'manifest.json').read_text());cs=[c for c in m['cases'] if c['unit'] in units]
 assert set(c['unit'] for c in cs)==set(units)
 save(root/'manifest.json',dict(m,cases=cs,units=len(units),pilot_units=units,planned_case_executions=5*len(cs),reuse=str(old)))
 pin=identities();save(root/'identities-before.json',pin)
 builds=[r for r in json.loads((old/'build-commands.json').read_text()) if Path(r['command'][-1]).parent.name in units]
 save(root/'build-commands.json',builds)
 jobs=[]
 for unit in units:
  (root/unit).mkdir();(root/'runs'/unit).mkdir(parents=True)
  for p in (old/unit).iterdir():
   if p.name.startswith(('test.elf','test.S','sail.elf')):(root/unit/p.name).symlink_to(p)
  (root/'runs'/unit/'Reference').symlink_to(old/'runs'/unit/'Reference',target_is_directory=True)
  rows=[c for c in cs if c['unit']==unit]
  for arm in s.ARMS[1:]:jobs.append((part,trace,root,old,unit,rows,arm))
 return root,jobs

def execute_job(job):
 part,trace,root,old,unit,cs,arm=job
 d=root/'runs'/unit/arm;work=root/'work'/unit/arm;fs=work/'fs';fs.mkdir(parents=True);cache=work/'cache';cache.mkdir()
 guest=v.storage.verify(old/unit/'test.elf');(fs/'t.elf').write_bytes(guest)
 cmd=json.loads((old/'runs'/unit/arm/'command.json').read_text());cmd[0]=str(C/'build/bin/elfrun')
 for i,a in enumerate(cmd):
  for flag,target in [('dump-tbcode',d/'tbcode'),('dump-tbmap',d/'tbmap'),('rvv-pc-census-out',d/'pc-census.csv'),('fsroot',fs),('cache',cache)]:
   if a.startswith('--'+flag+'='):cmd[i]='--'+flag+'='+str(target)
  if a.startswith('--trace='):cmd[i]='--trace='+str(trace)
 gate('guest');rec=v.execute(cmd,d,env(),60)
 for name in ['tbcode','tbmap','pc-census.csv']:v.storage.compress(d/name)
 raw=v.storage.verify(d/'stdout');ref=v.storage.verify(old/'runs'/unit/'Reference'/'packets.bin');size=v.packet_size(cs[0])
 # The replay must have complete packets; no success inferred from a counter.
 assert rec['returncode']==0 and not rec['timeout'] and len(raw)==len(ref)==size*len(cs),(job,rec,len(raw),len(ref))
 checks=[]
 for j,c in enumerate(cs):
  s.check_reference(c,raw[j*size:(j+1)*size],ref[j*size:(j+1)*size]);checks.append(dict(id=c['id'],status='PASS'))
 save(d/'checks.json',checks)
 (d/'packets.bin.gz').symlink_to('stdout.gz');v.storage.receipt(d/'packets.bin',hashlib.sha256(raw).hexdigest(),len(raw))
 save(d/'REUSE.json',dict(original_ELF_sha256=hashlib.sha256(guest).hexdigest(),original_reference_sha256=hashlib.sha256(ref).hexdigest(),original_root=str(old),new_execution=True,trace=trace,arm=arm))
 return len(cs)

def regress():
 import cache_entries177
 cache_entries177.install();execute=v.execute;s.install('integer');v.execute=execute
 roots=[];jobs=[]
 for trace in [0,1]:
  for part in selections:
   root,js=prepare(part,trace);roots.append(root);jobs+=js
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:counts=list(pool.map(execute_job,jobs))
 for root in roots:
  save(root/'identities-after.json',identities());assert json.loads((root/'identities-before.json').read_text())==identities()
 save(B/'FOCUSED_REPLAY.json',dict(status='PASS',commands=len(jobs),DUT_checks=sum(counts),per_mode_cases=sum(counts)//8,roots=list(map(str,roots)),guest_workers=4,reference_executions=0,original_ELF_rebuilds=0))

def contracts():
 names=['rvv_vector_run_admission_test','rvv_vector_run_codegen_test','rvv_vector_run_value_test','rvv_both_boundary_value_test','rvv_run_live_range_split_test','rvv_ssa_edge_commit_test','rvv_rvv_contract_test']
 def run(name):
  gate('offline');d=B/'contracts'/name
  r=v.execute([str(C/'build/bin'/name)],d,env(),180)
  assert r['returncode']==0 and not r['timeout'],(name,r)
  return dict(test=name,**r)
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:rs=list(pool.map(run,names))
 save(B/'CONTRACTS.json',dict(status='PASS',tests=rs,workers=2))

def audit():
 tools=Path('/home/vick/rvv-directed-task177/tools')
 for trace in [0,1]:
  for group,parts in [('main',['integer','fp','cache']),('cache64',['cache64'])]:
   roots=[B/f'trace{trace}'/p for p in parts]
   for mode in ['audit','controls']:
    gate('offline')
    dest=B/(f'audit-trace{trace}-{group}' if mode=='audit' else f'CONTROLS_TRACE{trace}_{group}.json')
    cmd=['python3',str(tools/'review_sequences177_v2.py'),mode,'--roots',*map(str,roots),'--out',str(dest)]+(['--cache64'] if group=='cache64' else [])
    r=subprocess.run(cmd,capture_output=True,env=env(),timeout=180)
    (B/f'{mode}-trace{trace}-{group}.stdout').write_bytes(r.stdout);(B/f'{mode}-trace{trace}-{group}.stderr').write_bytes(r.stderr)
    assert r.returncode==0,(cmd,r.stderr.decode())
def finalize_contracts():
 name='rvv_vector_run_codegen_test';gate('offline')
 r=v.execute([str(C/'build/bin'/name)],B/'contracts-final'/name,env(),180)
 assert r['returncode']==0 and not r['timeout'],r
 rs=[]
 for d in sorted((B/'contracts').iterdir()):
  rec=r if d.name==name else json.loads((d/'execution.json').read_text())
  assert rec['returncode']==0 and not rec['timeout'],(d,rec)
  rs.append(dict(test=d.name,**rec))
 save(B/'CONTRACTS.json',dict(status='PASS',tests=rs,workers=2,original_codegen_failure_retained=True,baseline174_codegen_failure_count=4,codegen179_before_golden_update_failure_count=46))

if __name__=='__main__':globals()[sys.argv[1]]()
