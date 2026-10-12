"""Bounded Task122 execution of frozen original Ara ELFs/commands/observers."""
import collections,concurrent.futures,json,os,sys,resource,shutil,signal,subprocess,time,traceback
from pathlib import Path
from rvv_ara_replay import observer,read,sha
R=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else Path(__file__).resolve().parent
STAGE=Path('/home/vick/rvdbt-special-memory-20261012-task118/build')
PINS={str(STAGE/'bin/elfrun'):'533443050f4d1ad4dc49ca74f3e5ac4ca1ccc576f2b107d3771412a218ac3e31',str(STAGE/'lib/libdbtjitshared.so'):'1773ca2bf867b0d3bdd76f1b60b168cbeda6d620a71ebd0ae9653d6da6feea6d'}
PREFIX='/home/user/research/materials/thesis_rvv_20260921/artifacts/rvv_validation_delivery_20261009/'
def remote(p):return Path(str(p).replace(PREFIX,'/home/vick/'))
def staged_observer(p):return Path(str(p).replace(PREFIX,str(R/'observers')+'/'))
def save(p,x):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,indent=2)+'\n')
def pins():assert all(sha(p)==h for p,h in PINS.items())
def run(c):
 d=R/'raw'/c['id'];d.mkdir(parents=True,exist_ok=False);w=d/'work';(w/'fs').mkdir(parents=True);(w/'cache').mkdir();elf=remote(c['elf']);assert sha(elf)==c['elf_sha256'];shutil.copy2(elf,w/'fs/t.elf');pins()
 cmd=[str(STAGE/'bin/elfrun'),*[x.replace('{WORK}',str(w)) for x in c['normalized_flags']]];save(d/'command.json',cmd);save(d/'IDENTITY.json',PINS)
 start=time.time();timeout=False
 with (d/'stdout').open('wb') as o,(d/'stderr').open('wb') as e:
  p=subprocess.Popen(cmd,cwd=d,stdout=o,stderr=e,env=dict(os.environ,LD_LIBRARY_PATH=str(STAGE/'lib')+':/lib/x86_64-linux-gnu'),start_new_session=True)
  try:rc=p.wait(timeout=c['timeout'])
  except subprocess.TimeoutExpired:timeout=True;os.killpg(p.pid,signal.SIGKILL);p.wait();rc=None
 pins();save(d/'IDENTITY_AFTER.json',PINS);c=dict(c,_rawdir=d)
 ok,detail=observer(c,rc,(d/'stdout').read_bytes(),staged_observer(c['producer']))
 save(d/'observer.json',detail)
 status='TIMEOUT' if timeout else 'CRASH' if rc<0 else 'SCOPED_PASS' if ok and c['scope']=='TEST_CASE1_2_ONLY' else 'PASS' if ok else 'RESULT_MISMATCH'
 save(d/'result.json',dict(id=c['id'],case=c['case'],arm=c['arm'],status=status,returncode=rc,timeout=timeout,accepted_scope_pass=ok,whole_file_pass=ok and c['scope']!='TEST_CASE1_2_ONLY',elf_sha256=c['elf_sha256'],stdout_sha256=sha(d/'stdout'),stderr_sha256=sha(d/'stderr'),observer_sha256=sha(d/'observer.json'),elapsed_seconds=time.time()-start))
 return status
if __name__=='__main__':
 resource.setrlimit(resource.RLIMIT_CORE,(0,0));q=read(R/'QUEUE.json');assert read(R/'PRODUCTION_EQUALITY.json')['production_matches'];pins()
 # No guests until every ELF and actual original parser dependency matches the derived selection.
 checked={}
 for c in q['calls']:
  for p,h in [(c['elf'],c['elf_sha256']),(c['runner'],c['runner_sha256'])]:
   if p not in checked:assert sha(remote(p) if p==c['elf'] else staged_observer(p))==h,p;checked[p]=h
  producer=Path(c['producer'])
  for p,h in q['inputs'].items():
   if Path(p).parent==producer and Path(p).name in ('run.py','runner.py','checker.py','exact_check.py','initializer_check.py','run.original.py.txt','CASES.json','CASES_BUILT.json','GROUPS.json','CONFIGS.json','SELECTED.json','COMPILED_FLAG_MAP.json','COMPILED_SCALAR_MAP.json','PREREGISTERED.json') and p not in checked:
    assert sha(staged_observer(p))==h,p;checked[p]=h
 save(R/'REMOTE_INPUT_AUDIT.json',checked);save(R/'IDENTITY_BEFORE.json',PINS);print(json.dumps(q['counts'],indent=2),flush=True)
 selected=read(R/'AFFECTED_QUEUE.json') if len(sys.argv)>2 and sys.argv[2]=='affected' else q['calls']
 assert all(c in q['calls'] for c in selected)
 count=collections.Counter()
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
  for f in concurrent.futures.as_completed([pool.submit(run,c) for c in selected]):
   try:count[f.result()]+=1
   except Exception:count['RUNNER_ERROR']+=1;print(traceback.format_exc(),flush=True)
   if sum(count.values())%100==0:print('PROGRESS',sum(count.values()),dict(count),flush=True)
 pins();save(R/'IDENTITY_AFTER.json',PINS);save(R/('EXECUTION_COUNTS.affected.json' if len(selected)!=len(q['calls']) else 'EXECUTION_COUNTS.json'),dict(count));print('COMPLETE',dict(count),flush=True)
