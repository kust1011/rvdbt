#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate/build/execute one ordinary vadd unit with existing directed APIs."""
import argparse,fcntl,hashlib,json,os,shutil,sys,time
from contextlib import contextmanager
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'scripts/rvv/directed')]
import rvv_verify as entry
import vadd as v
UNIT='w128-e32-m1-vv-zero'
PINS={'dut':'8a468967852b8f16225b359fce99c0d22ab286d6314cb90a79934a7376207281','dut_lib':'79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af','spike':'cddd7a406bd92836f220e929aca0f4925542e80d0b2246b8920e6f49648a6994','pk':'30f4e5906b13264ff98a8fa36dfea848f8504a65c028e96930329668f1f564ad','link':'671d4a06b5298dc776ad61cee92acf0f249e35262d87fa039ec4033950720c71'}
@contextmanager
def admitted(kind,parent):
 with open('/tmp/rvv-shared-admission.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  snap=entry.census()
  if len(snap['guests'])>8 or snap['offline_budget_used']>2:raise RuntimeError('shared capacity unavailable')
  if shutil.disk_usage(parent).free<11*1024**3:raise RuntimeError('10GiB reserve plus working space')
  if kind=='build':
   builds=0
   for p in Path('/proc').iterdir():
    try:exe=Path((p/'cmdline').read_bytes().split(b'\0')[0].decode()).name
    except (OSError,UnicodeError):continue
    builds+=exe.startswith(('clang','ld.lld'))
   if builds>=4:raise RuntimeError('shared build slots occupied')
  yield snap
@contextmanager
def predicate(timeout):
 deadline=time.monotonic()+timeout
 while True:
  for n in range(2):
   f=open('/tmp/rvv-task181-predicate-%d.lock'%n,'a')
   try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
   except BlockingIOError:f.close();continue
   try:yield
   finally:f.close()
   return
  if time.monotonic()>=deadline:raise RuntimeError('Task181 predicate slots occupied; retry later')
  time.sleep(.05)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['preflight','run'])
 for name in ('compiler','spike','pk','dut','dut-lib','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--link',type=Path,default=ROOT/'scripts/rvv/fixtures/rvvts-20261089/link.ld');p.add_argument('--library-path',default='');p.add_argument('--timeout',type=int,default=60);p.add_argument('--admission-timeout',type=int,default=30);a=p.parse_args()
 if not 0<=a.admission_timeout<=60:raise ValueError('admission-timeout must be 0..60')
 if not 1<=a.timeout<=120:raise ValueError('timeout must be 1..120')
 if a.output.exists():raise ValueError('output already exists')
 identities={}
 for key in ('compiler',*PINS):
  path=getattr(a,key);identities[key]=dict(path=str(path),sha256=entry.sha(path.read_bytes()))
  if key in PINS and identities[key]['sha256']!=PINS[key]:raise ValueError('prerequisite identity '+key)
 if not a.output.parent.is_dir():raise ValueError('output parent missing')
 report=dict(unit=UNIT,prerequisites=identities,source_modules={n:entry.sha((ROOT/'scripts/rvv/directed'/n).read_bytes()) for n in ('vadd.py','storage149.py')},scope='new ordinary 17-case B demonstration; historical compiler was clang20, configurable compiler is separately recorded; no historical acceptance or final181 credit',reference_source='CHIPS Spike 20feb9c2bf2a7deab964d8190b0cbd4b4131bec3; pk 9c61d29846d8521d9487a57739330f9682d5b542; binary pin in Task145 IDENTITIES; no reference rebuild')
 if a.action=='preflight':print(json.dumps(report,indent=2));return
 if os.getpriority(os.PRIO_PROCESS,0)!=10:raise ValueError('run requires nice -n 10')
 root=a.output/'corpus'
 with predicate(a.admission_timeout):
  a.output.mkdir()
  with admitted('build',a.output):v.build(root,str(a.compiler),a.link,selected_units=[UNIT],jobs=1)
  cs=entry.load(root/'manifest.json')['cases'];guest=v.storage.verify(root/UNIT/'test.elf')
  env=dict(os.environ,LD_LIBRARY_PATH=str(a.dut_lib.parent)+(':'+a.library_path if a.library_path else ''))
  refcmd=[str(a.spike),'--isa=rv32gcv_zvl128b',str(a.pk),str(root/UNIT/'test.elf')]
  with admitted('guest',a.output):rr=v.execute(refcmd,a.output/'reference',env,a.timeout)
  ref=v.storage.verify(a.output/'reference/stdout');entry.validate_packets(v,cs,ref,ref,rr)
  # Recorded accepted B flags, relocated in code; no legacy shell paths to edit.
  recorded=entry.load(ROOT/'docs/rvv-validation/delivery-task182/command.json')['command'];cmd=[str(a.dut),*recorded[1:]]
  fs=a.output/'fs';fs.mkdir();(fs/'t.elf').write_bytes(guest);cache=a.output/'cache';cache.mkdir();run=a.output/'dut'
  for i,x in enumerate(cmd):
   for flag,target in [('fsroot',fs),('cache',cache),('dump-tbmap',run/'tbmap'),('dump-tbcode',run/'tbcode'),('rvv-pc-census-out',run/'pc-census.csv')]:
    if x.startswith('--'+flag+'='):cmd[i]='--'+flag+'='+str(target)
  with admitted('guest',a.output) as snap:rec=v.execute(cmd,run,env,a.timeout)
  out=v.storage.verify(run/'stdout');checks=entry.validate_packets(v,cs,out,ref,rec)
 for key in PINS:
  if entry.sha(getattr(a,key).read_bytes())!=PINS[key]:raise ValueError('prerequisite changed '+key)
 report.update(status='PASS_BOUNDED_REGENERATED_VADD',checks=len(checks),guest_calls=2,DUT_calls=1,reference_calls=1,ELF_rebuilds=1,guest_sha256=entry.sha(guest),reference_sha256=entry.sha(ref),output_sha256=entry.sha(out),resources=snap)
 entry.save(a.output/'result.json',report);print(report['status'],len(checks),'checks')
if __name__=='__main__':
 try:main()
 except (OSError,ValueError,RuntimeError,AssertionError) as e:print('ERROR:',e,file=sys.stderr);sys.exit(1)
