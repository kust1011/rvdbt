#!/usr/bin/env python3
"""Run only reviewed terminal-fault and independently initialized ordinary fixtures."""
import hashlib,json,os,pathlib,subprocess,time
root=pathlib.Path('/home/vick/rvdbt-exception-task186')
assert (root/'configure.rc').read_text().strip()=='0'
assert (root/'build.rc').read_text().strip()=='0'
runs=[('unit','rv32_unit_memory_fault_test',[]),
 ('family','rv32_family_memory_fault_test',[]),
 ('special','rv32_special_memory_fault_test',[]),
 ('native','rv32_native_memory_fault_test',[]),
 ('whole','rv32_whole_native_fault_test',[]),
 ('whole-normal','rv32_whole_native_fault_test',['--normal-only']),
 ('scalar','rv32_scalar_native_fault_test',[]),
 ('grouped-terminal','rv32_grouped_memory_fault_test',['--terminal']),
 ('grouped-normal','rv32_grouped_memory_fault_test',['--normal-only']),
 ('bulk','rv32_permitted_bulk_fault_test',[])]
def reserve():
 s=os.statvfs(root); free=s.f_bavail*s.f_frsize
 assert free>=10*1024**3,free
 return free
def resource():
 return {'time':time.time(),'free_bytes':reserve(),'load':os.getloadavg(),
 'processes':subprocess.check_output(['ps','-eo','pid,ppid,ni,comm,args'],text=True)}
assert os.getpriority(os.PRIO_PROCESS,0)==10
raw=root/'raw-nice10';raw.mkdir(exist_ok=True)
with (root/'final-build.log').open('w') as log:
 rc=subprocess.call(['cmake','--build',str(root/'build'),'-j2','--target']+
                    list(dict.fromkeys(r[1] for r in runs)),stdout=log,stderr=subprocess.STDOUT)
(root/'final-build.rc').write_text(str(rc)+'\n');assert rc==0,rc
results=[]
for name,target,args in runs:
 work=raw/name;work.mkdir(exist_ok=True)
 assert not (work/'execution.json').exists(), 'Never overwrite original run'
 cmd=[str(root/'build/bin'/target)]+args
 before=resource();started=time.time()
 with (work/'stdout').open('wb') as out,(work/'stderr').open('wb') as err:
  rc=subprocess.call(cmd,cwd=work,stdout=out,stderr=err)
 after=resource()
 result={'name':name,'command':cmd,'rc':rc,'seconds':time.time()-started,
         'before':before,'after':after,
         'sha256':hashlib.sha256((root/'build/bin'/target).read_bytes()).hexdigest()}
 (work/'execution.json').write_text(json.dumps(result,indent=2)+'\n')
 results.append(result)
 print(name,rc,(work/'stdout').read_text().splitlines()[-1:] ,flush=True)
(root/'RESULTS-nice10.json').write_text(json.dumps(results,indent=2)+'\n')
raise SystemExit(any(r['rc'] for r in results))
