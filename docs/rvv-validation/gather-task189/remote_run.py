import os,pathlib,subprocess,json,hashlib,time,sys
root=pathlib.Path('/home/vick/rvdbt-exception-task186');out=root/'task189';out.mkdir(exist_ok=True)
phase=sys.argv[1];folder=out/(phase+'-corrected');folder.mkdir(exist_ok=False)
assert os.getpriority(os.PRIO_PROCESS,0)==10
assert (root/'configure.rc').read_text().strip()=='0'
def resource():
 s=os.statvfs(root);free=s.f_bavail*s.f_frsize;assert free>=10*1024**3
 return {'free_bytes':free,'nice':os.getpriority(os.PRIO_PROCESS,0),'load':os.getloadavg(),'processes':subprocess.check_output(['ps','-eo','pid,ppid,ni,comm,args'],text=True)}
before=resource()
targets=['rv32_optional_gather_fault_test']+(['rv32_native_memory_fault_test'] if phase=='fixed' else [])
old={t:hashlib.sha256((root/'build/bin'/t).read_bytes()).hexdigest() if (root/'build/bin'/t).exists() else None for t in targets}
with (folder/'build.log').open('w') as f:rc=subprocess.call(['cmake','--build',str(root/'build'),'-j2','--target']+targets,stdout=f,stderr=subprocess.STDOUT)
(folder/'build.rc').write_text(str(rc)+'\n')
(folder/'build-resource.json').write_text(json.dumps({'before':before,'after':resource(),'rc':rc},indent=2))
assert rc==0,'Failed build: testing forbidden'
results=[]
for t in targets:
 binary=root/'build/bin'/t;sha=hashlib.sha256(binary.read_bytes()).hexdigest();assert sha!=old[t],'Fresh changed executable required'
 run=folder/t;run.mkdir();cmd=[str(binary)]+(['--original'] if phase=='original' else [])
 before=resource();started=time.time()
 with (run/'stdout').open('w') as f,(run/'stderr').open('w') as e:rc=subprocess.call(cmd,cwd=run,stdout=f,stderr=e,timeout=180)
 result={'command':cmd,'rc':rc,'sha256':sha,'old_sha256':old[t],'seconds':time.time()-started,'before':before,'after':resource()}
 (run/'execution.json').write_text(json.dumps(result,indent=2));results.append(result)
 print(t,rc,(run/'stdout').read_text().splitlines()[-1:],flush=True)
(folder/'results.json').write_text(json.dumps(results,indent=2))
raise SystemExit(any(r['rc'] for r in results))
