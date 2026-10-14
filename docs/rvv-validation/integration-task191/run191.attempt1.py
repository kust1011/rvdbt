"""Bounded Task191 production integration; never imports a matrix controller."""
import ast, hashlib, importlib.util, json, os, pathlib, re, resource, subprocess, time
P=pathlib.Path
root=P('/home/vick/rvdbt-exception-task186'); out=root/'task191';out.mkdir(exist_ok=False)
assert os.getpriority(os.PRIO_PROCESS,0)==10
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def sha(p):return hashlib.sha256(P(p).read_bytes()).hexdigest()
def save(p,x):P(p).write_text(json.dumps(x,indent=2)+'\n')
def resources():
 s=os.statvfs(root);free=s.f_bavail*s.f_frsize;assert free>=10*1024**3
 return dict(free_bytes=free,nice=os.getpriority(os.PRIO_PROCESS,0),load=os.getloadavg(),processes=subprocess.check_output(['ps','-eo','pid,ppid,ni,comm,args'],text=True))
expected=json.loads((root/'EXPECTED_SOURCE191.json').read_text())
assert all(sha(root/'source'/p)==h for p,h in expected.items())
assert (root/'task191-build.rc').read_text().strip()=='0'
artifacts=['bin/elfrun','lib/libdbtstatic.a','lib/libdbtjitshared.so']
fixtures=[('mmu_mapping_metadata_test',[]),('rvv_rvv_contract_test',[]),('rvv_vector_run_codegen_test',[]),('rv32_optional_gather_fault_test',[]),('rv32_native_memory_fault_test',[]),('rv32_scalar_native_fault_test',[]),('rv32_grouped_memory_fault_test',['--normal-only']),('rv32_grouped_memory_fault_test',['--terminal'])]
artifacts+=['bin/'+n for n,a in fixtures]
pins={p:sha(root/'build'/p) for p in artifacts}
frozen=P('/home/vick/rvdbt-host512-task179-build/build')
frozen_pins={str(frozen/p):sha(frozen/p) for p in ['bin/elfrun','lib/libdbtjitshared.so']}
save(out/'MANIFEST.json',dict(source=expected,build=pins,frozen179=frozen_pins,cache_sha256=sha(root/'build/CMakeCache.txt'),compiler=subprocess.check_output(['/usr/bin/clang++-22','--version'],text=True),cpu=subprocess.check_output(['lscpu'],text=True),before=resources()))
results=[]
env=dict(os.environ,LD_LIBRARY_PATH=str(root/'build/lib')+':/lib/x86_64-linux-gnu')
def run(name,cmd,check,detail):
 d=out/name;d.mkdir(parents=True,exist_ok=False);before=resources();started=time.time()
 with (d/'stdout').open('wb') as so,(d/'stderr').open('wb') as se:
  try:rc=subprocess.call(cmd,cwd=d,stdout=so,stderr=se,env=env,timeout=180);timeout=False
  except subprocess.TimeoutExpired:rc=None;timeout=True
 raw=(d/'stdout').read_bytes();err=(d/'stderr').read_bytes()
 ok=not timeout and check(rc,raw,err)
 r=dict(name=name,command=list(map(str,cmd)),rc=rc,timeout=timeout,pass_check=ok,seconds=time.time()-started,stdout_sha256=sha(d/'stdout'),stderr_sha256=sha(d/'stderr'),before=before,after=resources(),detail=detail)
 save(d/'execution.json',r);results.append(r);save(out/'RESULTS.json',results)
 print(name,rc,ok,raw.decode(errors='replace').splitlines()[-1:],flush=True)
 assert ok,name
 return raw,err
for n,a in fixtures:
 run('fixtures/'+n+('-'+a[0][2:] if a else ''),[str(root/'build/bin'/n)]+a,lambda rc,o,e:rc==0,dict(binary_sha256=pins['bin/'+n]))
# Load predicate functions, never historical main/controller entrypoints.
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
act=module('act121','/home/vick/act-current121/run121.py')
chips=module('chips120','/home/vick/chips-current120/runner.py')
aq=json.loads(P('/home/vick/act-current121/QUEUE.json').read_text());cq=json.loads(P('/home/vick/chips-current120/manifest.json').read_text())
names={'Vls32-vluxei32.v','Vls32-vloxei32.v'}
entries=[e for e in aq['entries'] if e['case'] in names];assert len(entries)==2
inputs={}
for e in entries:
 for field in ['source','elf','checker','expected','capture']:
  assert sha(e[field])==e[field+'_sha256'];inputs[e[field]]=e[field+'_sha256']
 # Audit preserved source for actual equal-register load aliases.
 text=P(e['source']).read_text();aliases=[];count=0
 for lineno,line in enumerate(text.splitlines(),1):
  m=re.search(r'\b(vl[ou]xei32\.v)\s+v(\d+),\s*\([^)]*\),\s*v(\d+)',line)
  if m:
   count+=1
   if m[2]==m[3]:aliases.append(dict(line=lineno,instruction=line.strip()))
 e['task191_alias_audit']=dict(target_instructions=count,equal_vd_vs2=aliases)
acalls=[c for c in aq['calls'] if c['case'] in names];assert len(acalls)==8
ccalls=[c for c in cq['cells'] if not c['control'] and any(a['batch']=='indexload128' and a['test'] in ('vluxei32_v-0','vluxei32_v-1','vloxei32_v-0','vloxei32_v-1') and a['arm']=='BOTH' for a in c['aliases'])];assert len(ccalls)==4
save(out/'SELECTION.json',dict(act=acalls,chips=ccalls,act_entries=entries,rule='Two original ACT e32 indexed loads in four original arms; four original CHIPS e32 indexed loads in BOTH; each gather off/on; counters diagnostic only',original_flags_delta=['--rvv-gather=0/1','--rvv-stats=1'],inputs=inputs,tools={str(P(act.__file__)):sha(act.__file__),str(P(chips.__file__)):sha(chips.__file__)}))
for suite,calls in [('act',acalls),('chips',ccalls)]:
 for c in calls:
  name=c['case']+'/'+c['arm'] if suite=='act' else next(a['test'] for a in c['aliases'] if a['batch']=='indexload128' and a['arm']=='BOTH')
  elf=P(c['elf']) if suite=='act' else P('/home/vick/rvv_final_regression_20261007/inputs')/(c['elf_sha256']+'.elf')
  assert sha(elf)==c['elf_sha256']
  for gather in [0,1]:
   d=out/'external'/suite/name/str(gather);w=d/'work';(w/'fs').mkdir(parents=True);(w/'cache').mkdir();os.symlink(elf,w/'fs/t.elf')
   flags=c['normalized_flags'] if suite=='act' else c['flags']
   flags=[x.replace('{WORK}',str(w)) for x in flags]
   assert not any(x.startswith(('--rvv-gather=','--rvv-stats=')) for x in flags)
   # Put options before the guest-argv separator.
   split=flags.index('--');flags[split:split]=[f'--rvv-gather={gather}','--rvv-stats=1']
   cmd=[str(root/'build/bin/elfrun'),*flags]
   check=(lambda rc,o,e,c=c:eval(act.predicate,{'__builtins__':{}},dict(rc=rc,raw=(o+e).decode(errors='replace'),N=c['case'],sig=None))) if suite=='act' else (lambda rc,o,e,c=c:chips.classify(rc,o,c,False)=='PASS')
   raw,err=run(str(d.relative_to(out))+'/capture',cmd,check,dict(suite=suite,original_call=c,elf_sha256=c['elf_sha256'],gather=gather))
   text=err.decode(errors='replace');m=re.search(r'RVV_GATHER attempts=(\d+) calls=(\d+) elems=(\d+) unmapped=(\d+)',text);assert m,'missing counters'
   counters=dict(zip(['attempts','calls','elems','unmapped'],map(int,m.groups())))
   save(d/'counters.json',counters)
   if not gather:assert not any(counters.values()),'off gate must short circuit'
assert all(sha(root/'source'/p)==h for p,h in expected.items())
assert all(sha(root/'build'/p)==h for p,h in pins.items())
assert all(sha(p)==h for p,h in frozen_pins.items())
save(out/'FINAL.json',dict(status='PASS_BOUNDED_INTEGRATION',invocations=len(results),fixtures=len(fixtures),external=len(results)-len(fixtures),after=resources(),build=pins,frozen179_after=frozen_pins,production_edits=0,full_matrix_calls=0,repair_return_retry_calls=0))
