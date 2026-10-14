"""Task195 bounded changed-build integration; no historical matrix entrypoints."""
import collections, hashlib, importlib.util, json, os, resource, shutil, subprocess, sys, time
from pathlib import Path as P
root=P('/home/vick/rvv-integration-task195'); fixed=P('/home/vick/rvv-long-task192'); build=fixed/'build'; engine=build/'bin/elfrun'
PIN='908df235e36fe49f8a64793a8e4a401987f9b2c56da10179470b7bc7bd5ffbc4'
fixtures=['rvv_rvv_contract_test','rvv_vector_run_codegen_test','vchunk_dataflow_test','vstatechunkload_test','rvv_ssa_edge_commit_test','rvv_active_vl_widen_bound_test','rvv_active_vl_narrow_bound_test','rvv_fp_shared_mask_test','rvv_active_mask_memory_test','rvv_run_live_range_split_test']
def sha(p): return hashlib.sha256(P(p).read_bytes()).hexdigest()
def save(p,x): P(p).parent.mkdir(parents=True,exist_ok=True);P(p).write_text(json.dumps(x,indent=2)+'\n')
def load(p): return json.loads(P(p).read_text())
def resources():
 assert os.getpriority(os.PRIO_PROCESS,0)==10
 free=shutil.disk_usage(root).free;assert free>=10*1024**3
 return dict(free_bytes=free,nice=10,affinity='inherited; no assignment',load=os.getloadavg())
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
assert root.is_dir();resource.setrlimit(resource.RLIMIT_CORE,(0,0))
assert sha(engine)==PIN
source=load(fixed/'SOURCE191.json');source={p:sha(fixed/'source'/p) for p in source}
pins={str(p):sha(p) for p in [engine,build/'lib/libdbtstatic.a',build/'lib/libdbtjitshared.so',build/'bin/qra_vpr_test']}
initial=load(root/'BEFORE.json');assert pins==initial['binaries'];assert [p for p in source if source[p]!=initial['source'][p]]==['dbt/qmc/qcg/rvv_fp_shared_mask_test.cpp','dbt/qmc/qcg/vchunk_dataflow_test.cpp'];save(root/'RESUME3.json',dict(source=source,binaries=pins,resources=resources()))
act=module('act121','/home/vick/act-current121/run121.py');chips=module('chips120','/home/vick/chips-current120/runner.py')
aq=load('/home/vick/act-current121/QUEUE.json');cq=load('/home/vick/chips-current120/manifest.json')
actnames={'Vx32-vwadd.vv-00','Vx32-vnsrl.wv-00','Vx32-vmand.mm-00','Vls32-vle32.v','Vls32-vse32.v'}
acalls=[c for c in aq['calls'] if c['case'] in actnames];assert len(acalls)==20
entries=[e for e in aq['entries'] if e['case'] in actnames];assert len(entries)==5
for e in entries:
 for f in ['source','elf','checker','expected','capture']: assert sha(e[f])==e[f+'_sha256']
choices={('geometry4096','vwadd_vv-0'),('narrowfixed128','vnsrl_wv-0'),('mask1024','vmand_mm-0'),('long4096','vle32_v-0'),('long4096','vse32_v-0')}
ccalls=[]
for c in cq['cells']:
 matches=[a for a in c['aliases'] if (a['batch'],a['test']) in choices]
 if matches:
  assert not c['control'] and len(matches)==1
  assert sha(P('/home/vick/rvv_final_regression_20261007/inputs')/(c['elf_sha256']+'.elf'))==c['elf_sha256']
  ccalls.append(dict(cell=c,alias=matches[0]))
assert len(ccalls)==20
for calls,key in [(acalls,lambda c:(c['case'],c['arm'])),(ccalls,lambda c:(c['alias']['test'],c['alias']['arm']))]:
 counts=collections.Counter(key(c)[1] for c in calls);assert counts==dict.fromkeys(['B','M1','M2','BOTH'],5)
available={n:(build/'bin'/n).is_file() for n in fixtures};missing=[n for n in fixtures if not available[n]]
selection=dict(fixtures=fixtures,available=available,missing=missing,act_entries=entries,act_calls=acalls,chips_calls=ccalls,tools={m.__file__:sha(m.__file__) for m in [act,chips]},rule='five original cases per suite, four original arms, unchanged ELF/oracle/checker; diagnostics only; no reference or guest builds',baseline_cases=load(fixed/'baseline-int/manifest.json')['cases'])
save(root/'RESUME_SELECTION.json',selection)
results=load(root/'RESULTS.json')
env=dict(os.environ,LD_LIBRARY_PATH=str(build/'lib'))
def run(name,cmd,check,detail,timeout=300):
 d=root/name;d.mkdir(parents=True,exist_ok=False);before=resources();start=time.time()
 with (d/'stdout').open('wb') as so,(d/'stderr').open('wb') as se:
  proc=subprocess.Popen(list(map(str,cmd)),cwd=root,stdout=so,stderr=se,env=env,start_new_session=True)
  expired=False
  try: rc=proc.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
   import signal
   expired=True;os.killpg(proc.pid,signal.SIGKILL);rc=proc.wait()
 o=(d/'stdout').read_bytes();e=(d/'stderr').read_bytes();ok=not expired and check(rc,o,e)
 rec=dict(name=name,command=list(map(str,cmd)),returncode=rc,timeout=expired,pass_check=ok,seconds=time.time()-start,stdout_sha256=sha(d/'stdout'),stderr_sha256=sha(d/'stderr'),before=before,after=resources(),detail=detail)
 save(d/'execution.json',rec);results.append(rec);save(root/'RESULTS.json',results);print(name,rc,ok,flush=True);assert ok,name
 return d,o,e
missing=['rvv_fp_shared_mask_test']
if missing:
 run('build-mask-checker-fix',['cmake','--build',str(build),'-j2','--target',*missing],lambda rc,o,e:rc==0,dict(missing_only=missing),1800)
for n in fixtures:
 if any(r['name'] in ('fixtures/'+n,'fixtures/'+n+'-corrected') and r['pass_check'] for r in results):continue
 run('fixtures/'+n+('-corrected2' if n=='rvv_fp_shared_mask_test' else ''),[build/'bin'/n],lambda rc,o,e:rc==0,dict(binary_sha256=sha(build/'bin'/n),native_credit='read output/source individually; process execution alone is not native emitted-code evidence'))
for suite,calls in [('act',acalls),('chips',ccalls)]:
 for item in calls:
  c=item if suite=='act' else item['cell'];a=None if suite=='act' else item['alias']
  name=c['case'] if suite=='act' else a['test'];arm=c['arm'] if suite=='act' else a['arm']
  dest=root/'external'/suite/name/arm;work=dest/'work';(work/'fs').mkdir(parents=True);(work/'cache').mkdir()
  elf=P(c['elf']) if suite=='act' else P('/home/vick/rvv_final_regression_20261007/inputs')/(c['elf_sha256']+'.elf')
  shutil.copy2(elf,work/'fs/t.elf');assert sha(work/'fs/t.elf')==c['elf_sha256']
  flags=[f.replace('{WORK}',str(work)) for f in (c['normalized_flags'] if suite=='act' else c['flags'])]
  i=flags.index('--');diagnostics=['--dump-tbmap='+str(dest/'capture/tbmap'),'--dump-tbcode='+str(dest/'capture/tbcode'),'--rvv-pc-census=1','--rvv-pc-census-out='+str(dest/'capture/pc-census.csv')]
  if not any(f.startswith('--rvv-stats=') for f in flags):diagnostics.append('--rvv-stats=1')
  flags[i:i]=diagnostics
  check=(lambda rc,o,e,c=c:eval(act.predicate,{'__builtins__':{}},dict(rc=rc,raw=(o+e).decode(errors='replace'),N=c['case'],sig=None))) if suite=='act' else (lambda rc,o,e,c=c:chips.classify(rc,o,c,False)=='PASS')
  d,o,e=run(str(dest.relative_to(root))+'/capture',[engine,*flags],check,dict(original_call=item,elf_sha256=c['elf_sha256'],diagnostic_additions=diagnostics))
  text=e.decode(errors='replace');assert 'overflow=0' in (d/'pc-census.csv').read_text()
  save(dest/'ROUTE.json',dict(lines=[l for l in text.splitlines() if 'RVV_' in l or 'inline_hits' in l],pc_census_sha256=sha(d/'pc-census.csv'),tbmap_sha256=sha(d/'tbmap'),tbcode_sha256=sha(d/'tbcode'),claim='retained actual counters/census/emitted code; options give no native credit'))
# Exactly four changed-build DUT commands; reuse long192 predicates and reference.
sys.path[:0]=[str(fixed/'tools'),'/home/vick/rvdbt-exception-task186/task191-tools']
import long192 as l
l.install();before=resources();l.replay(fixed/'baseline-int',root/'baseline-int',engine,'long192-int-w4096-e8-m8')
resources();save(root/'baseline-int/resources.json',dict(before=before,after=resources()))
import review_sequences177 as review
review.audit([root/'baseline-int'],root/'baseline-int/audit')
assert source=={p:sha(fixed/'source'/p) for p in source};assert pins=={p:sha(p) for p in pins}
save(root/'FINAL.json',dict(status='PASS_BOUNDED_INTEGRATION',fixture_commands=10,external_commands=40,baseline_DUT_commands=4,baseline_DUT_packet_checks=16,guest_builds=0,reference_commands=0,existing_fixed192_checks_repeated=0,after=resources(),source=source,binaries=pins,fixtures={n:sha(build/'bin'/n) for n in fixtures},production_edits=0))
print('TASK195 PASS',flush=True)
