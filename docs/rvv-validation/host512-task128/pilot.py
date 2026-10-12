import importlib.util,sys,resource,json
from pathlib import Path
root=Path(sys.argv[1]).resolve()
spec=importlib.util.spec_from_file_location('original121','/home/vick/act-current121/run121.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
a.STAGE=root/'build';a.R=root/'pilot';a.R.mkdir()
a.PINS={str(p):a.sha(p) for p in (a.STAGE/'bin/elfrun',a.STAGE/'lib/libdbtjitshared.so')}
q=a.read(Path('/home/vick/act-current121/QUEUE.json'))
cases={'Vls32-vle32.v','Vls8-vle32.v','Vls32-vse32.v','Vls32-vl1re32.v','Vls32-vlm.v','Vls32-vlse32.v','Vls32-vluxei32.v','Vls32-vle32ff.v'}
entries=[e for e in q['entries'] if e['case'] in cases];calls=[c for c in q['calls'] if c['case'] in cases]
assert len(entries)==8 and len(calls)==32
inputs={}
for e in entries:
 for f in ('source','elf','checker','expected','capture'):
  p=Path(e[f]);assert a.sha(p)==e[f+'_sha256'];inputs[str(p)]=a.sha(p)
a.save(a.R/'INPUTS.json',inputs)
a.save(a.R/'QUEUE.json',{'entries':entries,'calls':calls,'predicate':q['original_DUT_predicate']})
r=[]
for c in calls:
 status=a.run(c);r.append(dict(case=c['case'],arm=c['arm'],status=status));print(r[-1],flush=True)
 if status!='PASS':
  a.save(a.R/'RESULTS.json',r);raise SystemExit(1)
a.save(a.R/'RESULTS.json',r)
# Diagnostic copies add only exit-time byte dump; primary pilot flags above remain exact.
a.R=root/'inspection';a.R.mkdir()
inspect=[]
for c in calls:
 if c['case'] not in {'Vls32-vle32.v','Vls32-vse32.v','Vls8-vle32.v','Vls32-vl1re32.v'}:continue
 c=dict(c);cmd=list(c['original_command']);cmd.insert(cmd.index('--'),'--dump-tbcode='+str(a.R/'unused.txt'));c['original_command']=cmd
 status=a.run(c);inspect.append(dict(case=c['case'],arm=c['arm'],status=status))
 if status!='PASS':a.save(a.R/'RESULTS.json',inspect);raise SystemExit(1)
a.save(a.R/'RESULTS.json',inspect)
assert all(a.sha(Path(p))==h for p,h in inputs.items())
