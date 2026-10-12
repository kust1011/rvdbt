import importlib.util,resource
from pathlib import Path
r=Path('/home/vick/rvdbt-host512-task128');spec=importlib.util.spec_from_file_location('original121','/home/vick/act-current121/run121.py');a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
a.STAGE=r/'build';a.R=r/'inspection';a.PINS={str(p):a.sha(p) for p in (a.STAGE/'bin/elfrun',a.STAGE/'lib/libdbtjitshared.so')};resource.setrlimit(resource.RLIMIT_CORE,(0,0))
results=[]
for c in a.read(r/'pilot/QUEUE.json')['calls']:
 if c['case'] not in {'Vls32-vlm.v','Vls32-vlse32.v','Vls32-vluxei32.v','Vls32-vle32ff.v'}:continue
 if (a.R/'raw'/c['case']/c['arm']/'result.json').exists():continue
 c=dict(c);cmd=list(c['original_command'])
 if not any(x.startswith('--dump-tbcode=') for x in cmd):cmd.insert(cmd.index('--'),'--dump-tbcode='+str(a.R/'unused.txt'))
 c['original_command']=cmd
 status=a.run(c);results.append(dict(case=c['case'],arm=c['arm'],status=status));assert status=='PASS'
a.save(a.R/'RESULTS-extra.json',results)
