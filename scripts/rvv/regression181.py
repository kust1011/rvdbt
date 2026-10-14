#!/usr/bin/env python3
"""Replay the final179 frozen queue or one bounded pilot in a fresh namespace."""
import argparse,json,shlex,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('action',choices=['minimal','run','external','external-audit','focused','summarize','status'])
p.add_argument('--host',default='xbd')
p.add_argument('--entry',default='b145-000')
p.add_argument('--output',help='Required fresh absolute remote namespace for minimal')
p.add_argument('--focused-suite',choices=['guard165','guard166','faults','fof-startmask','vill'])
a=p.parse_args();root='/home/vick/rvv-task181'
if a.action=='minimal':
 if not a.output or not a.output.startswith('/'):p.error('minimal requires --output with a fresh absolute remote path')
 code="""import hashlib,json,shutil,sys
from pathlib import Path
base=Path('/home/vick/rvv-task181');out=Path(sys.argv[1]);entry=sys.argv[2]
plan=json.load(open(base/'DIRECTED_PLAN.json'));assert any(e['id']==entry for e in plan['entries'])
assert plan['build']=='8a468967852b8f16225b359fce99c0d22ab286d6314cb90a79934a7376207281'
assert not out.exists(),'never overwrite an execution namespace'
out.mkdir(parents=True);(out/'tools').mkdir()
for name in ('DIRECTED_PLAN.json','PREDICATE_DATA_PINS.json'):shutil.copy2(base/name,out/name)
"""
 subprocess.run(['ssh',a.host,'python3 - '+shlex.join([a.output,a.entry])],input=code,text=True,check=True)
 sources=sorted((Path(__file__).parent/'regression181').glob('*.py'))
 subprocess.run(['scp',*[str(x) for x in sources],a.host+':'+a.output+'/tools/'],check=True)
 cmd='cd '+shlex.quote(a.output)+' && nice -n 10 env PYTHONDONTWRITEBYTECODE=1 RVV_TASK181_OWNER=181 RVV_TASK181_ROOT='+shlex.quote(a.output)+' python3 tools/replay.py pilot '+shlex.quote(a.entry)
else:
 commands={'run':['python3','tools/run.py'],'external':['python3','tools/external.py',root+'/external'],'external-audit':['python3','tools/audit_external.py'],'summarize':['python3','tools/summarize.py'],'status':['python3','tools/status.py']}
 if a.action=='focused':
  if not a.focused_suite:p.error('--focused-suite is required')
  commands['focused']=['python3','tools/focused.py',a.focused_suite]
 cmd='cd '+shlex.quote(root)+' && nice -n 10 env PYTHONDONTWRITEBYTECODE=1 '+shlex.join(commands[a.action])
raise SystemExit(subprocess.run(['ssh',a.host,cmd]).returncode)
