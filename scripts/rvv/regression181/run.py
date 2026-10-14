import os
"""Complete the declared queue, stopping on preserved failures."""
import json,os,subprocess,sys,time
from pathlib import Path
B=Path(os.environ.get('RVV_TASK181_ROOT','/home/vick/rvv-task181'));P=json.load(open(B/'DIRECTED_PLAN.json'));tool=B/'tools/replay.py'
for e in P['entries']:
 output=B/'directed'/e['id'];output.mkdir(parents=True,exist_ok=True)
 recovery=(output/'remaining').exists() and not (output/'remaining/COMPLETE').exists()
 for action in (['reuse','audit'] if e['reuse_same179'] else ['pilot','recover' if recovery else 'remaining','audit']):
  if (output/action/'COMPLETE').exists():continue
  print('START',e['id'],e['family'],e['accepted_cases'],action,flush=True)
  with (output/(action+'.log')).open('w') as f:
   rc=subprocess.run([sys.executable,str(tool),action,e['id']],stdout=f,stderr=subprocess.STDOUT).returncode
  (output/(action+'.rc')).write_text(str(rc)+'\n')
  if rc:
   (B/'DIRECTED_STOPPED.json').write_text(json.dumps(dict(entry=e['id'],action=action,returncode=rc,log=str(output/(action+'.log'))),indent=2)+'\n')
   print('STOPPED',e['id'],action,rc,flush=True);raise SystemExit(rc)
 print('ENTRY_COMPLETE',e['id'],flush=True)
(B/'DIRECTED_COMPLETE').write_text('PASS\n')
