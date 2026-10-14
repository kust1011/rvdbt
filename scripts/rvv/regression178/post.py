"""Finish focused matrices and export only after the complete directed queue."""
import json,subprocess,sys,time
from pathlib import Path
B=Path('/home/vick/rvv-task178')
while not (B/'DIRECTED_COMPLETE').exists():time.sleep(5)
for name in ('guard165','guard166','faults','fof-startmask','vill'):
 for action in ('replay','audit'):
  if (B/'focused'/name/action/'COMPLETE').exists():continue
  args=[sys.executable,str(B/'tools/focused.py'),name]+(['audit'] if action=='audit' else [])
  with (B/(name+'-'+action+'.log')).open('w') as f:rc=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT).returncode
  if rc:
   (B/'FOCUSED_STOPPED.json').write_text(json.dumps(dict(suite=name,stage=action,returncode=rc),indent=2)+'\n');raise SystemExit(rc)
while not (B/'external/audit/COMPLETE').exists():time.sleep(5)
with (B/'summarize.log').open('w') as f:rc=subprocess.run([sys.executable,str(B/'tools/summarize.py')],stdout=f,stderr=subprocess.STDOUT).returncode
raise SystemExit(rc)
