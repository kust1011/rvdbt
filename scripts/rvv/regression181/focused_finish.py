"""Complete independent focused queues on final179 under common owner admission."""
import json,subprocess,sys
from pathlib import Path
B=Path('/home/vick/rvv-task181')
for name in ('guard165','guard166','faults','fof-startmask','vill'):
 for action in ('replay','audit'):
  if (B/'focused'/name/action/'COMPLETE').exists():continue
  args=[sys.executable,str(B/'tools/focused.py'),name]+(['audit'] if action=='audit' else [])
  with (B/(name+'-'+action+'.log')).open('w') as f:rc=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT).returncode
  if rc:
   (B/'FOCUSED_STOPPED.json').write_text(json.dumps(dict(suite=name,stage=action,returncode=rc),indent=2)+'\n');raise SystemExit(rc)
(B/'FOCUSED_COMPLETE').write_text('PASS\n')
