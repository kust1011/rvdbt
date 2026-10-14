import os
"""Audit external retained packets after all commands finish; stop on failure."""
import json,subprocess,sys,time
from pathlib import Path
B=Path(os.environ.get('RVV_TASK181_ROOT','/home/vick/rvv-task181'))
while not (B/'external/COMPLETE').exists():
 if (B/'STOP_NEW_GUESTS.json').exists():raise SystemExit(1)
 time.sleep(5)
with (B/'external-audit.log').open('w') as f:
 rc=subprocess.run([sys.executable,str(B/'tools/audit_external.py')],stdout=f,stderr=subprocess.STDOUT).returncode
if rc:(B/'EXTERNAL_AUDIT_STOPPED.json').write_text(json.dumps(dict(returncode=rc))+'\n')
raise SystemExit(rc)
