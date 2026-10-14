"""Read progress without scanning or hashing old artifact forests."""
from pathlib import Path
import json
B=Path('/home/vick/rvv-task178')
for name in ('directed.log','directed-resume.log','external.log','external-recovery-attempt2.log','external-audit.log'):
 p=B/name
 if p.exists():print(name, '\n'.join(p.read_text().splitlines()[-3:]))
for name in ('DIRECTED_STOPPED.json','DIRECTED_COMPLETE','external/COMPLETE'):
 p=B/name
 if p.exists():print(name,p.read_text())
import shutil
print('free GiB',shutil.disk_usage(B).free/1024**3)

p=B/'DIRECTED_PLAN.json'
if p.exists():
 P=json.loads(p.read_text());done=[e for e in P['entries'] if (B/'directed'/e['id']/'audit/COMPLETE').exists()]
 print('audited entries',len(done),'of',len(P['entries']),'legal cases/arm',sum(e['accepted_cases'] for e in done),'of',sum(e['accepted_cases'] for e in P['entries']))
