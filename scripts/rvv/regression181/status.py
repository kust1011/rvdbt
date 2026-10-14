"""Inspect declared stages and checked summaries without scanning old raw forests."""
import json,os,shutil
from pathlib import Path
B=Path(os.environ.get('RVV_TASK181_ROOT','/home/vick/rvv-task181'))
P=json.load(open(B/'DIRECTED_PLAN.json'))
done=[e for e in P['entries'] if (B/'directed'/e['id']/'audit/COMPLETE').exists()]
print('audited entries',len(done),'of',len(P['entries']),'accepted cases/arm',sum(e['accepted_cases'] for e in done),'of',sum(e['accepted_cases'] for e in P['entries']))
log=B/('directed-resume.log' if (B/'directed-resume.log').exists() else 'directed.log')
if log.exists():
 lines=log.read_text().splitlines();print('directed','; '.join(lines[-3:]))
 starts=[s.split() for s in lines if s.startswith('START ')]
 if starts:
  s=starts[-1];p=B/'directed'/s[1]/(s[-1]+'.log')
  if p.exists():print('active','; '.join(p.read_text().splitlines()[-2:]))
external_done=(B/'external/audit/COMPLETE').exists()
if external_done:
 ext=json.load(open(B/'external/audit/SUMMARY.json'));print('external independently audited',ext['exact_joins'],'PASS')
for name in (() if external_done else ('external.log','external-audit.log'))+('post.log','DIRECTED_STOPPED.json','STOP_NEW_GUESTS.json','FOCUSED_STOPPED.json','EXTERNAL_AUDIT_STOPPED.json','FINAL_COMPLETE'):
 p=B/name
 if p.exists():print(name,'; '.join(p.read_text().splitlines()[-2:]))
print('free GiB',round(shutil.disk_usage(B).free/1024**3,3))
