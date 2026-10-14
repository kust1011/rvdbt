import json,tarfile,sys
from pathlib import Path
seen=set()
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz') as t:
 def add(p):
  p=Path(p)
  if p in seen:return
  seen.add(p)
  for q in [p,Path(str(p)+'.gz'),p.with_name(p.name+'.storage.json')]:
   if q.is_file():t.add(q,arcname=str(q).lstrip('/'),recursive=False)
 for suite in ['guard165','guard166','faults']:
  base=Path('/home/vick/rvv-task181/focused')/suite
  plan=json.loads((base/'audit/PLAN.json').read_text());add(base/'audit/PLAN.json');add(base/'audit/summary.json')
  add(Path(plan['original'])/'summary.json')
  for tool in plan['tools']:add(tool)
  for r in plan['records']:
   if r['status']=='PASS' or r['arm']=='Reference':continue
   key=r['case']['mnemonic']+'-'+r['kind'] if suite.startswith('guard') else r['case']['id']
   original=Path(plan['original'])/key
   for f in ['test.S','test.elf','build.json']:add(original/f)
   add(original/r['arm']/'command.json');add(base/'audit'/(key+'-RESULTS.json'))
   for f in ['command.json','execution.json','stdout','stderr','packets.bin']:add(base/'replay'/key/r['arm']/f)
