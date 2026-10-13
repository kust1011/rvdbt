#!/usr/bin/env python3
"""Record actual shared-host guest/offline process samples without changing settings."""
import json,time
from pathlib import Path
R=Path('/home/vick/rvv-directed-task161');rows=[]
while not (R/'COMPLETE').exists() and not (R/'ERROR').exists():
 guests=[];offline=[];builders=[]
 for p in Path('/proc').iterdir():
  if not p.name.isdecimal():continue
  try:
   args=(p/'cmdline').read_bytes().split(b'\0');stat=(p/'stat').read_text().rsplit(')',1)[1].split();exe=Path(args[0].decode(errors='replace')).name;script=Path(args[1].decode(errors='replace')).name if len(args)>1 else ''
  except (OSError,IndexError):continue
  entry=dict(pid=int(p.name),state=stat[0],nice=int(stat[16]),command=b' '.join(args).decode(errors='replace'))
  if exe in ('elfrun','spike','sail_riscv_sim'):guests.append(entry)
  if exe in ('python3','python') and (('audit' in script and 'parallel' not in script) or script.startswith(('reject_','controls_'))):offline.append(entry)
  if exe.startswith(('clang','ld.lld')):builders.append(entry)
 rows.append(dict(time=time.time(),guests=guests,offline=offline,builders=builders))
 (R/'RESOURCE_SAMPLES.json').write_text(json.dumps(rows,indent=2)+'\n')
 active=lambda r,k:sum(x['state']!='T' for x in r[k])
 summary=dict(samples=len(rows),max_active_guests=max(active(r,'guests') for r in rows),max_active_offline=max(active(r,'offline') for r in rows),max_compiler_processes=max(active(r,'builders') for r in rows),guest_limit=16,offline_limit=4)
 (R/'RESOURCE_SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n')
 time.sleep(5)
