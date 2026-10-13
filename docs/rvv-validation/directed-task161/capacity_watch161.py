#!/usr/bin/env python3
"""Enforce the shared offline allowance for custom session3 auditor names too."""
import json,os,signal,time
from pathlib import Path
R=Path('/home/vick/rvv-directed-task161');driver=int((R/'DRIVER_PID').read_text());stopped=set();events=json.loads((R/'OFFLINE_COORDINATION.json').read_text()) if (R/'OFFLINE_COORDINATION.json').exists() else [];last=None
while not (R/'COMPLETE').exists() and not (R/'ERROR').exists():
 processes={}
 for p in Path('/proc').iterdir():
  if not p.name.isdecimal():continue
  try:
   args=(p/'cmdline').read_bytes().split(b'\0');status=(p/'stat').read_text().rsplit(')',1)[1].split();processes[int(p.name)]=(int(status[1]),status[0],args)
  except OSError:continue
 if driver not in processes:break
 descendants={driver}
 while True:
  new=descendants|{pid for pid,(parent,_,_) in processes.items() if parent in descendants}
  if new==descendants:break
  descendants=new
 auditors=[]
 for pid,(parent,state,args) in processes.items():
  if len(args)<2 or Path(args[0].decode(errors='replace')).name not in ('python3','python'):continue
  script=Path(args[1].decode(errors='replace')).name
  if ('audit' in script and 'parallel' not in script) or script.startswith(('reject_','controls_')):
   auditors.append(dict(pid=pid,state=state,script=script,own=pid in descendants))
 other=[r for r in auditors if not r['own'] and r['state']!='T'];own=[r for r in auditors if r['own']]
 session3_pipeline=[dict(pid=pid,command=b' '.join(args).decode(errors='replace')) for pid,(_,state,args) in processes.items() if pid not in descendants and state!='T' and args and Path(args[0].decode(errors='replace')).name=='bash' and any('run162.sh' in arg.decode(errors='replace') for arg in args[1:2])]
 block=len(other)>=4 or bool(session3_pipeline)
 targets={driver}|{r['pid'] for r in own} if block else set()
 for pid in targets-stopped:
  try:os.kill(pid,signal.SIGSTOP);stopped.add(pid)
  except ProcessLookupError:pass
 for pid in stopped-targets:
  try:os.kill(pid,signal.SIGCONT)
  except ProcessLookupError:pass
 stopped&=targets
 state=(tuple(r['pid'] for r in other),tuple(r['pid'] for r in own),tuple(r['pid'] for r in session3_pipeline),block)
 if state!=last:
  events.append(dict(time=time.time(),other=other,own=own,reserved_session3_pipeline=session3_pipeline,reserved_session3_workers=4 if session3_pipeline else 0,blocked=block,stopped=sorted(stopped)))
  (R/'OFFLINE_COORDINATION.json').write_text(json.dumps(events,indent=2)+'\n');last=state
 time.sleep(1)
for pid in stopped:
 try:os.kill(pid,signal.SIGCONT)
 except ProcessLookupError:pass
