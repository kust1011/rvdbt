#!/usr/bin/env python3
"""Finish effective controls and compact retention receipts as each full closes."""
import collections,gzip,json,os,subprocess,time,traceback
from pathlib import Path
R=Path('/home/vick/rvv-directed-task161');os.environ['PYTHONDONTWRITEBYTECODE']='1'
def gate():
 while True:
  active=[];reserved=False
  for p in Path('/proc').iterdir():
   if not p.name.isdecimal():continue
   try:a=(p/'cmdline').read_bytes().split(b'\0');stat=(p/'stat').read_text().rsplit(')',1)[1].split();exe=Path(a[0].decode(errors='replace')).name;s=Path(a[1].decode(errors='replace')).name if len(a)>1 else ''
   except (OSError,IndexError):continue
   if exe=='bash' and s=='run162.sh':reserved=True
   if stat[0]!='T' and exe in ('python3','python') and (('audit' in s and 'parallel' not in s) or s.startswith(('reject_','controls_','verify_controls'))):active.append(dict(pid=int(p.name),command=b' '.join(a).decode(errors='replace')))
  if not reserved and len(active)<4:return active
  time.sleep(5)
def call(args,out):
 with out.open('wb') as f:subprocess.run(['python3',*map(str,args)],stdout=f,stderr=subprocess.STDOUT,check=True)
try:
 for name,base in [('wmac-full2','/home/vick/rvv-directed-task156/wmac-full2'),('widen-full','/home/vick/rvv-directed-task154/widen-full'),('extend-full','/home/vick/rvv-directed-task156/extend-full'),('destchunk-full','/home/vick/rvv-directed-task156/destchunk-full'),('destchunk-pilot','/home/vick/rvv-directed-task156/destchunk-pilot')]:
  base=Path(base);out=R/name
  while not (out/'COMPLETE').exists():
   if (out/'ERROR.txt').exists() or (R/'ERROR').exists():raise RuntimeError('Original stages failed '+name)
   time.sleep(5)
  gate()
  if name.endswith('full') and not (out/'controls-geometry/summary.json').exists():call([R/'controls_geometry161.py',base/'corpus',base/'scripts',out/'controls-geometry'],out/'controls-geometry.log')
  if not (out/'CONTROL_EFFECTIVENESS.json').exists():
   peers=gate();(out/'EFFECTIVENESS_CAPACITY.json').write_text(json.dumps(peers,indent=2)+'\n');call([R/'verify_controls161.py',base,out],out/'effectiveness.log')
  for src in ('adapter-verification.json','guest-pins.json'):
   with gzip.open(out/'evidence'/(src+'.gz'),'wb') as f:f.write((out/'audit'/src).read_bytes())
  root=base/'corpus';counts=collections.Counter();allocated=0
  for p in root.rglob('*'):
   if p.is_file():
    counts[p.name if p.name in ('stdout.bin','stderr.bin','packets.bin','execution.json','tbmap') else p.suffix]+=1;allocated+=p.stat().st_blocks*512
  (out/'RETENTION.json').write_text(json.dumps(dict(raw='xbd:'+str(base),audit='xbd:'+str(out),file_counts=dict(counts),allocated_bytes=allocated,cleanup_performed=False,deleted_paths=[],source_manifest_packets_elf_oracle_retained=True),indent=2)+'\n')
 (R/'SUPPLEMENT_COMPLETE').write_text(time.ctime()+'\n')
except BaseException:
 (R/'SUPPLEMENT_ERROR.txt').write_text(traceback.format_exc());raise
