#!/usr/bin/env python3
"""Bounded effective active-lane controls across every retained geometry/form."""
import collections,gzip,hashlib,importlib,json,sys,time
from pathlib import Path
root,scripts,out=map(Path,sys.argv[1:]);sys.path.insert(0,str(scripts));import vadd as v
family=json.loads((root/'manifest.json').read_text())['family'];w=importlib.import_module({'widen154':'widen154_next','wmac156':'wmac156','wmac156chunk':'wmac156','extend156':'extend156_next'}[family])
rows=json.loads((root/'manifest.json').read_text())['cases'];groups=collections.defaultdict(list);units=collections.defaultdict(list)
for c in rows:
 groups[(c['mnemonic'],c['form'],c['vlen'],c['sew'],c['lmul'])].append(c);units[c['unit']].append(c)
# Wait until fewer than four offline predicate processes are active.
while True:
 live=[]
 for p in Path('/proc').iterdir():
  if not p.name.isdecimal() or int(p.name)==__import__('os').getpid():continue
  try:a=(p/'cmdline').read_bytes().split(b'\0');cmd=b' '.join(a).decode(errors='replace')
  except OSError:continue
  if a and Path(a[0].decode(errors='replace')).name in ('python','python3') and len(a)>1 and (('audit' in Path(a[1].decode(errors='replace')).name and 'parallel' not in Path(a[1].decode(errors='replace')).name) or Path(a[1].decode(errors='replace')).name.startswith(('reject_','controls_'))):live.append(dict(pid=int(p.name),command=cmd))
 if len(live)<4:break
 time.sleep(10)
out.mkdir(exist_ok=False);(out/'CAPACITY.json').write_text(json.dumps(dict(other=live,ours=1,nice=10,affinity='none'),indent=2)+'\n')
cache={};records=[];selected=[]
def packet(c,arm):
 p=root/'runs'/c['unit']/arm/'packets.bin'
 if p not in cache:
  if len(cache)>=10:cache.clear()
  cache[p]=v.storage.verify(p)
 size=v.packet_size(c);offset=units[c['unit']].index(c)*size
 return cache[p][offset:offset+size]
for key,subset in sorted(groups.items()):
 c=next((q for q in subset if q['vstart']==0 and q['mask']=='none' and q['vl']>0),None)
 assert c is not None,key
 raw=packet(c,'B');ref=packet(c,'Reference');w.validate(c);w.check_isa(c,raw);w.check_reference(c,raw,ref)
 b=c['vlen']//8;e=c['sew']//8 if family=='extend156' else c['sew']//4;pos=96+32*b+c['vd']*b
 selected.append(dict(case=c['id'],geometry=key,raw_sha256=hashlib.sha256(raw).hexdigest(),reference_sha256=hashlib.sha256(ref).hexdigest()))
 for label,off,modes in [('active-low',pos,('ISA','reference')),('active-high',pos+e-1,('ISA','reference')),('prestate',96,('ISA',)),('post-vstart',64,('ISA',))]:
  bad=bytearray(raw);bad[off]^=1;assert bad!=raw
  for mode in modes:
   try:w.check_isa(c,bad) if mode=='ISA' else w.check_reference(c,bad,ref)
   except ValueError as ex:records.append(dict(case=c['id'],control=label,mode=mode,effective=True,rejected=True,error=str(ex),offset=off,before=raw[off],after=bad[off],mutation_sha256=hashlib.sha256(bad).hexdigest()))
   else:raise ValueError('accepted '+str(key)+' '+label+' '+mode)
with gzip.open(out/'records.json.gz','wt') as f:json.dump(records,f,separators=(',',':'))
(out/'selected.json').write_text(json.dumps(selected,indent=2)+'\n');(out/'summary.json').write_text(json.dumps(dict(geometries_forms=len(groups),selected_packets=len(selected),controls=len(records),rejected=len(records),effective=len(records),allowed=0,guest_executions=0,widths=sorted({c['vlen'] for c in rows})),indent=2)+'\n')
