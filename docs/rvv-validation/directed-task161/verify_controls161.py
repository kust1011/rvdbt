#!/usr/bin/env python3
"""Verify frozen negative controls and effective allowed variants from retained packets."""
import collections,hashlib,importlib,json,sys
from pathlib import Path
base,review=map(Path,sys.argv[1:]);sys.path.insert(0,str(base/'scripts'));import vadd as v
root=base/'corpus';m=json.loads((root/'manifest.json').read_text());family=m['family'];module=importlib.import_module({'widen154':'widen154_next','wmac156':'wmac156','wmac156chunk':'wmac156','extend156':'extend156_next'}[family]);ids={c['id']:c for c in m['cases']};units=collections.defaultdict(list);cache={}
for c in m['cases']:units[c['unit']].append(c)
def packet(c):
 p=root/'runs'/c['unit']/'B'/'packets.bin'
 if p not in cache:cache[p]=v.storage.verify(p)
 size=v.packet_size(c);off=units[c['unit']].index(c)*size
 return cache[p][off:off+size]
s=json.loads((review/'controls/summary.json').read_text());records=[]
for r in s['records']:
 c=ids[r['case']];raw=packet(c)
 if 'corrupt' not in r:continue
 bad=v.storage.verify(review/'controls'/r['corrupt']);assert bad!=raw
 records.append(dict(case=c['id'],control=r['control'],mode=r.get('mode','ISA'),effective=True,raw_sha256=hashlib.sha256(raw).hexdigest(),mutation_sha256=hashlib.sha256(bad).hexdigest()))
allowed=[]
for r in s.get('allowed_records',[]):
 c=ids[r['case']];raw=packet(c);b=c['vlen']//8;e=c['sew']//8 if family=='extend156' else c['sew']//4;off=96+32*b+c['vd']*b+e;variant=bytearray(raw);variant[off:off+e]=b'\xff'*e
 changed=variant!=raw
 # If the frozen candidate is already all-ones, use the independently allowed old bytes.
 if not changed:variant[off:off+e]=v.decode(c,raw)[2][c['vd']*b+e:c['vd']*b+2*e]
 replacement=False
 if variant==raw:
  before=v.decode(c,raw)[2];count=c.get('dest_registers',c['group_registers'])*b//e
  for i in range(c['vstart'],count):
   active=i<c['vl'] and (c['mask']=='none' or before[i//8]>>(i%8)&1)
   if active:continue
   off=96+32*b+c['vd']*b+i*e
   for value in (b'\xff'*e,before[c['vd']*b+i*e:c['vd']*b+(i+1)*e]):
    candidate=bytearray(raw);candidate[off:off+e]=value
    if candidate==raw:continue
    try:module.check_isa(c,candidate)
    except ValueError:continue
    variant=candidate;replacement=True;break
   if replacement:break
 assert variant!=raw;module.check_isa(c,variant)
 allowed.append(dict(case=c['id'],control=r['control'],frozen_candidate_effective=changed,replacement_selected=replacement,offset=off,effective=True,accepted=True,raw_sha256=hashlib.sha256(raw).hexdigest(),variant_sha256=hashlib.sha256(variant).hexdigest()))
(review/'CONTROL_EFFECTIVENESS.json').write_text(json.dumps(dict(negative_records_verified=len(records),negative_records_without_stored_mutations=sum('corrupt' not in r for r in s['records']),allowed=allowed,guest_executions=0),indent=2)+'\n')
