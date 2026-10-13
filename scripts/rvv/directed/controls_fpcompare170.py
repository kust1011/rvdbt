#!/usr/bin/env python3
"""Effective corruption/allowance controls on actual independently accepted packets."""
import collections,json,struct,sys
from pathlib import Path
import fpcompare170 as f
import vadd as v

def controls(root,out):
 out.mkdir(parents=True,exist_ok=False);manifest=json.loads((root/'manifest.json').read_text());rows=manifest['cases'];groups=collections.defaultdict(list)
 for c in rows:groups[c['unit']].append(c)
 counts=collections.Counter();selected=[];allowances=collections.Counter()
 def reject(c,raw,name):
  try:f.check_isa(c,raw)
  except ValueError:counts[name]+=1;return
  raise AssertionError(('ineffective control',c['id'],name))
 for unit,cs in groups.items():
  # Actual packets: each tag in every geometry; all four DUT arms and reference.
  size=v.packet_size(cs[0]);cached={arm:v.storage.verify(root/'runs'/unit/arm/'packets.bin') for arm in ('Reference','B','M1','M2','BOTH')}
  for index,c in enumerate(cs):
   if c['tag'] not in ('length0','length1','dest-source2','dest-source1','dest-v0-masked','mask-source-interior-16','semantic-zero-negzero','semantic-snan-one','semantic-qnan-one','semantic-snan-qnan','semantic-negative-snan-negative-qnan','suppress-off','suppress-prestart','suppress-tail','sticky-rm4','malformed-box-snan','policy11','start1'):continue
   selected.append(c['id'])
   for arm,packets in cached.items():
    raw=packets[index*size:(index+1)*size];f.check_isa(c,raw);_,_,before,_=v.decode(c,raw);b,e=c['vlen']//8,c['sew']//8;post=96+32*b;vd=c['vd']*b
    active=[i for i in range(c['vstart'],c['vl']) if f.active(c,before,i)]
    if active:
     i=active[0];bad=bytearray(raw);off=post+vd+(i//8 if f.comparison(c) else i*e);bad[off]^=(1<<(i%8)) if f.comparison(c) else 1;reject(c,bad,'active-result')
    bad=bytearray(raw)
    for offset in (52+7*4,52+9*4):struct.pack_into('<I',bad,offset,struct.unpack_from('<I',bad,offset)[0]^16)
    reject(c,bad,'NV-sticky-or-suppression')
    bad=bytearray(raw);bad[post+31*b]^=1
    if c['vd']!=31 and not (c['vd']<=31<c['vd']+(1 if f.comparison(c) else c['group_registers'])):reject(c,bad,'other-register')
    bad=bytearray(raw);bad[-1]^=1;reject(c,bad,'scalar-preservation-box')
    if c['vstart']:
     bad=bytearray(raw);bad[post+vd]^=1;reject(c,bad,'prestart-preservation')
    if c['vstart']<c['vl']:
     if f.comparison(c):
      i=c['vlen']-1
      if i>=c['vl']:
       for value in f.allowed_mask(c,before,i):
        good=bytearray(raw);off=post+vd+i//8;good[off]=(good[off]&~(1<<(i%8)))|(value<<(i%8));f.check_isa(c,good);f.check_reference(c,good,raw);allowances['mask-tail-independent-variant']+=1
     else:
      i=c['vl']
      if c['ta'] and i<c['group_registers']*b//e:
       good=bytearray(raw);off=post+vd+i*e;good[off:off+e]=b'\xff'*e;f.check_isa(c,good);f.check_reference(c,good,raw);allowances['vector-tail-agnostic']+=1
 v.save(out/'CONTROLS.json',dict(selected_actual_packets=len(selected)*5,selected_cases=len(selected),rejections=dict(counts),effective_rejections=sum(counts.values()),allowed_variants=dict(allowances),selected=selected,checker_sha256=v.sha(Path(f.__file__)),status='PASS'))
if __name__=='__main__':controls(Path(sys.argv[1]),Path(sys.argv[2]))
