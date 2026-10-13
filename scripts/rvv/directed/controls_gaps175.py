#!/usr/bin/env python3
"""One effective mutation pass over actual packets; zero guest executions."""
import collections,json,struct,sys
from pathlib import Path
import gaps175 as f
import vadd as v

def controls(root,out):
 out.mkdir(parents=True,exist_ok=False);rows=json.loads((root/'manifest.json').read_text())['cases'];groups=collections.defaultdict(list)
 for c in rows:groups[c['unit']].append(c)
 counts=collections.Counter();allow=collections.Counter();selected=0
 def reject(c,raw,name):
  try:f.check_isa(c,raw)
  except ValueError:counts[name]+=1;return
  raise AssertionError((c['id'],name))
 for unit,cs in groups.items():
  size=v.packet_size(cs[0]);cached={a:v.storage.verify(root/'runs'/unit/a/'packets.bin') for a in ('Reference','B','M1','M2','BOTH')}
  for index,c in enumerate(cs):
   if not (c['tag'] in ('length0','length1','dest-source2','dest-source1','source-v0','policy11','start1','shift0','shift31','shift64','shift4294967295') or c['tag'].startswith(('bits-snan','malformed','sticky','supp-'))):continue
   for arm,packets in cached.items():
    selected+=1;raw=packets[index*size:(index+1)*size];f.check_isa(c,raw);_,_,before,_=v.decode(c,raw);b,e=c['vlen']//8,c['sew']//8;post=96+32*b;vd=c['vd']*b
    active=[i for i in range(c['vstart'],c['vl']) if f.active(c,before,i)]
    if active:
     for i in sorted({active[0],active[-1]}):
      bad=bytearray(raw);bad[post+vd+i*e]^=1;reject(c,bad,'active-result')
    bad=bytearray(raw)
    for off in (80,88):struct.pack_into('<I',bad,off,struct.unpack_from('<I',bad,off)[0]^16)
    reject(c,bad,'exact-sticky-flags')
    bad=bytearray(raw);bad[-1]^=1;reject(c,bad,'FP-scalar')
    bad=bytearray(raw);bad[92]^=1;reject(c,bad,'integer-scalar')
    bad=bytearray(raw);bad[post+(0 if c['vd'] else 31*b)]^=1;reject(c,bad,'other-register')
    if c['vstart'] or c['vl']==0:
     bad=bytearray(raw);bad[post+vd]^=1;reject(c,bad,'prestart-or-VL0')
    if c['vstart']<c['vl'] and c['vl']<c['group_registers']*b//e:
     off=post+vd+c['vl']*e
     if c['ta']:
      good=bytearray(raw);good[off:off+e]=b'\xff'*e
      if good!=raw:f.check_isa(c,good);f.check_reference(c,good,raw);allow['changed-tail-ones']+=1
     else:
      bad=bytearray(raw);bad[off]^=1;reject(c,bad,'undisturbed-tail')
 v.save(out/'CONTROLS.json',dict(status='PASS',selected_actual_packets=selected,effective_rejections=sum(counts.values()),rejections=dict(counts),changed_allowed=sum(allow.values()),allowances=dict(allow),checker_sha256=v.sha(Path(f.__file__)),guest_executions=0))
if __name__=='__main__':controls(Path(sys.argv[1]),Path(sys.argv[2]))
