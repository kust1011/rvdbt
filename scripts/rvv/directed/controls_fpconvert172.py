#!/usr/bin/env python3
"""Pilot/full effective controls on actual packets, never synthetic guest credit."""
import collections,json,struct,sys
from pathlib import Path
import fpconvert172 as f
import vadd as v

def controls(root,out):
 out.mkdir(parents=True,exist_ok=False);rows=json.loads((root/'manifest.json').read_text())['cases'];groups=collections.defaultdict(list)
 for c in rows:groups[c['unit']].append(c)
 counts=collections.Counter();allowed=collections.Counter();selected=[];semantic=collections.Counter()
 def reject(c,raw,name):
  try:f.check_isa(c,raw)
  except ValueError:counts[name]+=1;return
  raise AssertionError(('ineffective control',c['id'],name))
 def flag_change(raw,flags):
  bad=bytearray(raw)
  for offset in (52+7*4,52+9*4):struct.pack_into('<I',bad,offset,(struct.unpack_from('<I',raw,offset)[0]&~31)|flags)
  return bad
 for unit,cs in groups.items():
  size=v.packet_size(cs[0]);cached={arm:v.storage.verify(root/'runs'/unit/arm/'packets.bin') for arm in ('Reference','B','M1','M2','BOTH')}
  for index,c in enumerate(cs):
   tag=c['tag'];pick=tag in ('length0','length1','policy11','legal-overlap','legal-overlap-masked','start1','suppress-off','suppress-masked','suppress-prestart','suppress-tail','suppress-zero','suppress-no-body','sticky-rm4') or tag.startswith(('sticky-clean-','semantic-snan-','semantic-qnan-','semantic-tie-even-','semantic-tie-odd-','semantic-tie-1over2-','semantic-tie--1over2-','semantic-minsub-half-','semantic-minnormal-edge-','semantic-overflow-tie-','semantic-unsigned-max-','semantic-signed-min-','semantic-signed-max-'))
   if not pick:continue
   selected.append(c['id'])
   for arm,packets in cached.items():
    raw=packets[index*size:(index+1)*size];f.check_isa(c,raw);_,post,before,after=v.decode(c,raw);b=c['vlen']//8;e=c['dst_eew']//8;data=96+32*b;start=c['vd']*b
    act=[i for i in range(c['vstart'],c['vl']) if f.active(c,before,i)]
    if act:
     i=act[0];off=data+start+i*e;bad=bytearray(raw);bad[off]^=1;reject(c,bad,'active-conversion-bits')
     alternatives=[];form=c['mnemonic'];sw,dw=c['src_eew'],c['dst_eew'];se=sw//8;aoff=c['vs2']*b+i*se;word=int.from_bytes(before[aoff:aoff+se],'little');value,flags=f.lane(c,before,i)
     # Coherent wrong semantic results AND flags, not just a one-bit mismatch.
     if '.rtz.' in form:alternatives.append(('RTZ-uses-frm',form.replace('.rtz.','.'),c['frm']))
     if '.rod.' in form:
      alternatives.extend([('ROD-as-RNE',form.replace('.rod.','.'),0),('ROD-as-RTZ',form.replace('.rod.','.'),1)])
     if '.xu.' in form:alternatives.append(('unsigned-as-signed',form.replace('.xu.','.x.'),c['frm']))
     elif '.x.' in form:alternatives.append(('signed-as-unsigned',form.replace('.x.','.xu.'),c['frm']))
     if '.rtz.' not in form and '.rod.' not in form:alternatives.append(('dynamic-as-RTZ',form,1))
     for name,other,rm in alternatives:
      wrong,wflags=f.element(other,sw,dw,word,rm)
      if (wrong,wflags)==(value,flags):continue
      # Semantic cases have exactly one active lane, hence union is exact here.
      if len(act)!=1:continue
      bad=flag_change(raw,c['fflags_initial']|wflags);bad[off:off+e]=wrong.to_bytes(e,'little')
      if bad==raw:continue
      reject(c,bad,name);semantic[name]+=1
    for bit,name in ((16,'NV'),(1,'NX'),(2,'UF'),(4,'OF'),(8,'DZ-forbidden')):reject(c,flag_change(raw,post[7]^bit),'flags-'+name+'-sticky-suppression')
    r=next(r for r in range(1,32) if not c['vd']<=r<c['vd']+c['dst_regs']);bad=bytearray(raw);bad[data+r*b]^=1;reject(c,bad,'unrelated-vector-preservation')
    bad=bytearray(raw);bad[-1]^=1;reject(c,bad,'scalar-FP-preservation')
    if c['vstart']:
     bad=bytearray(raw);bad[data+start]^=1;reject(c,bad,'prestart-preservation')
    # Changed legal outcomes receive credit only if bytes really changed.
    for i in range(c['dst_regs']*b//e):
     if f.active(c,before,i):continue
     off=data+start+i*e;old=before[start+i*e:start+(i+1)*e]
     agnostic=c['vstart']<c['vl'] and i>=c['vstart'] and ((i>=c['vl'] and c['ta']) or (i<c['vl'] and c['ma']))
     if agnostic:
      good=bytearray(raw);good[off:off+e]=old if after[start+i*e:start+(i+1)*e]==b'\xff'*e else b'\xff'*e
      if good!=raw:f.check_isa(c,good);f.check_reference(c,good,raw);allowed['tail-or-mask-agnostic-changed']+=1
     else:
      bad=bytearray(raw);bad[off]^=1;reject(c,bad,'inactive-undisturbed')
     break
 v.save(out/'CONTROLS.json',dict(status='PASS',selected_cases=len(selected),selected_actual_packets=len(selected)*5,effective_rejections=sum(counts.values()),rejections=dict(counts),semantic_rejections=dict(semantic),effective_changed_allowances=sum(allowed.values()),allowances=dict(allowed),checker_sha256=v.sha(Path(f.__file__)),selected=selected))
 print(len(selected)*5,sum(counts.values()),sum(allowed.values()),dict(semantic),flush=True)
if __name__=='__main__':controls(Path(sys.argv[1]),Path(sys.argv[2]))
