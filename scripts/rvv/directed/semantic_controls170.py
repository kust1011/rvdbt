#!/usr/bin/env python3
"""Semantic alternatives and EFFECTIVE allowed variants from actual Task170 packets.

Supplement to the frozen generic controls. Inputs/predicates stay independent.
"""
import collections,hashlib,json,struct,sys
from pathlib import Path
import fpcompare170 as f
import fp157 as fp
import vadd as v

def controls(root,out):
 out.mkdir(parents=True,exist_ok=False);cases=json.loads((root/'manifest.json').read_text())['cases'];units=collections.defaultdict(list)
 for c in cases:units[c['unit']].append(c)
 rejected=collections.Counter();allowed=collections.Counter();records=[]
 tags={'semantic-zero-negzero','semantic-negzero-zero','semantic-snan-one','semantic-qnan-one','semantic-snan-qnan','semantic-negative-snan-negative-qnan','semantic-minsub-zero','semantic-one-two','malformed-box-snan','policy11','suppress-off','suppress-prestart','suppress-tail','dest-v0-masked'}
 for unit,cs in units.items():
  size=v.packet_size(cs[0]);blobs={arm:v.storage.verify(root/'runs'/unit/arm/'packets.bin') for arm in ('Reference','B','M1','M2','BOTH')}
  for index,c in enumerate(cs):
   if c['tag'] not in tags:continue
   b,e=c['vlen']//8,c['sew']//8;vd=c['vd']*b;post=96+32*b;op=c['mnemonic'];k=fp.constants(c['sew'])
   for arm,blob in blobs.items():
    raw=blob[index*size:(index+1)*size];f.check_isa(c,raw);before=v.decode(c,raw)[2]
    def reject(bad,name):
     assert bad!=raw,(c['id'],name,'identity mutation')
     try:f.check_isa(c,bad)
     except ValueError:
      rejected[(op+'.'+c['form'],name)]+=1;records.append(dict(case=c['id'],arm=arm,control=name,outcome='REJECT',original=hashlib.sha256(raw).hexdigest(),mutation=hashlib.sha256(bad).hexdigest()));return
     raise AssertionError((c['id'],name,'accepted wrong semantics'))
    def result(value,name):
     bad=bytearray(raw)
     if f.comparison(c):bad[post+vd]=(bad[post+vd]&254)|(value&1)
     else:bad[post+vd:post+vd+e]=value.to_bytes(e,'little')
     reject(bad,name)
    if f.active(c,before,0):
     value,nv=f.lane(c,before,0)
     if op in ('vfmin','vfmax'):
      if c['tag'] in ('semantic-zero-negzero','semantic-negzero-zero'):result(value^k['negzero'],'wrong-zero-tie-sign')
      if c['tag']=='semantic-snan-one':result(k['canonical'],'obsolete-sNaN-canonical-result')
      if c['tag']=='semantic-qnan-one':result(k['canonical'],'wrong-qNaN-number-selection')
      if c['tag']=='semantic-one-two':result(k['two'] if value==k['one'] else k['one'],'min-max-swapped')
     elif op.startswith('vfsgnj'):
      result(value^k['negzero'],'wrong-sign-injection')
      if 'snan' in c['tag']:
       canonical=(value&k['negzero'])|k['canonical']
       result(canonical,'wrong-NaN-canonicalization')
     elif op=='vfclass':
      result(value^3,'wrong-class-bit-or-upper-bits')
     else:
      result(value^1,'wrong-ordered-or-unordered-bit')
     # Coherently toggle only NV; this separates value correctness from flags.
     if c['tag'] in ('semantic-snan-one','semantic-qnan-one','semantic-snan-qnan','malformed-box-snan'):
      bad=bytearray(raw)
      for offset in (80,88):struct.pack_into('<I',bad,offset,struct.unpack_from('<I',bad,offset)[0]^16)
      reject(bad,'exact-NaN-NV-or-boxing')
    if c['vstart']<c['vl'] and f.comparison(c):
     # Tail values are set-valued even under tu. Alter an actual packet, preserve
     # flags, and show independent reference equivalence despite changed bits.
     for kind,indices in [('mask-tail',range(c['vl'],c['vlen'])),('masked-body',range(c['vstart'],c['vl']))]:
      for i in indices:
       if kind=='masked-body' and f.active(c,before,i):continue
       off=post+vd+i//8;old=(raw[off]>>(i%8))&1;choices=f.allowed_mask(c,before,i)-{old}
       if not choices:continue
       for value in choices:
        good=bytearray(raw);good[off]=(good[off]&~(1<<(i%8)))|(value<<(i%8));assert good!=raw
        f.check_isa(c,good);f.check_reference(c,good,raw);allowed[(op+'.'+c['form'],kind)]+=1
        records.append(dict(case=c['id'],arm=arm,control=kind,outcome='ALLOW_CHANGED',original=hashlib.sha256(raw).hexdigest(),mutation=hashlib.sha256(good).hexdigest()))
       break
    elif c['tag']=='policy11' and c['vstart']<c['vl']:
     i=c['vl']
     if i<c['group_registers']*b//e:
      off=post+vd+i*e;old=before[vd+i*e:vd+(i+1)*e];actual=raw[off:off+e];replacement=old if actual==b'\xff'*e else b'\xff'*e
      if replacement!=actual:
       good=bytearray(raw);good[off:off+e]=replacement;f.check_isa(c,good);f.check_reference(c,good,raw);allowed[(op+'.'+c['form'],'vector-tail')]+=1
 v.save(out/'SEMANTIC_CONTROLS.json',dict(status='PASS',actual_mutations=len(records),effective_rejections=sum(rejected.values()),effective_allowed_variants=sum(allowed.values()),by_form_control=[dict(form=form,control=name,count=n) for (form,name),n in sorted(rejected.items())],allowed_by_form=[dict(form=form,control=name,count=n) for (form,name),n in sorted(allowed.items())],checker_sha256=v.sha(Path(f.__file__))))
 import gzip
 with gzip.open(out/'MUTATIONS.json.gz','wt') as stream:json.dump(records,stream,separators=(',',':'))
if __name__=='__main__':controls(Path(sys.argv[1]),Path(sys.argv[2]))
