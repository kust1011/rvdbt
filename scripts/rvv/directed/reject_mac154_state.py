#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Supplemental destructive-operand/state mutations of retained pilot packets."""
import argparse,collections,json
from pathlib import Path
import vadd as v
import mac152_next as m

def run(root,out):
    rows=json.loads((root/'manifest.json').read_text())['cases'];units=collections.defaultdict(list);cache={};records=[]
    out.mkdir(parents=True,exist_ok=False)
    for c in rows:units[c['unit']].append(c)
    def packet(c):
      p=root/'runs'/c['unit']/'B/packets.bin'
      if p not in cache:cache[p]=v.storage.verify(p)
      size=v.packet_size(c);offset=units[c['unit']].index(c)*size
      return cache[p][offset:offset+size],p,offset
    def reject(c,label,mutator):
      raw,p,off=packet(c);m.check_isa(c,raw);bad=bytearray(raw);mutator(bad,raw)
      if bad==raw:raise ValueError('ineffective mutation '+label)
      target=out/f'{len(records):04d}.bin';v.storage.write(target,bad)
      try:m.check_isa(c,bad)
      except ValueError as ex:records.append(dict(case=c['id'],control=label,rejected=True,error=str(ex),source=str(p),offset=off,corrupt=target.name,sha256=v.sha(target)))
      else:raise ValueError('accepted '+label)
    for op,forms in m.FORMS.items():
      for form in forms:
        subset=[c for c in rows if c['mnemonic']==op and c['form']==form and (c['vlen'],c['sew'],c['lmul'])==(128,64,'m4')]
        def case(tag):return next(c for c in subset if c['tag']==tag)
        c=case('witness-distinct');b=c['vlen']//8;e=c['sew']//8;dst=96+32*b+c['vd']*b
        for j in range(11):
          for phase,base in [('pre',8),('post',52)]:reject(c,phase+'-csr-scalar-'+str(j),lambda bad,raw,pos=base+4*j:bad.__setitem__(pos,bad[pos]^1))
        reject(c,'prestate',lambda bad,raw:bad.__setitem__(96+8*b,bad[96+8*b]^1))
        reject(c,'other-register',lambda bad,raw:bad.__setitem__(96+32*b+31*b,bad[96+32*b+31*b]^1))
        def wrong_role(bad,raw):
          before=v.decode(c,raw)[2];a=int.from_bytes(before[c['vs2']*b:c['vs2']*b+e],'little');d=int.from_bytes(before[c['vd']*b:c['vd']*b+e],'little');z=int.from_bytes(before[c['vs1']*b:c['vs1']*b+e],'little') if form=='vv' else c['operand']
          wrong={'vmacc':z*d+a,'vnmsac':a-z*d,'vmadd':z*a+d,'vnmsub':d-z*a}[op]%(1<<c['sew']);bad[dst:dst+e]=wrong.to_bytes(e,'little')
        reject(c,'wrong-destructive-role',wrong_role)
        def erased_old(bad,raw):
          before=bytearray(v.decode(c,raw)[2]);before[c['vd']*b:c['vd']*b+e]=bytes(e);bad[dst:dst+e]=m.lane(c,before,0)
        reject(c,'old-destination-erased',erased_old)
        for tag,lane in [('length1',1),('mask-alternating',1),('start-partial-active-tu',0),('start-zero-vl',0),('start-equal-partial',0),('start-above-partial',0)]:
          q=case(tag);pos=96+32*b+q['vd']*b+lane*e
          reject(q,tag+'-preservation',lambda bad,raw,pos=pos:bad.__setitem__(pos,bad[pos]^1))
        if form=='vx':
          q=case('operand2147483648');pos=96+32*b+q['vd']*b
          def wrong_extension(bad,raw):
            before=v.decode(q,raw)[2];a=int.from_bytes(before[q['vs2']*b:q['vs2']*b+e],'little');d=int.from_bytes(before[q['vd']*b:q['vd']*b+e],'little');bad[pos:pos+e]=m.element(q,a,0x80000000,d)
          reject(q,'RV32-zero-extension-instead-of-sign-extension',wrong_extension)
    v.save(out/'summary.json',dict(controls=len(records),rejected=len(records),records=records,guest_executions=0))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('out',type=Path);a=p.parse_args();run(a.root,a.out)
