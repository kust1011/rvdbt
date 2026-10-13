#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual-packet extension controls: sign roles, high bytes and preservation."""
import argparse,collections,json
from pathlib import Path
import extend156_next as w
import vadd as v

def run(root,out):
    rows=json.loads((root/'manifest.json').read_text())['cases'];units=collections.defaultdict(list);cache={};records=[];allowed=[]
    for c in rows:units[c['unit']].append(c)
    out.mkdir(parents=True,exist_ok=False)
    def packet(c,arm):
      p=root/'runs'/c['unit']/arm/'packets.bin'
      if p not in cache:cache[p]=v.storage.verify(p)
      size=v.packet_size(c);offset=units[c['unit']].index(c)*size
      return cache[p][offset:offset+size]
    def reject(c,label,off,data,modes=('ISA',)):
      raw=packet(c,'B');ref=packet(c,'Reference');w.check_isa(c,raw);w.check_reference(c,raw,ref);bad=bytearray(raw);bad[off:off+len(data)]=data
      if bad==raw:raise ValueError('ineffective mutation '+label)
      p=out/f'{len(records):04d}.bin';v.storage.write(p,bad)
      for mode in modes:
        try:w.check_isa(c,bad) if mode=='ISA' else w.check_reference(c,bad,ref)
        except ValueError as ex:records.append(dict(case=c['id'],control=label,mode=mode,rejected=True,error=str(ex),corrupt=p.name))
        else:raise ValueError('accepted '+label+' '+mode)
    for op,forms in w.FORMS.items():
      for form in forms:
        subset=[c for c in rows if c['mnemonic']==op and c['form']==form and (c['vlen'],c['sew'],c['lmul'])==(128,64,'m8')]
        c=next(c for c in subset if c['tag']=='length1');raw=packet(c,'B');before=v.decode(c,raw)[2];b=16;e=8;pos=96+32*b+c['vd']*b
        wrong=w.lane(dict(c,mnemonic='vsext' if op=='vzext' else 'vzext'),before,0);reject(c,'wrong-extension',pos,wrong,('ISA','reference'))
        reject(c,'upper-result',pos+e-1,bytes([raw[pos+e-1]^1]),('ISA','reference'))
        for tag,index in [('mask-alternating',1),('start-partial-active-tu',0),('start-zero-vl-maxcsr',0)]:
          q=next(q for q in subset if q['tag']==tag);raw=packet(q,'B');off=96+32*b+q['vd']*b+index*e;reject(q,tag+'-preserved',off,bytes([raw[off]^1]))
        raw=packet(c,'B')
        for base in [8,52]:
          for j in range(11):off=base+4*j;reject(c,'CSR-scalar-'+str(base)+'-'+str(j),off,bytes([raw[off]^1]))
        q=next(q for q in subset if q['tag']=='dest-high-source-mask');raw=packet(q,'B');off=96+32*b+q['vd']*b
        reject(q,'legal-overlap-active',off,bytes([raw[off]^1]),('ISA','reference'))
        variant=bytearray(raw);variant[off+e:off+2*e]=b'\xff'*e;w.check_isa(q,variant);allowed.append(dict(case=q['id'],control='overlap-mask-agnostic',accepted=True))
    v.save(out/'summary.json',dict(controls=len(records),rejected=len(records),allowed=len(allowed),records=records,allowed_records=allowed,guest_executions=0))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('out',type=Path);a=p.parse_args();run(a.root,a.out)
