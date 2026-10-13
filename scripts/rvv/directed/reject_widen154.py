#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual-packet controls for widening, also the distinct source-inspired MAC pilot."""
import argparse,collections,json
from pathlib import Path
import vadd as v
import widen154_next as w
import mac152_next as m

def run(root,out):
    manifest=json.loads((root/'manifest.json').read_text());rows=manifest['cases'];units=collections.defaultdict(list);cache={};records=[];allowed=[]
    mac=manifest['family']=='mac154qemu';checker=m if mac else w
    out.mkdir(parents=True,exist_ok=False)
    for c in rows:units[c['unit']].append(c)
    def packet(c,arm):
      p=root/'runs'/c['unit']/arm/'packets.bin'
      if p not in cache:cache[p]=v.storage.verify(p)
      size=v.packet_size(c);offset=units[c['unit']].index(c)*size
      return cache[p][offset:offset+size],p,offset
    def reject(c,label,mutate,modes=('ISA',)):
      raw,p,off=packet(c,'B');ref,_,_=packet(c,'Reference');checker.check_isa(c,raw);checker.check_reference(c,raw,ref)
      bad=bytearray(raw);mutate(bad,raw)
      if bad==raw:raise ValueError('ineffective mutation '+label)
      target=out/f'{len(records):04d}.bin';v.storage.write(target,bad)
      for mode in modes:
        try:checker.check_isa(c,bad) if mode=='ISA' else checker.check_reference(c,bad,ref)
        except ValueError as ex:records.append(dict(case=c['id'],control=label,mode=mode,rejected=True,error=str(ex),source=str(p),offset=off,corrupt=target.name,sha256=v.sha(target)))
        else:raise ValueError('accepted '+label+' '+mode)
    for op,forms in checker.FORMS.items():
      for form in forms:
        subset=[c for c in rows if c['mnemonic']==op and c['form']==form and (c['vlen'],c['sew'],c['lmul'])==(128,8,'m1')]
        c=next(c for c in subset if c['tag']=='qemu-even');b=c['vlen']//8;de=c['sew']//8 if mac else c['sew']//4
        pos=96+32*b+c['vd']*b
        for label,off,modes in [('active',pos,('ISA','reference')),('masked',pos+de,('ISA',)),('prestate',96,('ISA',)),('other-register',96+32*b+31*b,('ISA',)),('post-vcsr',52+24,('ISA',))]:reject(c,label,lambda bad,raw,off=off:bad.__setitem__(off,bad[off]^1),modes)
        odd=next(c for c in subset if c['tag']=='qemu-odd');oddpos=96+32*b+odd['vd']*b
        reject(odd,'odd-enabled',lambda bad,raw:bad.__setitem__(oddpos+de,bad[oddpos+de]^1),('ISA','reference'))
        reject(odd,'odd-disabled',lambda bad,raw:bad.__setitem__(oddpos,bad[oddpos]^1))
        q=next(c for c in subset if c['tag']=='qemu-partial');tail=96+32*b+q['vd']*b+q['vl']*de
        reject(q,'undisturbed-tail',lambda bad,raw:bad.__setitem__(tail,bad[tail]^1))
        if mac:continue
        # Toggle only the high result byte: rejects narrow-result truncation.
        reject(c,'upper-result-byte',lambda bad,raw:bad.__setitem__(pos+de-1,bad[pos+de-1]^1),('ISA','reference'))
        for tag in ['dest-high-source2-mask','start-partial-active-tu','dest-wide-source']:
          qs=[q for q in subset if q['tag']==tag]
          if not qs:continue
          q=qs[0];raw,_,_=packet(q,'B');before=v.decode(q,raw)[2]
          i=next(i for i in range(q['vstart'],q['vl']) if q['mask']=='none' or before[i//8]>>(i%8)&1);off=96+32*b+q['vd']*b+i*de
          reject(q,tag+'-active',lambda bad,raw,off=off:bad.__setitem__(off,bad[off]^1),('ISA','reference'))
          if w.overlap_agnostic(q) and q['vl']>1 and q['mask']!='none':
            i=next(i for i in range(q['vstart'],q['vl']) if not(before[i//8]>>(i%8)&1));off=96+32*b+q['vd']*b+i*de;variant=bytearray(raw);variant[off:off+de]=b'\xff'*de;checker.check_isa(q,variant);allowed.append(dict(case=q['id'],control='overlap-inactive-ones',accepted=True))
        # Distinguish extension/operand order using another independently executed lane.
        raw,_,_=packet(c,'B');before=v.decode(c,raw)[2]
        for label,wrongop in [('wrong-signedness',{'vwaddu':'vwadd','vwadd':'vwaddu','vwsubu':'vwsub','vwsub':'vwsubu','vwmulu':'vwmul','vwmul':'vwmulu','vwmulsu':'vwmulu'}[op])]:
          candidates=[]
          for i in range(c['vl']):
            if not(before[i//8]>>(i%8)&1):continue
            wrong=w.lane(dict(c,mnemonic=wrongop),before,i)
            if wrong!=w.lane(c,before,i):candidates.append((i,wrong))
          if candidates:
            i,wrong=candidates[0];off=pos+i*de
            reject(c,label,lambda bad,raw,off=off,wrong=wrong:bad.__setitem__(slice(off,off+de),wrong),('ISA','reference'))
          else:raise ValueError('missing signedness witness '+op+'.'+form)
    v.save(out/'summary.json',dict(controls=len(records),rejected=len(records),allowed=len(allowed),allowed_records=allowed,records=records,guest_executions=0))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('out',type=Path);a=p.parse_args();run(a.root,a.out)
