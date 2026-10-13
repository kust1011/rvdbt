#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New-semantic controls, synthetic before guests and retained packets after pilot."""
import argparse,collections,json,struct
from pathlib import Path
import vadd as v
import wmac156 as w

def synthetic(c):
    b=c['vlen']//8;de=c['sew']//4;before=w.initial(c);after=bytearray(before)
    for i in range(c['vstart'],c['vl']):
      if c['mask']=='none' or before[i//8]>>(i%8)&1:after[c['vd']*b+i*de:c['vd']*b+(i+1)*de]=w.lane(c,before,i)
    x=c['operand']&0xffffffff
    return struct.pack('<2I',0x145add,c['ordinal'])+struct.pack('<11I',*v.csr_expected(c),x)+struct.pack('<11I',*v.csr_expected(c,True),x)+before+after

def run(rows,packet,out):
    records=[];allowed=[]
    out.mkdir(parents=True,exist_ok=False)
    def reject(c,label,changes,modes=('ISA',)):
      raw=packet(c,'B');ref=packet(c,'Reference');w.check_isa(c,raw);w.check_reference(c,raw,ref)
      bad=bytearray(raw)
      for off,data in changes:bad[off:off+len(data)]=data
      if bad==raw:raise ValueError('ineffective mutation '+label)
      target=out/f'{len(records):04d}.bin';v.storage.write(target,bad)
      for mode in modes:
        try:w.check_isa(c,bad) if mode=='ISA' else w.check_reference(c,bad,ref)
        except ValueError as ex:records.append(dict(case=c['id'],control=label,mode=mode,rejected=True,error=str(ex),corrupt=target.name))
        else:raise ValueError('accepted '+label+' '+mode)
    for op,forms in w.FORMS.items():
      for form in forms:
        subset=[c for c in rows if c['mnemonic']==op and c['form']==form and (c['vlen'],c['sew'],c['lmul'])==(128,8,'m1')]
        c=next(c for c in subset if c['tag']=='qemu-even');b=c['vlen']//8;de=c['sew']//4;pos=96+32*b+c['vd']*b
        def flip(q,label,off,modes=('ISA',)):
          raw=packet(q,'B');reject(q,label,[(off,bytes([raw[off]^1]))],modes)
        for label,off,modes in [('active',pos,('ISA','reference')),('masked',pos+de,('ISA',)),('upper-result',pos+de-1,('ISA','reference')),('prestate',96,('ISA',)),('other-register',96+32*b+31*b,('ISA',))]:flip(c,label,off,modes)
        for stage,base in [('pre',8),('post',52)]:
          for j,key in enumerate(v.CSRS+['s0']):flip(c,stage+'-'+key,base+4*j)
        for tag,index in [('qemu-partial',lambda q:q['vl']),('qemu-odd',lambda q:0),('start-partial-active-tu',lambda q:0),('start-zero-vl-maxcsr',lambda q:0)]:
          q=next(c for c in subset if c['tag']==tag);flip(q,tag+'-preserved',96+32*b+q['vd']*b+index(q)*de)
        # Every form must reject a wrong operand-sign interpretation.
        wrongop={'vwmaccu':'vwmacc','vwmacc':'vwmaccu','vwmaccsu':'vwmaccus','vwmaccus':'vwmaccsu'}[op]
        witnesses=[q for q in subset if q['tag'].startswith('witness-')]
        for label,wrong in [
          ('wrong-signedness',lambda q,a,z,d:w.element(dict(q,mnemonic=wrongop),a,z,d)),
          ('erased-wide-addend',lambda q,a,z,d:w.element(q,a,z,0)),
          ('narrow-addend',lambda q,a,z,d:w.element(q,a,z,d&((1<<q['sew'])-1))),
          ('narrow-product',lambda q,a,z,d:((d+(int.from_bytes(w.element(q,a,z,0),'little')&((1<<q['sew'])-1)))%(1<<(2*q['sew']))).to_bytes(q['sew']//4,'little')),
          ('old-destination-multiplicand',lambda q,a,z,d:w.element(q,d,z,a)),
        ]:
          found=False
          for q in witnesses:
            raw=packet(q,'B');before=v.decode(q,raw)[2];e=q['sew']//8;qb=q['vlen']//8
            a=int.from_bytes(before[q['vs2']*qb:q['vs2']*qb+e],'little');z=int.from_bytes(before[q['vs1']*qb:q['vs1']*qb+e],'little') if form=='vv' else q['operand']&0xffffffff;d=int.from_bytes(before[q['vd']*qb:q['vd']*qb+2*e],'little')
            badvalue=wrong(q,a,z,d)
            if badvalue!=w.lane(q,before,0):reject(q,label,[(96+32*qb+q['vd']*qb,badvalue)],('ISA','reference'));found=True;break
          if not found:raise ValueError('missing witness '+op+'.'+form+' '+label)
        # RV32 scalar sign/zero extension becomes visible in a 64-bit product.
        if form=='vx':
          q=next(q for q in rows if q['mnemonic']==op and q['form']=='vx' and q['sew']==32 and q['vlen']==128 and q['tag']=='operand2147483648' and q['lmul']=='m4')
          raw=packet(q,'B');before=v.decode(q,raw)[2];qb=16;e=4;d=int.from_bytes(before[q['vd']*qb:q['vd']*qb+8],'little');a=int.from_bytes(before[q['vs2']*qb:q['vs2']*qb+4],'little');a=w.w.signed(a,32) if op in ('vwmacc','vwmaccus') else a
          z=0x80000000 if op in ('vwmacc','vwmaccsu') else -0x80000000
          reject(q,'RV32-wrong-scalar-extension',[(96+32*qb+q['vd']*qb,((d+a*z)%(1<<64)).to_bytes(8,'little'))],('ISA','reference'))
        if form=='vv':
          q=next(c for c in subset if c['tag']=='same-sources');flip(q,'legal-narrow-source-alias-active',96+32*b+q['vd']*b,('ISA','reference'))
        q=next(c for c in subset if c['tag']=='policy11');raw=packet(q,'B');off=96+32*b+q['vd']*b
        variant=bytearray(raw);variant[off+de:off+2*de]=b'\xff'*de;w.check_isa(q,variant);allowed.append(dict(case=q['id'],accepted=True,control='policy-inactive-all-ones'))
        flip(q,'policy-inactive-invalid',off+de)
    v.save(out/'summary.json',dict(controls=len(records),rejected=len(records),allowed=len(allowed),records=records,allowed_records=allowed,guest_executions=0))
    return dict(controls=len(records),rejected=len(records),allowed=len(allowed))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('out',type=Path);a=p.parse_args();manifest=json.loads((a.root/'manifest.json').read_text());rows=manifest['cases'];units=collections.defaultdict(list);cache={}
    for c in rows:units[c['unit']].append(c)
    def packet(c,arm):
      path=a.root/'runs'/c['unit']/arm/'packets.bin'
      if path not in cache:cache[path]=v.storage.verify(path)
      size=v.packet_size(c);offset=units[c['unit']].index(c)*size
      return cache[path][offset:offset+size]
    print(run(rows,packet,a.out))
