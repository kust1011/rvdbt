#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New comparison semantic mutations from retained packets, zero guest reruns."""
import argparse,collections,json
from pathlib import Path
import vadd as v
import compare151_next as m

def run(root,out):
    rows=json.loads((root/'manifest.json').read_text())['cases'];units=collections.defaultdict(list);cache={};records=[];witnesses=[]
    out.mkdir(parents=True,exist_ok=False)
    for c in rows:units[c['unit']].append(c)
    def packet(c,arm):
        p=root/'runs'/c['unit']/arm/'packets.bin'
        if p not in cache:cache[p]=v.storage.verify(p)
        offset=units[c['unit']].index(c)*v.packet_size(c)
        return cache[p][offset:offset+v.packet_size(c)],p,offset
    def reject(c,kind,bit,reg=None,replacement=None,reference=False):
        raw,p,offset=packet(c,'B');ref,_,_=packet(c,'Reference');m.check_isa(c,raw);m.check_reference(c,raw,ref)
        b=c['vlen']//8;bad=bytearray(raw);pos=96+32*b+(c['vd'] if reg is None else reg)*b+bit//8
        old=bad[pos]>>(bit%8)&1
        value=1-old if replacement is None else replacement
        assert value!=old,(kind,c['id'],bit)
        bad[pos]=(bad[pos]&~(1<<(bit%8)))|(value<<(bit%8))
        target=out/f'{len(records):04d}.bin';v.storage.write(target,bad)
        for mode in (['ISA','reference'] if reference else ['ISA']):
            try:
                if mode=='ISA':m.check_isa(c,bad)
                else:m.check_reference(c,bad,ref)
            except ValueError as ex:records.append(dict(case=c['id'],control=kind,bit=bit,mode=mode,rejected=True,error=str(ex),source=str(p),offset=offset,corrupt=target.name,sha256=v.sha(target)))
            else:raise ValueError('accepted '+kind+' '+mode)
    for op,forms in m.FORMS.items():
      for form in forms:
        subset=[c for c in rows if c['mnemonic']==op and c['form']==form and (c['vlen'],c['sew'],c['lmul'])==(128,64,'m4')]
        def case(tag):return next(c for c in subset if c['tag']==tag)
        reject(case('start-partial-active-tu'),'prestart',0)
        reject(case('start-zero-vl'),'no-body',0)
        reject(case('dest-v0-masked'),'masked-v0-inactive-preserve',1)
        reject(case('length1'),'non-destination',0,reg=31)
        c=case('length1');raw,_,_=packet(c,'B');before=v.decode(c,raw)[2];vd=c['vd']*16
        bit=next(i for i in range(c['vlmax'],c['vlen']) if before[vd+i//8]>>(i%8)&1)
        reject(c,'tail-illegal-zero',bit,replacement=0)
        # Narrowing overlap overrides vma: actual old/one allowed, zero if old
        # was one is forbidden. No deterministic reference equality for inactive.
        c=case('dest-source2');raw,_,_=packet(c,'B');before=v.decode(c,raw)[2];after=v.decode(c,raw)[3];vd=c['vd']*16
        bits=[i for i in range(c['vl']) if not(before[i//8]>>(i%8)&1) and before[vd+i//8]>>(i%8)&1 and after[vd+i//8]>>(i%8)&1]
        if bits:reject(c,'overlap-inactive-illegal-zero',bits[0],replacement=0)
        found=False
        for c in subset:
          if c['vstart'] or c['mask']!='none' or not c['vl']:continue
          raw,_,_=packet(c,'B');before=v.decode(c,raw)[2]
          for i in range(c['vl']):
            a=int.from_bytes(before[c['vs2']*16+i*8:c['vs2']*16+(i+1)*8],'little')
            if form=='vv':
              if op not in ('vmslt','vmsltu','vmsle','vmsleu'):continue
              z=int.from_bytes(before[c['vs1']*16+i*8:c['vs1']*16+(i+1)*8],'little')
              wrong=m.element(dict(c,mnemonic={'vmslt':'vmsltu','vmsltu':'vmslt','vmsle':'vmsleu','vmsleu':'vmsle'}[op]),a,z)
              kind='signed-unsigned-order-swap'
            else:
              z=(c['operand']&0xffffffff) if form=='vx' else (c['operand']&31)
              wrong=m.element(c,a,z);kind='scalar-zero-extension' if form=='vx' else 'simm5-zero-extension'
            if wrong!=m.lane(c,before,i):
              reject(c,kind,i,replacement=wrong,reference=True);witnesses.append(dict(form=op+'.'+form,kind=kind,case=c['id'],bit=i));found=True;break
          if found:break
    v.save(out/'summary.json',dict(controls=len(records),rejected=len(records),records=records,signedness_witnesses=witnesses,guest_executions=0,framework_controls='unchanged; not repeated'))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('out',type=Path);a=p.parse_args();run(a.root,a.out)
