#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Carry-specific corruption controls from actual fixed-reference packets."""
import argparse,collections,json
from pathlib import Path
import vadd as v
import carry149_next as c

def run(root,out):
    out.mkdir(parents=True,exist_ok=False)
    rows=json.loads((root/'manifest.json').read_text())['cases'];units=collections.defaultdict(list);records=[];cache={}
    for row in rows:units[row['unit']].append(row)
    def packet(row,arm):
        path=root/'runs'/row['unit']/arm/'packets.bin'
        if path not in cache:cache[path]=v.storage.verify(path)
        size=v.packet_size(row);offset=units[row['unit']].index(row)*size
        return cache[path][offset:offset+size],path,offset
    def reject(row,name,lane=0,restore=False,reference_only=False):
        raw,path,offset=packet(row,'B');ref,_,_=packet(row,'Reference');v.check(row,raw,reference=ref)
        bad=bytearray(raw);b=row['vlen']//8;post=96+32*b;vd=row['vd']*b
        pos=post+vd+(lane//8 if c.mask_result(row) else lane*(row['sew']//8))
        bit=1<<(lane%8) if c.mask_result(row) else 1
        if restore:
            before=v.decode(row,raw)[2]
            if c.mask_result(row):bad[pos]=(bad[pos]&~bit)|(before[vd+lane//8]&bit)
            else:bad[pos:pos+row['sew']//8]=before[vd+lane*(row['sew']//8):vd+(lane+1)*(row['sew']//8)]
            if bad==raw:raise ValueError('non-distinguishing restoration '+row['id'])
        else:bad[pos]^=bit
        dest=out/f'{len(records):04d}.bin';v.storage.write(dest,bad)
        try:
            if reference_only:v.check_reference(row,bad,ref)
            else:v.check_isa(row,bad)
        except ValueError as ex:records.append(dict(case=row['id'],control=name,mode='reference' if reference_only else 'ISA',lane=lane,rejected=True,error=str(ex),source=str(path),offset=offset,corrupt=dest.name,sha256=v.sha(dest)))
        else:raise ValueError('accepted '+name+' '+row['id'])
    for op,forms in c.FORMS.items():
      for form in forms:
        subset=[r for r in rows if r['mnemonic']==op and r['form']==form and (r['vlen'],r['sew'],r['lmul'])==(128,64,'m4')]
        tag='witness-toggle-carry-cin1' if op in ('vadc','vmadc') else 'witness-toggle-borrow-cin1'
        witness=next(r for r in subset if r['tag']==tag)
        for mode in [False,True]:reject(witness,'wrong-carry-or-borrow' if c.with_input(witness) else 'spurious-v0-input',reference_only=mode)
        # False carry bits still execute every body lane. Select a differing old
        # destination bit/value, then simulate treating carry input as a mask.
        zero=next(r for r in subset if r['tag']=='witness-toggle-carry-cin0')
        raw,_,_=packet(zero,'B');before,after=v.decode(zero,raw)[2:];b=16;vd=zero['vd']*b;e=8
        differing=[i for i in range(zero['vl']) if ((before[vd+i//8]^after[vd+i//8])>>(i%8)&1) if c.mask_result(zero)] if c.mask_result(zero) else [i for i in range(zero['vl']) if before[vd+i*e:vd+(i+1)*e]!=after[vd+i*e:vd+(i+1)*e]]
        reject(zero,'carry-input-treated-as-execution-mask',lane=differing[0],restore=True)
        start=next(r for r in subset if r['tag']=='start1')
        reject(start,'prestart-destination-damaged',lane=0)
        empty=next(r for r in subset if r['tag']=='start-zero-vl')
        reject(empty,'no-body-destination-damaged',lane=0)
        if form.endswith('m'):
            for bit in [7,8,63,64,511,512]:
                row=next(r for r in rows if r['mnemonic']==op and r['form']==form and (r['vlen'],r['sew'],r['lmul'])==(1024,8,'m8') and r['tag']=='carry-bit'+str(bit))
                for mode in [False,True]:reject(row,'packed-carry-boundary'+str(bit),lane=bit,reference_only=mode)
        if c.mask_result(witness):
            row=next(r for r in subset if r['tag']=='dest-v0')
            reject(row,'v0-input-output-overlap')
    v.save(out/'summary.json',dict(controls=len(records),rejected=len(records),records=records,framework_controls='unchanged; not repeated',guest_executions=0))
    print(len(records),'carry controls rejected')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('out',type=Path);a=p.parse_args();run(a.root,a.out)
