#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepared targeted merge/move controls; require actual fixed-reference packets.

No guests run here, and the utility has not earned rejection credit yet.
"""
import argparse,collections,json
from pathlib import Path
import vadd as v
import mergemove150_next as m

def run(root,out):
    rows=json.loads((root/'manifest.json').read_text())['cases'];units=collections.defaultdict(list);records=[];cache={}
    out.mkdir(parents=True,exist_ok=False)
    for c in rows:units[c['unit']].append(c)
    def packet(c,arm):
        path=root/'runs'/c['unit']/arm/'packets.bin'
        if path not in cache:cache[path]=v.storage.verify(path)
        size=v.packet_size(c);offset=units[c['unit']].index(c)*size
        return cache[path][offset:offset+size],path,offset
    def reject(c,name,lane,value):
        raw,path,offset=packet(c,'B');ref,_,_=packet(c,'Reference')
        m.check_isa(c,raw);m.check_reference(c,raw,ref)
        e=c['sew']//8;b=c['vlen']//8;pos=96+32*b+c['vd']*b+lane*e
        bad=bytearray(raw);bad[pos:pos+e]=value
        if bad==raw:raise ValueError('non-distinguishing control '+c['id']+' '+name)
        target=out/f'{len(records):04d}.bin';v.storage.write(target,bad)
        for mode in ['ISA','reference']:
            try:
                if mode=='ISA':m.check_isa(c,bad)
                else:m.check_reference(c,bad,ref)
            except ValueError as ex:records.append(dict(case=c['id'],control=name,mode=mode,lane=lane,rejected=True,error=str(ex),source=str(path),offset=offset,corrupt=target.name,sha256=v.sha(target)))
            else:raise ValueError('accepted '+name+' '+mode)
    for op,forms in m.FORMS.items():
      for form in forms:
        subset=[c for c in rows if c['mnemonic']==op and c['form']==form and (c['vlen'],c['sew'],c['lmul'])==(128,64,'m4')]
        c=next(c for c in subset if c['tag']=='mask-alternating');raw,_,_=packet(c,'B');before=v.decode(c,raw)[2];e=8;b=16;k=m.kind(c)
        if op=='vmerge':
            # Polarity reversal is distinguishable on both selection branches.
            for lane in [0,1]:
                other=int.from_bytes(before[c['vs1']*b+lane*e:c['vs1']*b+(lane+1)*e],'little') if k=='vv' else m.scalar(c) if k=='vx' else c['operand']
                wrong=(other&((1<<64)-1)).to_bytes(e,'little') if not (before[lane//8]>>(lane%8)&1) else before[c['vs2']*b+lane*e:c['vs2']*b+(lane+1)*e]
                reject(c,'reversed-selection-polarity',lane,wrong)
            old=before[c['vd']*b+e:c['vd']*b+2*e]
            reject(c,'selection-treated-as-execution-mask',1,old)
        else:
            # Nonzero output must not depend on selection v0 or dummy vs2.
            old=before[c['vd']*b+e:c['vd']*b+2*e]
            reject(c,'spurious-v0-execution-mask',1,old)
            wrong=before[:e]
            reject(c,'reading-encoded-vs2-instead-of-source',0,wrong)
        if k=='vx':
            c=next(c for c in subset if c['tag']=='operand2147483648')
            # Legacy selection pattern is all-on, so merge also writes scalar.
            reject(c,'scalar-zero-extension',0,(0x80000000).to_bytes(8,'little'))
        if k=='vi':
            c=next(c for c in subset if c['tag']=='operand-16')
            reject(c,'unsigned-five-bit-immediate',0,(16).to_bytes(8,'little'))
    v.save(out/'summary.json',dict(controls=len(records),rejected=len(records),records=records,guest_executions=0,framework_controls='unchanged; not repeated'))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('out',type=Path);a=p.parse_args();run(a.root,a.out)
