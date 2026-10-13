#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Supplementary new-family preserved-state and legal v0-data controls."""
import argparse,collections,json
from pathlib import Path
import vadd as v
import mergemove150_next as m

def run(root,out):
    rows=json.loads((root/'manifest.json').read_text())['cases'];units=collections.defaultdict(list);cache={};records=[]
    out.mkdir(parents=True,exist_ok=False)
    for c in rows:units[c['unit']].append(c)
    def packet(c,arm):
        p=root/'runs'/c['unit']/arm/'packets.bin'
        if p not in cache:cache[p]=v.storage.verify(p)
        size=v.packet_size(c);offset=units[c['unit']].index(c)*size
        return cache[p][offset:offset+size],p,offset
    def reject(c,name,pos,modes):
        raw,p,offset=packet(c,'B');ref,_,_=packet(c,'Reference');m.check_isa(c,raw);m.check_reference(c,raw,ref)
        bad=bytearray(raw);bad[pos]^=1;target=out/f'{len(records):04d}.bin';v.storage.write(target,bad)
        for mode in modes:
            try:
                if mode=='ISA':m.check_isa(c,bad)
                else:m.check_reference(c,bad,ref)
            except ValueError as ex:records.append(dict(case=c['id'],control=name,mode=mode,rejected=True,error=str(ex),source=str(p),offset=offset,corrupt=target.name,sha256=v.sha(target)))
            else:raise ValueError('accepted '+name+' '+mode)
    for op,forms in m.FORMS.items():
      for form in forms:
        subset=[c for c in rows if c['mnemonic']==op and c['form']==form and (c['vlen'],c['sew'],c['lmul'])==(128,64,'m4')]
        for tag,name in [('start-partial-active-tu','prestart'),('start-zero-vl','no-body'),('length1','undisturbed-tail')]:
            c=next(c for c in subset if c['tag']==tag);lane=1 if tag=='length1' else 0
            reject(c,name,96+512+c['vd']*16+lane*8,['ISA'])
        if op=='vmv':
            for tag in ['dest-v0']+(['source-v0','self-source-v0'] if form=='v.v' else []):
                c=next(c for c in subset if c['tag']==tag)
                reject(c,tag+'-active-data',96+512+c['vd']*16,['ISA','reference'])
    v.save(out/'summary.json',dict(controls=len(records),rejected=len(records),records=records,guest_executions=0,framework_controls='unchanged; not repeated'))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('out',type=Path);a=p.parse_args();run(a.root,a.out)
