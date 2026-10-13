#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inactive narrowing overlap must retain old one or choose one, never zero."""
import argparse,collections,json
from pathlib import Path
import vadd as v
import compare151_next as m

def run(root,out):
    rows=json.loads((root/'manifest.json').read_text())['cases'];units=collections.defaultdict(list);cache={};records=[]
    out.mkdir(parents=True,exist_ok=False)
    for c in rows:units[c['unit']].append(c)
    for op,forms in m.FORMS.items():
      for form in forms:
        c=next(c for c in rows if c['mnemonic']==op and c['form']==form and (c['vlen'],c['sew'],c['lmul'])==(1024,8,'m8') and c['tag']=='dest-source2')
        p=root/'runs'/c['unit']/'B'/'packets.bin'
        if p not in cache:cache[p]=v.storage.verify(p)
        offset=units[c['unit']].index(c)*v.packet_size(c);raw=cache[p][offset:offset+v.packet_size(c)];m.check_isa(c,raw)
        _,_,before,after=v.decode(c,raw);b=c['vlen']//8;vd=c['vd']*b
        assert m.overlap(c) and not c['ma']
        bit=next(i for i in range(c['vl']) if not(before[i//8]>>(i%8)&1) and before[vd+i//8]>>(i%8)&1)
        assert after[vd+bit//8]>>(bit%8)&1
        bad=bytearray(raw);bad[96+32*b+vd+bit//8]&=~(1<<(bit%8))
        target=out/f'{len(records):04d}.bin';v.storage.write(target,bad)
        try:m.check_isa(c,bad)
        except ValueError as ex:records.append(dict(case=c['id'],bit=bit,rejected=True,error=str(ex),source=str(p),offset=offset,corrupt=target.name,sha256=v.sha(target)))
        else:raise ValueError('accepted illegal overlap zero')
    v.save(out/'summary.json',dict(controls=len(records),rejected=len(records),records=records,guest_executions=0))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('out',type=Path);a=p.parse_args();run(a.root,a.out)
