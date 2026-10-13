#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check compare-tail and different-EEW overlap allowed sets on pilot packets."""
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
       subset=[c for c in rows if c['mnemonic']==op and c['form']==form and (c['vlen'],c['sew'],c['lmul'])==(128,64,'m4')]
       for tag,kind in [('length1','tail-one-vta0'),('dest-source2','overlap-inactive-one-vma0')]:
        c=next(c for c in subset if c['tag']==tag);p=root/'runs'/c['unit']/'B'/'packets.bin'
        if p not in cache:cache[p]=v.storage.verify(p)
        offset=units[c['unit']].index(c)*v.packet_size(c);raw=cache[p][offset:offset+v.packet_size(c)]
        m.check_isa(c,raw);before=v.decode(c,raw)[2];after=v.decode(c,raw)[3];b=c['vlen']//8;vd=c['vd']*b
        candidates=range(c['vl'],c['vlen']) if tag=='length1' else [i for i in range(c['vl']) if not(before[i//8]>>(i%8)&1)]
        bit=next(i for i in candidates if not(after[vd+i//8]>>(i%8)&1))
        assert not c['ta'] if tag=='length1' else not c['ma'] and m.overlap(c)
        bad=bytearray(raw);bad[96+32*b+vd+bit//8]|=1<<(bit%8);m.check_isa(c,bad)
        target=out/f'{len(records):04d}.bin';v.storage.write(target,bad)
        records.append(dict(case=c['id'],control=kind,bit=bit,allowed=True,source=str(p),offset=offset,variant=target.name,sha256=v.sha(target)))
    v.save(out/'summary.json',dict(allowed=len(records),records=records,guest_executions=0))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('out',type=Path);a=p.parse_args();run(a.root,a.out)
