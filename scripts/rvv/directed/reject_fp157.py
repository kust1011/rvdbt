#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded effective mutations of actual retained FP packets; no guest reruns."""
import json
from pathlib import Path
import sys
import fp157 as f
import vadd as v

def run(root,out):
    out.mkdir(parents=True,exist_ok=False)
    rows=json.loads((root/'manifest.json').read_text())['cases']
    by_unit={}
    for c in rows:by_unit.setdefault(c['unit'],[]).append(c)
    selected={}
    for c in rows:
        if c['tag'].startswith(('edge-','suppress-')) or c['tag'] in ('fp-snan','fp-halfway-even','fp-overflow','fp-divide-zero','fp-subnormal-round','fp-masked-exception','fp-prestart-exception','fp-no-body-flags','fp-malformed-box','length1','policy11'):
            selected.setdefault((c['mnemonic'],c['form'],c['sew'],c['tag']),c)
    records=[];accepted=[]
    for c in selected.values():
        b=c['vlen']//8;e=c['sew']//8;unit=c['unit'];cs=by_unit[unit];index=cs.index(c);size=v.packet_size(c)
        ref=v.storage.verify(root/'runs'/unit/'Reference'/'packets.bin')[index*size:(index+1)*size]
        raw=v.storage.verify(root/'runs'/unit/'B'/'packets.bin')[index*size:(index+1)*size]
        f.check_isa(c,raw);f.check_reference(c,raw,ref)
        def reject(label,offset,reference=False):
            bad=bytearray(raw);bad[offset]^=1
            try:(f.check_reference(c,bad,ref) if reference else f.check_isa(c,bad))
            except ValueError as ex:records.append(dict(case=c['id'],control=label,predicate='reference' if reference else 'ISA',rejected=True,error=str(ex)))
            else:raise ValueError('accepted effective FP mutation '+label)
        for base in (8,52):
            for j in range(11):reject('CSR-scalar-'+str(base)+'-'+str(j),base+4*j)
        reject('scalar-FP-pre',size-16);reject('scalar-FP-post',size-8)
        reject('other-register',96+32*b+31*b)
        reject('captured-source',96+c['vs2']*b)
        before=v.decode(c,raw)[2]
        active=[i for i in range(c['vstart'],c['vl']) if f.active(c,before,i)]
        if active:
            off=96+32*b+c['vd']*b+active[0]*e
            reject('active-result',off);reject('independent-active',off,True)
            reject('independent-fflags',52+7*4,True)
        inactive=[i for i in range(c['group_registers']*b//e) if not f.active(c,before,i)]
        if inactive:
            reject('inactive-preservation',96+32*b+c['vd']*b+inactive[0]*e)
        if c['tag']=='policy11' and c['vstart']<c['vl']:
            bad=bytearray(raw)
            for i in range(c['vstart'],c['group_registers']*b//e):
                if not f.active(c,before,i):
                    off=96+32*b+c['vd']*b+i*e;bad[off:off+e]=b'\xff'*e
            f.check_isa(c,bad);f.check_reference(c,bad,ref)
            accepted.append(dict(case=c['id'],control='allowed-agnostic-ones',accepted=True))
    v.save(out/'records.json',records);v.save(out/'allowed.json',accepted)
    v.save(out/'summary.json',dict(rejected=len(records),allowed=len(accepted),actual_packets=len(selected),guest_reruns=0))
    print(dict(rejected=len(records),allowed=len(accepted)))

if __name__=='__main__':run(Path(sys.argv[1]),Path(sys.argv[2]))
