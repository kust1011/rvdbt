#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Corrupt copies of actual packets; preserve formal receipts unchanged."""
import argparse, importlib.util, json
from pathlib import Path
spec=importlib.util.spec_from_file_location('vadd',Path(__file__).with_name('vadd.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
def run(root,out):
    out.mkdir(parents=True,exist_ok=False);cases=json.loads((root/'manifest.json').read_text())['cases'];records=[]
    def control(name,c,offset=None,missing=False,rc=0,timeout=False):
        unit=[x for x in cases if x['unit']==c['unit']];index=unit.index(c);size=v.packet_size(c)
        source=root/'runs'/c['unit']/'Reference'/'packets.bin';raw=bytearray(source.read_bytes()[index*size:(index+1)*size])
        v.check(c,raw) # each uncorrupted source must pass first
        if offset is not None:raw[offset]^=0x24
        if missing:raw=raw[:-1]
        dest=out/(name+'.bin');dest.write_bytes(raw)
        try:v.check(c,raw,rc,timeout)
        except ValueError as e:
            records.append(dict(control=name,case=c['id'],source=str(source),source_offset=index*size,mutated_offset=offset,returncode=rc,timeout=timeout,result='REJECTED',reason=str(e),control_sha256=v.sha(dest)))
        else:raise ValueError('checker accepted corruption '+name)
    c=next(x for x in cases if x['vlen']==128 and x['sew']==16 and x['lmul']=='m1' and x['form']=='vv' and x['tag']=='length1')
    b=c['vlen']//8;e=c['sew']//8;post=96+32*b
    control('active',c,post+c['vd']*b)
    control('tail-undisturbed',c,post+c['vd']*b+e)
    control('preserved-source',c,post+c['vs2']*b)
    control('pre-state',c,96+c['vs2']*b)
    for i,csr in enumerate(v.CSRS):control('post-'+csr,c,52+4*i)
    control('scalar-source',c,92)
    control('missing-output',c,missing=True)
    control('failed-execution',c,rc=1)
    control('host-signal',c,rc=-11)
    control('timeout',c,timeout=True)
    c=next(x for x in cases if x['vlen']==128 and x['sew']==16 and x['lmul']=='m1' and x['form']=='vv' and x['tag']=='mask-alternating')
    control('inactive-mask-undisturbed',c,post+c['vd']*b+e)
    c=next(x for x in cases if x['vlen']==128 and x['sew']==16 and x['lmul']=='m1' and x['form']=='vv' and x['tag']=='start1')
    control('prestart',c,post+c['vd']*b)
    v.save(out/'summary.json',dict(controls=len(records),rejected=len(records),records=records))
    print(f'{len(records)} actual-packet controls rejected')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('output',type=Path);a=p.parse_args();run(a.root,a.output)
