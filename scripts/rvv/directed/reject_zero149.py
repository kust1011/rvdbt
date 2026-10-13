#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Supplement controls: actual 0/0 packets; no regenerated golden answers."""
import argparse,collections,json
from pathlib import Path
import vadd as v

def run(root,out):
    out.mkdir(parents=True,exist_ok=False);cs=json.loads((root/'manifest.json').read_text())['cases'];units=collections.defaultdict(list);records=[]
    for c in cs:units[c['unit']].append(c)
    for c in cs:
      if (c['vlen'],c['sew'],c['lmul'])!=(128,64,'m4'):continue
      size=v.packet_size(c);offset=units[c['unit']].index(c)*size;path=root/'runs'/c['unit']/'B'/'packets.bin'
      raw=v.storage.verify(path)[offset:offset+size];ref=v.storage.verify(path.parent.parent/'Reference'/'packets.bin')[offset:offset+size]
      v.check(c,raw,reference=ref);post=96+512+c['vd']*16
      wrong=(0 if c['mnemonic'].startswith('vdiv') else (1<<64)-1).to_bytes(8,'little')
      for mode in ['isa','independent']:
        bad=bytearray(raw);bad[post:post+8]=wrong;dest=out/(c['mnemonic']+'-'+c['form']+'-'+mode+'.bin');v.storage.write(dest,bad)
        try:
          if mode=='isa':v.check(c,bad,reference=ref)
          else:v.check_reference(c,bad,ref)
        except ValueError as ex:records.append(dict(case=c['id'],control='wrong-zero-over-zero-'+mode,rejected=True,error=str(ex),source=str(path),offset=offset,corrupt=dest.name,logical_sha256=v.sha(dest)))
        else:raise ValueError('accepted zero-over-zero corruption')
    assert len(records)==16
    v.save(out/'summary.json',dict(controls=len(records),rejected=len(records),records=records));print(len(records),'0/0 controls rejected')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('out',type=Path);a=p.parse_args();run(a.root,a.out)
