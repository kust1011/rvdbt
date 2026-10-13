#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retained destination-chunk delta packet controls, no guest reruns."""
import collections,json,sys
from pathlib import Path
import vadd as v
import wmac156 as w

def run(rows,packet,out):
    out.mkdir(parents=True,exist_ok=False);records=[]
    for op,forms in w.FORMS.items():
      for form in forms:
        for start in [False,True]:
          c=next(c for c in rows if c['mnemonic']==op and c['form']==form and bool(c['vstart'])==start and c['mask']=='none' and (c['vlen'],c['sew'],c['lmul'])==(128,32,'m4'))
          raw=packet(c,'B');ref=packet(c,'Reference');w.check_isa(c,raw);w.check_reference(c,raw,ref)
          b=c['vlen']//8;de=c['sew']//4;pos=96+32*b+c['vd']*b
          offsets=[('active',pos+c['vstart']*de),('upper-byte',pos+c['vstart']*de+de-1),('tail',pos+c['vl']*de),('prestart' if start else 'post-vstart',pos if start else 52+12)]
          for label,off in offsets:
            bad=bytearray(raw);bad[off]^=1
            try:w.check_isa(c,bad)
            except ValueError as ex:records.append(dict(case=c['id'],control=label,rejected=True,error=str(ex)))
            else:raise ValueError('accepted '+label)
    v.save(out/'summary.json',dict(controls=len(records),rejected=len(records),allowed=0,records=records,guest_executions=0));return len(records)
if __name__=='__main__':
    root=Path(sys.argv[1]);rows=json.loads((root/'manifest.json').read_text())['cases'];units=collections.defaultdict(list);cache={}
    for c in rows:units[c['unit']].append(c)
    def packet(c,arm):
      p=root/'runs'/c['unit']/arm/'packets.bin'
      if p not in cache:cache[p]=v.storage.verify(p)
      size=v.packet_size(c);off=units[c['unit']].index(c)*size;return cache[p][off:off+size]
    print(run(rows,packet,Path(sys.argv[2])))
