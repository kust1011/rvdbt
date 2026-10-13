#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Task147 independently corrupted formal packets and allowed-choice controls."""
import argparse, json, struct
from pathlib import Path
import vadd as v
import config

def reject(root,out):
    out.mkdir(parents=True,exist_ok=False)
    m=json.loads((root/'manifest.json').read_text());rows=[];positive=[]
    for form in ['vsetvli','vsetivli','vsetvl']:
      selected=[]
      for tag in ['avl0','avl1','deterministic-repeat','vill-recovery','rd-zero','rd-rs1-overlap','preserve-policy-vl1','rd-rs2-overlap','upper-bit31','unsupported-lmul100']:
        matches=[c for c in m['cases'] if c['form']==form and c['tag']==tag and c['vlen']==128 and c['sew']==8 and c['lmul']=='m1' and not c['ta'] and not c['ma']]
        if matches:selected.append(matches[0])
      for c in selected:
        cs=[x for x in m['cases'] if x['unit']==c['unit']];offset=cs.index(c)*v.packet_size(c)
        source=root/'runs'/c['unit']/'B'/'packets.bin';raw=source.read_bytes()[offset:offset+v.packet_size(c)]
        reference=(root/'runs'/c['unit']/'Reference'/'packets.bin').read_bytes()[offset:offset+v.packet_size(c)]
        v.check(c,raw,reference=reference)
        # Each independent alteration leaves all other packet fields untouched.
        changes={'rd':92,'vl':52,'vtype':56,'vstart':64,'vlenb':60,'other-csr':68,'vector-output':96+32*(c['vlen']//8)+17,'pre-vector':96+17,'pre-rd':48}
        for name,pos in changes.items():
          bad=bytearray(raw);bad[pos]^=1
          p=out/(c['id']+'-'+name+'.bin');p.write_bytes(bad)
          try:v.check(c,bytes(bad),reference=reference)
          except ValueError as e:rows.append(dict(case=c['id'],control=name,rejected=True,error=str(e),corrupt=p.name,source=str(source),offset=offset,sha256=v.sha(p)))
          else:raise ValueError('corruption accepted: '+c['id']+' '+name)
        for name,blob,rc,timeout in [('missing',raw[:-4],0,False),('crash',raw,1,False),('timeout',raw,0,True)]:
          try:v.check(c,blob,rc,timeout,reference)
          except ValueError as e:rows.append(dict(case=c['id'],control=name,rejected=True,error=str(e)))
          else:raise ValueError('failure control accepted')
        if config.bounds(c)[0]!=config.bounds(c)[1]:
          # An alternative permitted VL with matching actual rd must be accepted.
          for value in set(config.bounds(c)):
            good=bytearray(raw);struct.pack_into('<I',good,52,value);struct.pack_into('<I',good,92,value)
            v.check(c,bytes(good),reference=reference)
            p=out/(c['id']+'-allowed'+str(value)+'.bin');p.write_bytes(good)
            positive.append(dict(case=c['id'],vl=value,accepted=True,packet=p.name))
          bad=bytearray(raw);value=config.bounds(c)[0]-1
          struct.pack_into('<I',bad,52,value);struct.pack_into('<I',bad,92,value)
          p=out/(c['id']+'-below-bound.bin');p.write_bytes(bad)
          try:v.check(c,bytes(bad),reference=reference)
          except ValueError as e:rows.append(dict(case=c['id'],control='coherent-rd-vl-outside-set',rejected=True,error=str(e),corrupt=p.name))
          else:raise ValueError('coherent illegal VL accepted')
        # Invoke independent comparison directly, bypassing DUT ISA check.
        bad=bytearray(raw);bad[68]^=1
        try:config.check_reference(c,bytes(bad),reference)
        except ValueError as e:rows.append(dict(case=c['id'],control='reference-comparison-only',rejected=True,error=str(e)))
        else:raise ValueError('independent comparison control accepted')
    c=next(c for c in m['cases'] if c['form']=='vsetvli' and c['tag']=='deterministic-repeat' and c['vlen']==128 and c['sew']==8 and c['lmul']=='m1' and not c['ta'] and not c['ma'])
    cs=[x for x in m['cases'] if x['unit']==c['unit']];size=v.packet_size(c);offset=cs.index(c)*size
    raw=(root/'runs'/c['unit']/'B'/'packets.bin').read_bytes()[offset:offset+size]
    bad=bytearray(raw);lo,hi=config.bounds(c);alternate=hi if v.decode(c,raw)[1][0]==lo else lo
    struct.pack_into('<I',bad,52,alternate);struct.pack_into('<I',bad,92,alternate)
    v.check_isa(c,bytes(bad)) # individually legal; inconsistent with equal inputs
    p=out/'determinism-legal-vl-corruption.bin';p.write_bytes(bad)
    deterministic=config.determinism(root,{(c['id'],'B'):bytes(bad)})
    if not deterministic['failures']:raise ValueError('nondeterministic legal-choice corruption accepted')
    v.save(out/'determinism-control.json',deterministic)
    rows.append(dict(case=c['id'],control='determinism-with-individually-legal-vl',rejected=True,corrupt=p.name))
    v.save(out/'rejections.json',dict(count=len(rows),rejected=sum(r['rejected'] for r in rows),controls=rows,allowed_choice_controls=positive))
    print(f'{len(rows)} controls rejected; {len(positive)} permitted-choice controls accepted')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('output',type=Path);a=p.parse_args();reject(a.root,a.output)
