#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only branch examples from actual pilot packets, never golden creation."""
import argparse,collections,hashlib,json
from pathlib import Path
import vadd as v

def review(base,out):
    root=base/'corpus';cs=json.loads((root/'manifest.json').read_text())['cases']
    ids={c['id']:c for c in cs};units=collections.defaultdict(list)
    for c in cs:units[c['unit']].append(c)
    controls=json.loads((base/'controls/summary.json').read_text())['records'];selected=[]
    for op in ['vmul','vmulh','vmulhu','vmulhsu','vdiv','vdivu','vrem','vremu']:
      for form in ['vv','vx']:
        tags=['witness-high-both-negative' if op.startswith('vmul') else 'witness-negative-positive' if op in ['vdiv','vrem'] else 'witness-unsigned-extreme']
        if op in ['vdiv','vdivu','vrem','vremu']:tags+=['witness-zero-divisor']
        if op in ['vdiv','vrem']:tags+=['witness-min-minus-one']
        for tag in tags:selected.append(next(c for c in cs if c['mnemonic']==op and c['form']==form and (c['vlen'],c['sew'],c['lmul'])==(128,64,'m4') and c['tag']==tag))
        if form=='vx':selected.append(ids[next(r['case'] for r in controls if r.get('control')=='scalar-zero-extension' and ids[r['case']]['mnemonic']==op and ids[r['case']]['form']==form)])
    rows=[]
    for c in {c['id']:c for c in selected}.values():
      size=v.packet_size(c);offset=units[c['unit']].index(c)*size;b=c['vlen']//8;e=c['sew']//8;arms={};ref=None
      for arm in ['Reference','B','M1','M2','BOTH']:
        p=root/'runs'/c['unit']/arm/'packets.bin';data=v.storage.verify(p)[offset:offset+size]
        v.check(c,data,reference=ref)
        if arm=='Reference':ref=data
        pre,post,before,after=v.decode(c,data)
        a=int.from_bytes(before[c['vs2']*b:c['vs2']*b+e],'little')
        z=int.from_bytes(before[c['vs1']*b:c['vs1']*b+e],'little') if c['form']=='vv' else (c['operand']-(1<<32) if c['operand']&0x80000000 else c['operand'])&((1<<c['sew'])-1)
        destination=int.from_bytes(after[c['vd']*b:c['vd']*b+e],'little')
        arms[arm]=dict(vs2=f'0x{a:016x}',other=f'0x{z:016x}',destination_lane0=f'0x{destination:016x}',pre_csrs=pre,post_csrs=post,logical_packet_sha256=hashlib.sha256(data).hexdigest(),raw_logical_path=str(p.relative_to(base)),offset=offset,bytes=size,original_command_file=str((p.parent/'command.json').relative_to(base)))
      rows.append(dict(case=c['id'],geometry={k:c[k] for k in ['sew','lmul','vlen','vl','vstart','mask','ta','ma','vd','vs2','vs1','operand']},source=str((root/c['unit']/'test.S').relative_to(base)),source_logical_sha256=v.sha(root/c['unit']/'test.S'),elf_logical_sha256=v.sha(root/c['unit']/'test.elf'),arms=arms))
    v.save(out,dict(remote_base=str(base.resolve()),extractor_sha256=v.sha(__file__),examples=rows));print(len(rows),'actual case examples')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('base',type=Path);p.add_argument('output',type=Path);a=p.parse_args();review(a.base,a.output)
