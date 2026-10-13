#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Freeze finite FP declarations and compile all distinct target encodings."""
import collections
import gzip
import json
from pathlib import Path
import struct
import subprocess
import sys
import fp157 as f
import vadd as v
import audit

def synthetic(c):
    before=f.initial(c);after=bytearray(before);b=c['vlen']//8;e=c['sew']//8
    for i in range(c['vstart'],c['vl']):
        if f.active(c,before,i):
            off=c['vd']*b+i*e;after[off:off+e]=f.lane(c,before,i)[0].to_bytes(e,'little')
    x=c['operand']&0xffffffff
    return (struct.pack('<2I',0x145add,c['ordinal'])+
            struct.pack('<11I',*f.csr_expected(c),x)+
            struct.pack('<11I',*f.csr_expected(c,True,before),x)+before+after+
            struct.pack('<2Q',f.scalar(c),f.scalar(c)))

def prepare(out):
    out.mkdir(parents=True,exist_ok=False);rows=f.cases();encodings={};units={}
    for i,c in enumerate(rows):
        c['ordinal']=i;units.setdefault(c['unit'],c);encodings.setdefault(f.target(c),f.instruction(c))
        assert c['sew'] in (32,64) and 0<=c['frm']<5
        assert c['vd']%c['group_registers']==c['vs2']%c['group_registers']==c['vs1']%c['group_registers']==0
        assert max(c['vd'],c['vs1'],c['vs2'])+c['group_registers']<=32
    # Both precisions x every form x all rounding modes; large-VLEN chunk pilot.
    pilot=[u for u,c in units.items() if (c['vlen'],c['sew'],c['lmul']) in [(128,32,'m1'),(128,64,'m1')]
           or (c['vlen'],c['sew'],c['lmul'],c['frm'])==(1024,64,'m1',0)]
    delta=[u for u,c in units.items() if (c['vlen'],c['sew'],c['lmul']) in [(128,32,'mf2'),(1024,64,'m8')]
           and ('-edge-rm' in u or u.endswith(('-vv-zero','-vv-start','-vx-zero','-vx-start')))]
    # The original 3914-case pilot remains its own immutable declaration.
    # Added edge units at m1 are full-only; this delta targets new geometries.
    pilot=[u for u in pilot if '-edge-rm' not in u]+delta
    selected=[c for c in rows if c['unit'] in set(pilot)]
    for c in selected:f.check_isa(c,synthetic(c))
    source=out/'TARGET_ENCODING_CHECK.S';source.write_text('.option norvc\n.text\n'+'\n'.join(encodings)+'\n')
    obj=out/'TARGET_ENCODING_CHECK.o'
    run=subprocess.run(['clang-20','--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d','-c',str(source),'-o',str(obj)],capture_output=True)
    (out/'BUILD.stderr').write_bytes(run.stderr)
    if run.returncode:raise RuntimeError(run.stderr.decode())
    sections,_=audit.elf_sections_symbols(obj);words=struct.unpack('<'+'I'*len(encodings),sections['.text'][1])
    assert list(words)==list(encodings.values())
    with gzip.open(out/'PREPARED_MANIFEST.json.gz','wt') as stream:json.dump(rows,stream,separators=(',',':'))
    v.save(out/'PILOT_UNITS.json',pilot)
    v.save(out/'DELTA_PILOT_UNITS.json',delta)
    reserved=sum(c['vstart']>=c['vlmax'] and c['vstart']>0 for c in rows)
    v.save(out/'DECLARATION.json',dict(forms=[op+'.'+form for op,forms in f.FORMS.items() for form in forms],cases=len(rows),units=len(units),checks=len(rows)*5,commands=len(units)*5,ordinary=len(rows)-reserved,reserved_start=reserved,geometries=len({(c['vlen'],c['sew'],c['lmul']) for c in rows}),rounding_modes=list(range(5)),reserved_encodings=f.reserved_declarations(),execution='NOT_RUN',guest_credit=0,per_form=dict(collections.Counter(c['mnemonic']+'.'+c['form'] for c in rows))))
    v.save(out/'LOCAL_CHECKS.json',dict(layouts=len(rows),distinct_compiled_encodings=len(encodings),synthetic_pilot_predicates=len(selected),pilot_units=len(pilot),pilot_cases=len(selected),pilot_checks=len(selected)*5,pilot_commands=len(pilot)*5,delta_pilot_units=len(delta),delta_pilot_cases=sum(c['unit'] in set(delta) for c in rows),guest_credit=0))
    print(json.loads((out/'LOCAL_CHECKS.json').read_text()))

if __name__=='__main__':prepare(Path(sys.argv[1]))
