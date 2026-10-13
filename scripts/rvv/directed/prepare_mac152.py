#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite next-family declaration and local preflight, no guest credit."""
import collections,gzip,hashlib,json,struct,subprocess,sys
from pathlib import Path
import mac152_next as m
import vadd as v

def prepare(out):
    out.mkdir(parents=True,exist_ok=True);rows=m.cases();checks=0
    for e in (8,16,32,64):
      for op,expected in [('vmacc',22),('vnmsac',-8),('vmadd',38),('vnmsub',-32)]:
        assert int.from_bytes(m.element(dict(mnemonic=op,sew=e),3,5,7),'little')==expected%(1<<e);checks+=1
    # Explicit RV32-to-SEW64 scalar sign extension, with an independent
    # expression for the old-destination operand role.
    for op in m.FORMS:
      c=dict(next(c for c in rows if c['mnemonic']==op and c['form']=='vx' and c['sew']==64 and c['tag']=='length0'),operand=0x80000000)
      before=m.initial(c);b=c['vlen']//8
      a=int.from_bytes(before[c['vs2']*b:c['vs2']*b+8],'little');d=int.from_bytes(before[c['vd']*b:c['vd']*b+8],'little');z=-(1<<31)
      r={'vmacc':d+z*a,'vnmsac':d-z*a,'vmadd':a+z*d,'vnmsub':a-z*d}[op]
      assert int.from_bytes(m.lane(c,before,0),'little')==r%(1<<64);checks+=1
    # Every geometry/form/tag supplies encoding/layout; prestate extents sampled
    # per geometry, not rebuilt for every duplicate length/mask case.
    geometry={};encodings={};units={}
    for i,c in enumerate(rows):
      c['ordinal']=i;units.setdefault(c['unit'],c)
      assert c['vd']%c['group_registers']==c['vs2']%c['group_registers']==0
      if c['form']=='vv':assert c['vs1']%c['group_registers']==0
      assert max(c['vd'],c['vs2'],c['vs1'])+c['group_registers']<=32
      geometry.setdefault((c['vlen'],c['sew'],c['lmul']),c)
      encodings.setdefault(m.target(c),m.instruction(c))
    for c in geometry.values():assert len(m.initial(c))==32*c['vlen']//8;checks+=1
    for op,forms in m.FORMS.items():
      for form in forms:
       for tag in ['length1','dest-source2','end-group','same-sources' if form=='vv' else 'operand2147483648','dest-both-sources','start-partial-active-tu']:
        c=next(c for c in rows if c['mnemonic']==op and c['form']==form and (c['vlen'],c['sew'],c['lmul'])==(128,8,'m1') and c['tag']==tag)
        before=m.initial(c);after=bytearray(before);b=c['vlen']//8;e=c['sew']//8
        for i in range(c['vstart'],c['vl']):
          if c['mask']=='none' or before[i//8]>>(i%8)&1:after[c['vd']*b+i*e:c['vd']*b+(i+1)*e]=m.lane(c,before,i)
        x=c['operand']&0xffffffff
        raw=struct.pack('<2I',0x145add,c['ordinal'])+struct.pack('<11I',*v.csr_expected(c),x)+struct.pack('<11I',*v.csr_expected(c,True),x)+before+after
        m.check_isa(c,raw);m.check_reference(c,raw,raw);checks+=2
        bad=bytearray(raw);bad[96+32*b+c['vd']*b]^=1
        try:m.check_isa(c,bad)
        except ValueError:checks+=1
        else:raise AssertionError('active/prestart corruption accepted')
    source=out/'TARGET_ENCODING_CHECK.S';source.write_text('.option norvc\n.text\n'+ '\n'.join(encodings)+'\n')
    obj=out/'TARGET_ENCODING_CHECK.o';r=subprocess.run(['clang-20','--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d','-c',str(source),'-o',str(obj)],capture_output=True)
    (out/'TARGET_ENCODING_BUILD.stderr').write_bytes(r.stderr);assert r.returncode==0,r.stderr
    import audit
    sections,_=audit.elf_sections_symbols(obj);data=sections['.text'][1]
    assert list(struct.unpack('<'+'I'*len(encodings),data))==list(encodings.values());obj.unlink()
    reserved=sum(c['vstart']>=c['vlmax'] for c in rows)
    v.save(out/'DECLARATION.json',dict(forms=[op+'.'+f for op,fs in m.FORMS.items() for f in fs],cases=len(rows),units=len(units),ordinary=len(rows)-reserved,reserved_start=reserved,reserved_encodings=m.reserved_declarations(),execution='NOT_RUN',guest_credit=0))
    with gzip.open(out/'PREPARED_MANIFEST.json.gz','wt') as f:json.dump(rows,f,separators=(',',':'))
    pilot=[unit for unit,c in units.items() if (c['vlen'],c['sew'],c['lmul']) in [(128,8,'m1'),(128,64,'m4'),(1024,8,'m8'),(4096,8,'m8')]]
    v.save(out/'PILOT_UNITS.json',pilot)
    v.save(out/'LOCAL_CHECKS.json',dict(checks=checks,encodings=len(encodings),layouts=len(rows),geometry_extents=len(geometry),pilot_units=len(pilot),pilot_cases=sum(c['unit'] in pilot for c in rows),guest_executions=0))
    v.save(out/'PREPARED_FREEZE.json',{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(m.__file__),Path(__file__)]})
    print(json.loads((out/'DECLARATION.json').read_text()))
if __name__=='__main__':prepare(Path(sys.argv[1]))
