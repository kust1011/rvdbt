#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite widening declaration, layout/encoding checks; no guest credit."""
import collections,gzip,hashlib,json,struct,subprocess,sys
from pathlib import Path
import widen154_next as w
import vadd as v

def prepare(out):
    out.mkdir(parents=True,exist_ok=True);rows=w.cases();encodings={};units={};checks=0
    for i,c in enumerate(rows):
      c['ordinal']=i;w.validate(c);units.setdefault(c['unit'],c);encodings.setdefault(w.target(c),w.instruction(c))
    for e in (8,16,32):
      for op,forms in w.FORMS.items():
        for form in forms:
          c=next(c for c in rows if c['mnemonic']==op and c['form']==form and c['sew']==e)
          for a,z in [(3,5),((1<<(2*e if w.wide(c) else e))-1,1),(1<<(e-1),(1<<e)-1),(0,0xffffffff)]:
            ae=2*e if w.wide(c) else e;aa=a&((1<<ae)-1);zz=z&((1<<e)-1)
            if op in ('vwadd','vwsub','vwmul','vwmulsu') and aa>=(1<<(ae-1)):aa-=1<<ae
            if op in ('vwadd','vwsub','vwmul') and zz>=(1<<(e-1)):zz-=1<<e
            expected=aa*zz if op.startswith('vwmul') else aa-zz if op.startswith('vwsub') else aa+zz
            assert int.from_bytes(w.element(c,a,z),'little')==expected%(1<<(2*e));checks+=1
    geometries={}
    for c in rows:geometries.setdefault((c['vlen'],c['sew'],c['lmul'],w.wide(c),w.vector(c)),c)
    for c in geometries.values():assert len(w.initial(c))==32*c['vlen']//8;checks+=1
    tags=['length1','qemu-partial','qemu-even','qemu-odd','dest-high-source2','dest-high-source2-mask','dest-high-source1','dest-high-both-sources','dest-wide-source','start-partial-active-tu','end-group','start-zero-vl-maxcsr']
    selected={}
    for c in rows:
      if (c['vlen'],c['sew'],c['lmul'])==(128,8,'m1') and c['tag'] in tags:selected.setdefault((c['mnemonic'],c['form'],c['tag']),c)
    for c in selected.values():
      b=c['vlen']//8;de=c['sew']//4;before=w.initial(c);after=bytearray(before)
      for i in range(c['vstart'],c['vl']):
        if c['mask']=='none' or before[i//8]>>(i%8)&1:after[c['vd']*b+i*de:c['vd']*b+(i+1)*de]=w.lane(c,before,i)
      x=c['operand']&0xffffffff
      raw=struct.pack('<2I',0x145add,c['ordinal'])+struct.pack('<11I',*v.csr_expected(c),x)+struct.pack('<11I',*v.csr_expected(c,True),x)+before+after
      w.check_isa(c,raw);w.check_reference(c,raw,raw);checks+=2
      bad=bytearray(raw);bad[96+32*b+c['vd']*b]^=1
      try:w.check_isa(c,bad)
      except ValueError:checks+=1
      else:raise AssertionError('destination corruption accepted')
    source=out/'TARGET_ENCODING_CHECK.S';source.write_text('.option norvc\n.text\n'+'\n'.join(encodings)+'\n');obj=out/'TARGET_ENCODING_CHECK.o'
    r=subprocess.run(['clang-20','--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d','-c',str(source),'-o',str(obj)],capture_output=True)
    (out/'TARGET_ENCODING_BUILD.stderr').write_bytes(r.stderr);assert r.returncode==0,r.stderr
    import audit
    sections,_=audit.elf_sections_symbols(obj);data=sections['.text'][1]
    assert list(struct.unpack('<'+'I'*len(encodings),data))==list(encodings.values());obj.unlink()
    pilot=[unit for unit,c in units.items() if (c['vlen'],c['sew'],c['lmul']) in [(128,8,'m1'),(128,32,'m4'),(1024,8,'m4'),(4096,8,'mf8')]]
    reserved=sum(c['vstart']>=c['vlmax'] for c in rows)
    v.save(out/'DECLARATION.json',dict(forms=[op+'.'+f for op,fs in w.FORMS.items() for f in fs],cases=len(rows),units=len(units),ordinary=len(rows)-reserved,reserved_start=reserved,reserved_encodings=w.reserved_declarations(),execution='NOT_RUN',guest_credit=0))
    with gzip.open(out/'PREPARED_MANIFEST.json.gz','wt') as f:json.dump(rows,f,separators=(',',':'))
    v.save(out/'PILOT_UNITS.json',pilot);v.save(out/'LOCAL_CHECKS.json',dict(checks=checks,encodings=len(encodings),layouts=len(rows),geometry_extents=len(geometries),pilot_units=len(pilot),pilot_cases=sum(c['unit'] in pilot for c in rows),guest_executions=0))
    v.save(out/'PREPARED_FREEZE.json',{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(w.__file__),Path(__file__)]})
    print(json.loads((out/'LOCAL_CHECKS.json').read_text()))
if __name__=='__main__':prepare(Path(sys.argv[1]))
