#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Declare the next extension family and check its new semantics before guests."""
import gzip,json,struct,subprocess,sys
from pathlib import Path
import extend156_next as w
import vadd as v
import audit

def prepare(out):
    out.mkdir(parents=True,exist_ok=False);rows=w.cases();encodings={};units={};records=[];checks=0
    for i,c in enumerate(rows):c['ordinal']=i;w.validate(c);units.setdefault(c['unit'],c);encodings.setdefault(w.target(c),w.instruction(c))
    selected={}
    for c in rows:
      if c['tag'] in ['length1','mask-alternating','dest-high-source-mask','start-partial-active-tu','start-zero-vl-maxcsr','policy11']:
        selected.setdefault((c['mnemonic'],c['form'],c['tag']),c)
    for c in selected.values():
      b=c['vlen']//8;e=c['sew']//8;before=w.initial(c);after=bytearray(before)
      for i in range(c['vstart'],c['vl']):
        if c['mask']=='none' or before[i//8]>>(i%8)&1:after[c['vd']*b+i*e:c['vd']*b+(i+1)*e]=w.lane(c,before,i)
      x=c['operand']&0xffffffff
      raw=struct.pack('<2I',0x145add,c['ordinal'])+struct.pack('<11I',*v.csr_expected(c),x)+struct.pack('<11I',*v.csr_expected(c,True),x)+before+after
      w.check_isa(c,raw);w.check_reference(c,raw,raw);checks+=2
      def reject(label,off,data):
        bad=bytearray(raw);bad[off:off+len(data)]=data;assert bad!=raw
        try:w.check_isa(c,bad)
        except ValueError as ex:records.append(dict(case=c['id'],control=label,rejected=True,error=str(ex)))
        else:raise ValueError('accepted '+label)
      if c['tag']=='length1':
        off=96+32*b+c['vd']*b;wrong=w.lane(dict(c,mnemonic='vsext' if c['mnemonic']=='vzext' else 'vzext'),before,0)
        reject('wrong-extension',off,wrong);reject('upper-result',off+e-1,bytes([raw[off+e-1]^1]))
      off=96+32*b+c['vd']*b;reject('destination-corruption',off,bytes([raw[off]^1]));reject('other-register',96+32*b+31*b,bytes([raw[96+32*b+31*b]^1]))
      for base in [8,52]:
        for j in range(11):reject('CSR-scalar-'+str(base)+'-'+str(j),base+4*j,bytes([raw[base+4*j]^1]))
    source=out/'TARGET_ENCODING_CHECK.S';source.write_text('.option norvc\n.text\n'+'\n'.join(encodings)+'\n');obj=out/'TARGET_ENCODING_CHECK.o'
    r=subprocess.run(['clang-20','--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d','-c',str(source),'-o',str(obj)],capture_output=True);(out/'BUILD.stderr').write_bytes(r.stderr);assert r.returncode==0,r.stderr
    sections,_=audit.elf_sections_symbols(obj);data=sections['.text'][1];assert list(struct.unpack('<'+'I'*len(encodings),data))==list(encodings.values())
    pilot=[unit for unit,c in units.items() if (c['vlen'],c['sew'],c['lmul']) in [(128,64,'m8'),(128,16,'m1'),(1024,64,'m8'),(4096,64,'m1')]]
    reserved=sum(c['vstart']>=c['vlmax'] for c in rows)
    v.save(out/'DECLARATION.json',dict(forms=[op+'.'+f for op,fs in w.FORMS.items() for f in fs],cases=len(rows),units=len(units),ordinary=len(rows)-reserved,reserved_start=reserved,reserved_encodings=w.reserved_declarations(),execution='NOT_RUN',guest_credit=0))
    with gzip.open(out/'PREPARED_MANIFEST.json.gz','wt') as f:json.dump(rows,f,separators=(',',':'))
    v.save(out/'PILOT_UNITS.json',pilot);v.save(out/'LOCAL_CHECKS.json',dict(checks=checks,encodings=len(encodings),layouts=len(rows),synthetic_controls=len(records),records=records,pilot_units=len(pilot),pilot_cases=sum(c['unit'] in pilot for c in rows),guest_executions=0))
    print(dict(cases=len(rows),units=len(units),encodings=len(encodings),checks=checks,controls=len(records),pilot_units=len(pilot),pilot_cases=sum(c['unit'] in pilot for c in rows)))
if __name__=='__main__':prepare(Path(sys.argv[1]))
