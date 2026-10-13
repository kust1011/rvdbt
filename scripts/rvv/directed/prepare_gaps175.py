#!/usr/bin/env python3
import collections,gzip,json,struct,subprocess,sys
from pathlib import Path
import gaps175 as f
import vadd as v
import audit

def synthetic(c):
 before=f.initial(c);after=bytearray(before);b,e=c['vlen']//8,c['sew']//8
 for i in range(c['vstart'],c['vl']):
  if f.active(c,before,i):
   off=c['vd']*b+i*e;after[off:off+e]=f.lane(c,before,i).to_bytes(e,'little')
 x=c['operand']&0xffffffff
 return struct.pack('<2I',0x145add,c['ordinal'])+struct.pack('<11I',*f.csr_expected(c),x)+struct.pack('<11I',*f.csr_expected(c,True),x)+before+after+struct.pack('<2Q',f.scalar(c),f.scalar(c))
def prepare(out,family,compiler):
 out.mkdir(parents=True,exist_ok=False);rows=f.cases(family);units={};enc={}
 for i,c in enumerate(rows):
  c['ordinal']=i;f.validate(c);f.check_isa(c,synthetic(c));units.setdefault(c['unit'],c);enc.setdefault(f.target(c),f.instruction(c))
 pilot=[u for u,c in units.items() if (c['vlen'],c['sew'],c['lmul']) in ((128,32,'mf2'),(128,64,'m1'),(128,8,'mf8'),(1024,32,'m1'),(4096,32,'m4'))]
 source=out/'ENCODINGS.S';source.write_text('.option norvc\n.text\n'+'\n'.join(enc)+'\n');obj=out/'ENCODINGS.o'
 p=subprocess.run([compiler,'--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d','-c',str(source),'-o',str(obj)],capture_output=True);(out/'BUILD.stderr').write_bytes(p.stderr);assert p.returncode==0,p.stderr
 sections,_=audit.elf_sections_symbols(obj);assert list(struct.unpack('<'+'I'*len(enc),sections['.text'][1]))==list(enc.values())
 with gzip.open(out/'PREPARED_MANIFEST.json.gz','wt') as stream:json.dump(rows,stream,separators=(',',':'))
 v.save(out/'pilot.json',pilot);v.save(out/'remaining.json',[u for u in units if u not in pilot])
 v.save(out/'DECLARATION.json',dict(family=family,forms=f.FORMS[family],cases=len(rows),units=len(units),checks=len(rows)*5,commands=len(units)*5,per_form=dict(collections.Counter(c['mnemonic']+'.'+c['form'] for c in rows)),pilot_cases=sum(c['unit'] in pilot for c in rows),pilot_units=len(pilot),synthetic_checks=len(rows),encodings=len(enc),guest_credit=0))
 print(family,len(rows),len(units),len(pilot),flush=True)
if __name__=='__main__':prepare(Path(sys.argv[1]),sys.argv[2],sys.argv[3] if len(sys.argv)>3 else 'clang-22')
