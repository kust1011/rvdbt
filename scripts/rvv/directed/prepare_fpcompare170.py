#!/usr/bin/env python3
"""Freeze full disjoint manifest, validate target words and closed-form rules."""
import collections,gzip,json,struct,subprocess,sys
from pathlib import Path
import fpcompare170 as f
import fp157 as fp
import vadd as v
import audit

def synthetic(c):
 before=f.initial(c);after=bytearray(before);b,e=c['vlen']//8,c['sew']//8
 for i in range(c['vstart'],c['vl']):
  if f.active(c,before,i):
   value=f.lane(c,before,i)[0]
   if f.comparison(c):
    off=c['vd']*b+i//8;after[off]=(after[off]&~(1<<(i%8)))|(value<<(i%8))
   else:
    off=c['vd']*b+i*e;after[off:off+e]=value.to_bytes(e,'little')
 x=c['operand']&0xffffffff
 return struct.pack('<2I',0x145add,c['ordinal'])+struct.pack('<11I',*f.csr_expected(c),x)+struct.pack('<11I',*f.csr_expected(c,True,before),x)+before+after+struct.pack('<2Q',f.scalar(c),f.scalar(c))

def prepare(out,compiler):
 out.mkdir(parents=True,exist_ok=False);rows=f.cases();units={};encodings={}
 for i,c in enumerate(rows):
  c['ordinal']=i;units.setdefault(c['unit'],c);encodings.setdefault(f.target(c),f.instruction(c))
  assert c['vs2']%c['group_registers']==0 and c['vs1']%c['group_registers']==0
  assert max(c['vs2'],c['vs1'])+c['group_registers']<=32
  assert 0<=c['vstart']<c['vlmax'] and 0<=c['vl']<=c['vlmax']
  if not f.comparison(c):assert c['vd']%c['group_registers']==0 and c['vd']+c['group_registers']<=32
 pilot=[u for u,c in units.items() if (c['vlen'],c['sew'],c['lmul']) in [(128,32,'mf2'),(128,64,'m1'),(1024,32,'m1'),(4096,64,'m8')]]
 selected=[c for c in rows if c['unit'] in set(pilot)]
 for c in selected:f.check_isa(c,synthetic(c))
 analytical=[]
 for bits in (32,64):
  k=fp.constants(bits)
  for op in ('vfmin','vfmax'):
   for a,z,value,nv in [(0,k['negzero'],k['negzero'] if op=='vfmin' else 0,0),(k['snan'],k['one'],k['one'],16),(k['qnan'],k['one'],k['one'],0),(k['snan'],k['qnan'],k['canonical'],16)]:
    assert f.element(bits,op,a,z)==(value,nv);analytical.append([bits,op,a,z,value,nv])
  for op in ('vmfeq','vmfne','vmflt','vmfle','vmfgt','vmfge'):
   assert f.element(bits,op,k['qnan'],k['one'])==(int(op=='vmfne'),0 if op in ('vmfeq','vmfne') else 16)
   assert f.element(bits,op,k['snan'],k['one'])==(int(op=='vmfne'),16)
  values=[k['neginf'],k['negone'],k['minsub']|k['negzero'],k['negzero'],0,k['minsub'],k['one'],k['inf'],k['snan'],k['qnan']]
  for index,word in enumerate(values):assert f.element(bits,'vfclass',word,0)==(1<<index,0)
  for op in ('vfsgnj','vfsgnjn','vfsgnjx'):
   a=k['snan'];z=k['negone'];expected=a|k['negzero'] if op in ('vfsgnj','vfsgnjx') else a
   assert f.element(bits,op,a,z)==(expected,0)
 source=out/'TARGET_ENCODING_CHECK.S';source.write_text('.option norvc\n.text\n'+'\n'.join(encodings)+'\n');obj=out/'TARGET_ENCODING_CHECK.o'
 cmd=[compiler,'--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d','-c',str(source),'-o',str(obj)];p=subprocess.run(cmd,capture_output=True);(out/'BUILD.stderr').write_bytes(p.stderr);assert p.returncode==0,p.stderr
 sections,_=audit.elf_sections_symbols(obj);assert list(struct.unpack('<'+'I'*len(encodings),sections['.text'][1]))==list(encodings.values())
 with gzip.open(out/'PREPARED_MANIFEST.json.gz','wt') as s:json.dump(rows,s,separators=(',',':'))
 v.save(out/'PILOT_UNITS.json',pilot)
 for branch,ops in [('minmax',('vfmin','vfmax')),('sign',('vfsgnj','vfsgnjn','vfsgnjx')),('compare-class',tuple(op for op in f.FORMS if op.startswith('vmf') or op=='vfclass'))]:
  current=[u for u,c in units.items() if c['mnemonic'] in ops]
  v.save(out/(branch+'-pilot.json'),[u for u in current if u in pilot]);v.save(out/(branch+'-remaining.json'),[u for u in current if u not in pilot])
 v.save(out/'DECLARATION.json',dict(forms=[op+'.'+form for op,fs in f.FORMS.items() for form in fs],cases=len(rows),units=len(units),checks=len(rows)*5,commands=len(units)*5,ordinary=len(rows),reserved=f.reserved_declarations(),reserved_vstart='vstart>=VLMAX excluded; separate NOT_RUN',blocked='none declared for supported FP32/64 ordinary cases',geometries=len({(c['vlen'],c['sew'],c['lmul']) for c in rows}),per_form=dict(collections.Counter(c['mnemonic']+'.'+c['form'] for c in rows)),execution='NOT_RUN',guest_credit=0))
 v.save(out/'LOCAL_CHECKS.json',dict(distinct_encodings=len(encodings),pilot_units=len(pilot),pilot_cases=len(selected),synthetic_pilot_predicates=len(selected),analytical_checks=analytical,guest_credit=0))
 print(len(rows),len(units),len(selected),len(pilot),flush=True)
if __name__=='__main__':prepare(Path(sys.argv[1]),sys.argv[2] if len(sys.argv)>2 else 'clang-20')
