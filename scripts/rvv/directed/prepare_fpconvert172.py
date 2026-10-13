#!/usr/bin/env python3
"""Freeze exact legal conversion declarations and validate encodings/predicates."""
import collections,gzip,json,struct,subprocess,sys
from pathlib import Path
import fpconvert172 as f
import fp157 as fp
import vadd as v
import audit

def synthetic(c):
 before=f.initial(c);after=bytearray(before);b=c['vlen']//8;e=c['dst_eew']//8
 for i in range(c['vstart'],c['vl']):
  if f.active(c,before,i):
   off=c['vd']*b+i*e;after[off:off+e]=f.lane(c,before,i)[0].to_bytes(e,'little')
 x=c['operand']&0xffffffff
 return struct.pack('<2I',0x145add,c['ordinal'])+struct.pack('<11I',*f.csr_expected(c),x)+struct.pack('<11I',*f.csr_expected(c,True,before),x)+before+after+struct.pack('<2Q',f.scalar(c),f.scalar(c))

def minimal():
 checks=0
 def eq(form,sw,dw,x,rm,want):
  nonlocal checks
  assert f.element(form,sw,dw,x,rm)==want,(form,sw,dw,x,rm,f.element(form,sw,dw,x,rm),want);checks+=1
 for bits in (32,64):
  k=fp.constants(bits)
  for signed in (False,True):
   suffix='x' if signed else 'xu';hi=(1<<(bits-int(signed)))-1;lo=1<<(bits-1) if signed else 0
   for rm in range(5):
    for form in ('vfcvt.'+suffix+'.f.v','vfcvt.rtz.'+suffix+'.f.v'):
     for key,want in [('zero',(0,0)),('negzero',(0,0)),('qnan',(hi,16)),('snan',(hi,16)),('inf',(hi,16)),('neginf',(lo,16))]:eq(form,bits,bits,k[key],rm,want)
    eq('vfcvt.f.'+suffix+'.v',bits,bits,0,rm,(0,0))
   eq('vfcvt.rtz.'+suffix+'.f.v',bits,bits,k['half'],4,(0,1))
   eq('vfcvt.'+suffix+'.f.v',bits,bits,k['half']|k['negzero'],0,(0,1))
   eq('vfcvt.'+suffix+'.f.v',bits,bits,k['negone'],0,((1<<bits)-1,0) if signed else (0,16))
 # Independently hand-derived IEEE encodings: tie even/odd, ROD jamming,
 # exact subnormal, tiny half ULP, overflow and exact integer16 sign extension.
 x=0x3ff0000010000000
 for rm,want in [(0,0x3f800000),(1,0x3f800000),(2,0x3f800000),(3,0x3f800001),(4,0x3f800001)]:eq('vfncvt.f.f.w',64,32,x,rm,(want,1))
 for rm in range(5):
  eq('vfncvt.rod.f.f.w',64,32,x,rm,(0x3f800001,1))
  eq('vfncvt.rod.f.f.w',64,32,0x3690000000000000,rm,(1,3)) # 2^-150
  eq('vfncvt.rod.f.f.w',64,32,0x7fefffffffffffff,rm,(0x7f7fffff,5))
  eq('vfwcvt.f.x.v',16,32,0x8000,rm,(0xc7000000,0))
  eq('vfwcvt.f.xu.v',16,32,0xffff,rm,(0x477fff00,0))
  eq('vfncvt.f.f.w',64,32,0x36a0000000000000,rm,(1,0))
  eq('vfwcvt.f.f.v',32,64,0x80000000,rm,(0x8000000000000000,0))
 return checks

def prepare(out,compiler='clang-20'):
 out.mkdir(parents=True,exist_ok=False);checks=minimal();rows=f.cases();units={};enc={}
 for i,c in enumerate(rows):
  c['ordinal']=i;f.validate(c);units.setdefault(c['unit'],c);enc.setdefault(f.target(c),f.instruction(c))
 pilot=[u for u,c in units.items() if (c['vlen'],c['sew'],c['lmul']) in [(128,16,'mf4'),(128,32,'mf2'),(128,64,'m1'),(1024,32,'m1'),(4096,32,'m4')]]
 # Geometry/preservation checks on synthetic packets are zero guest credit.
 selected=[c for c in rows if c['unit'] in set(pilot)]
 for c in selected:f.check_isa(c,synthetic(c))
 source=out/'TARGET_ENCODING_CHECK.S';source.write_text('.option norvc\n.text\n'+'\n'.join(enc)+'\n');obj=out/'TARGET_ENCODING_CHECK.o'
 p=subprocess.run([compiler,'--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d','-c',str(source),'-o',str(obj)],capture_output=True);(out/'BUILD.stderr').write_bytes(p.stderr);assert not p.returncode,p.stderr
 sections,_=audit.elf_sections_symbols(obj);assert list(struct.unpack('<'+'I'*len(enc),sections['.text'][1]))==list(enc.values())
 with gzip.open(out/'PREPARED_MANIFEST.json.gz','wt') as stream:json.dump(rows,stream,separators=(',',':'))
 profiles=[]
 for form in f.FORMS:
  configs={tuple((k,c[k]) for k in ('vlen','sew','lmul','src_eew','dst_eew','src_emul','dst_emul','src_regs','dst_regs','vlmax')) for c in rows if c['mnemonic']==form}
  profiles.append(dict(form=form,configs=[dict(x) for x in sorted(configs)],configuration_count=len(configs)))
 v.save(out/'PROFILE.json',dict(flen=64,elen=64,fp_operand_widths=[32,64],half_extension='NOT_ASSUMED',forms=profiles))
 for branch,prefix in [('same','vfcvt'),('widen','vfwcvt'),('narrow','vfncvt')]:
  branch_units=[u for u,c in units.items() if c['mnemonic'].startswith(prefix)]
  v.save(out/(branch+'-pilot.json'),[u for u in branch_units if u in pilot]);v.save(out/(branch+'-remaining.json'),[u for u in branch_units if u not in pilot])
 v.save(out/'DECLARATION.json',dict(forms=list(f.FORMS),cases=len(rows),units=len(units),checks=len(rows)*5,commands=len(units)*5,per_form=dict(collections.Counter(c['mnemonic'] for c in rows)),form_config_pairs=sum(x['configuration_count'] for x in profiles),pilot_cases=len(selected),pilot_units=len(pilot),execution='NOT_RUN',reserved_obligations=['unsupported FP16 operands (no half extension assumed)','EMUL>8 / FP128 / ELEN>64','misaligned/out-of-bounds groups','illegal widening low overlap/fractional source overlap','illegal narrowing high overlap','masked data source/destination v0','reserved frm5/6/7, including explicit RTZ/ROD: separately adjudicated, no ordinary credit','vstart>=VLMAX excluded; separate obligation']))
 v.save(out/'LOCAL_CHECKS.json',dict(analytical_checks=checks,synthetic_pilot_packets=len(selected),distinct_encodings=len(enc),validated_layouts=len(rows),guest_credit=0))
 print(len(rows),len(units),len(selected),len(pilot),flush=True)
if __name__=='__main__':prepare(Path(sys.argv[1]),sys.argv[2] if len(sys.argv)>2 else 'clang-20')
