#!/usr/bin/env python3
import collections,gzip,json,struct,subprocess,sys
from pathlib import Path
import fpreduce174 as f
import fp157 as fp
import vadd as v
import audit

def synthetic(c):
 before=f.initial(c);after=bytearray(before);b=c['vlen']//8;e=c['dst_eew']//8
 flags=c['fflags_initial']
 if c['vl']:
  value,flags=sorted(f.allowed(c,before))[0];off=c['vd']*b;after[off:off+e]=value.to_bytes(e,'little')
 post=f.csr_expected(c,True,before);post[7:]=[flags,c['frm'],c['frm']<<5|flags]
 return struct.pack('<2I',0x145add,c['ordinal'])+struct.pack('<11I',*f.csr_expected(c),c['operand'])+struct.pack('<11I',*post,c['operand'])+before+after+struct.pack('<2Q',f.scalar(c),f.scalar(c))

def minimal():
 checks=0
 for bits in (32,64):
  k=fp.constants(bits)
  for rm in range(5):
   for form in f.FORMS[:4]:
    assert f.fold(form,bits,rm,k['one'],(k['one'],k['negone']))==(k['negone'] if 'min' in form else k['one'],0);checks+=1
   assert f.fold('vfredosum.vs',bits,rm,k['inf'],(k['neginf'],))==(k['canonical'],16);checks+=1
   assert f.fold('vfredosum.vs',bits,rm,k['snan'],())==(k['snan'],0);checks+=1
   assert f.fold('vfredmin.vs',bits,rm,k['zero'],(k['negzero'],))==(k['negzero'],0);checks+=1
   assert f.fold('vfredmax.vs',bits,rm,k['zero'],(k['negzero'],))==(0,0);checks+=1
 # Exact operation order: (2^24+1)-2^24 is zero with NX in RNE.
 assert f.fold('vfredosum.vs',32,0,0,(0x4b800000,0x3f800000,0xcb800000))==(0,1);checks+=1
 return checks

def prepare(out,compiler):
 out.mkdir(parents=True,exist_ok=False);checks=minimal();rows=f.cases();units={};enc={}
 for i,c in enumerate(rows):
  c['ordinal']=i;f.validate(c);units.setdefault(c['unit'],c);enc.setdefault(f.target(c),f.instruction(c))
 pilot=[u for u,c in units.items() if (c['vlen'],c['sew'],c['lmul']) in ((128,32,'mf2'),(128,64,'m1'),(1024,32,'m1'),(4096,32,'m8'))]
 selected=[c for c in rows if c['unit'] in pilot]
 for c in selected:f.check_isa(c,synthetic(c))
 source=out/'TARGET_ENCODING_CHECK.S';source.write_text('.option norvc\n.text\n'+'\n'.join(enc)+'\n');obj=out/'TARGET_ENCODING_CHECK.o'
 p=subprocess.run([compiler,'--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d','-c',str(source),'-o',str(obj)],capture_output=True);(out/'BUILD.stderr').write_bytes(p.stderr);assert p.returncode==0,p.stderr
 sections,_=audit.elf_sections_symbols(obj);assert list(struct.unpack('<'+'I'*len(enc),sections['.text'][1]))==list(enc.values())
 with gzip.open(out/'PREPARED_MANIFEST.json.gz','wt') as stream:json.dump(rows,stream,separators=(',',':'))
 v.save(out/'pilot.json',pilot);v.save(out/'remaining.json',[u for u in units if u not in pilot])
 configs=collections.Counter()
 for c in units.values():configs[c['mnemonic']]+=1
 v.save(out/'DECLARATION.json',dict(forms=list(f.FORMS),cases=len(rows),units=len(units),checks=len(rows)*5,commands=len(units)*5,per_form=dict(collections.Counter(c['mnemonic'] for c in rows)),configurations_per_form=dict(configs),pilot_cases=len(selected),pilot_units=len(pilot),vlen=[128,256,512,1024,2048,4096],sew=[32,64],widening='32 to64; LMULmf2 through m8; scalar operands EMUL1',nonzero_vstart='must trap; separate no successful packet credit',unordered_scope='proven tree-invariant exact dyadic subsets, bounded specials and one-active QEMU values; general inexact unordered sums EXCLUDED',execution='NOT_RUN'))
 v.save(out/'LOCAL_CHECKS.json',dict(analytical_checks=checks,synthetic_pilot_packets=len(selected),distinct_encodings=len(enc),validated_layouts=len(rows),guest_credit=0))
 print(len(rows),len(units),len(selected),len(pilot),flush=True)
if __name__=='__main__':prepare(Path(sys.argv[1]),sys.argv[2] if len(sys.argv)>2 else 'clang-20')
