#!/usr/bin/env python3
"""FP32 -> FP64 widening arithmetic; exact rational predicates, independent oracles."""
import json
from pathlib import Path
import fp157 as fp
from fma164 import fused
FORMS={**{o:('vv','vf','wv','wf') for o in ('vfwadd','vfwsub')},**{o:('vv','vf') for o in ('vfwmul','vfwmacc','vfwnmacc','vfwmsac','vfwnmsac')}}
FUNCT6=dict(vfwadd=48,vfwsub=50,vfwmul=56,vfwmacc=60,vfwnmacc=61,vfwmsac=62,vfwnmsac=63)
SIGNS=dict(vfwmacc=(False,False),vfwnmacc=(True,True),vfwmsac=(False,True),vfwnmsac=(True,False))
QEMU=json.loads(Path(__file__).with_name('qemu_fpwiden173.json').read_text())
def widen(word):
 s,k,v,sn=fp.unpack(32,word)
 if k=='nan':return (s<<63)|fp.constants(64)['inf']|(1 if sn else (1<<51))
 if k=='inf':return (s<<63)|fp.constants(64)['inf']
 result,flags=fp.rounded(64,v,0,s);assert not flags
 return result

def target(c):
 rhs='fs0' if c['form'].endswith('f') else f'v{c["vs1"]}'
 args=f'{rhs},v{c["vs2"]}' if c['mnemonic'] in SIGNS else f'v{c["vs2"]},{rhs}'
 return f'{c["mnemonic"]}.{c["form"]} v{c["vd"]},{args}'+(',v0.t' if c['mask']!='none' else '')
def instruction(c):
 return ((FUNCT6[c['mnemonic']]+(4 if c['form'].startswith('w') else 0))<<26 | int(c['mask']=='none')<<25 | c['vs2']<<20 | (8 if c['form'].endswith('f') else c['vs1'])<<15 | (5 if c['form'].endswith('f') else 1)<<12 | c['vd']<<7 | 0x57)
def legal(c):
 exp=c['lmul_exp'];nr=max(1,2**exp);dr=max(1,2**(exp+1));wide=c['form'].startswith('w');vf=c['form'].endswith('f');acc=c['mnemonic'] in SIGNS
 assert c['sew']==32 and -1<=exp<=2 and c['group_registers']==dr
 reads=[(c['vs2'],64 if wide else 32,dr if wide else nr)]
 if not vf:reads.append((c['vs1'],32,nr))
 if acc:reads.append((c['vd'],64,dr))
 assert c['vd']%dr==0 and c['vd']+dr<=32 and (c['mask']=='none' or c['vd']!=0)
 for r,e,n in reads:
  assert r%n==0 and r+n<=32
  if max(r,c['vd'])<min(r+n,c['vd']+dr) and e==32:
   assert not acc and exp>=0 and r==c['vd']+dr-n
 for r,e,n in reads:
  for z,t,m in reads:
   assert e==t or max(r,z)>=min(r+n,z+m), 'one source EEW per physical register'
 return True

def initial(c):
 import vadd as v
 raw=bytearray(v.initial(dict(c,family='fpwiden173-baseline')));b=c['vlen']//8
 for reg,key,bits in ((c['vd'],'fp_d',64),(c['vs2'],'fp_a',64 if c['form'].startswith('w') else 32),(c['vs1'],'fp_b',32)):
  n=max(1,2**(c['lmul_exp']+(bits==64)));e=bits//8;k=fp.constants(bits)
  patterns=[k[x] for x in ('one','two','snan','qnan','zero','inf','minsub','maxfinite','negzero','nextone')]
  for i in range(n*b//e):
   word=c.get(key,patterns[i%len(patterns)])
   if 'exception_lane' in c and i!=c['exception_lane']:word=k['zero'] if key=='fp_d' else k['one']
   if 'qemu_vectors' in c:
    values=c['qemu_vectors'][key];word=values[i%len(values)]
   raw[reg*b+i*e:reg*b+(i+1)*e]=word.to_bytes(e,'little')
 raw[:b]=sum(1<<i for i in range(c['vlmax']) if c['mask'] in ('none','all') or c['mask']=='alternating' and i%2==0 or c['mask']=='odd' and i%2==1 or c['mask']=='single-on' and i==min(8,c['vlmax']-1) or c['mask']=='single-off' and i!=min(8,c['vlmax']-1)).to_bytes(b,'little')
 return bytes(raw)
def operands(c,before,i):
 b=c['vlen']//8
 def word(r,e):return int.from_bytes(before[r*b+i*e:r*b+(i+1)*e],'little')
 a=word(c['vs2'],8) if c['form'].startswith('w') else widen(word(c['vs2'],4))
 z=widen(fp.scalar_operand(c) if c['form'].endswith('f') else word(c['vs1'],4))
 return a,z,word(c['vd'],8)
def lane(c,before,i):
 a,z,d=operands(c,before,i);op=c['mnemonic']
 if op in SIGNS:
  np,nc=SIGNS[op];return fused(64,a^(np<<63),z,d^(nc<<63),c['frm'])
 return fp.arithmetic(64,{'vfwadd':'vfadd','vfwsub':'vfsub','vfwmul':'vfmul'}[op],a,z,c['frm'])
def nonfused(c,before,i):
 # Incorrect narrow product before wide accumulation, a common widening/FMA error.
 a,z,d=operands(c,before,i);np,nc=SIGNS[c['mnemonic']]
 _,_,va,_=fp.unpack(64,a);_,_,vz,_=fp.unpack(64,z)
 if va is None or vz is None:return None
 p,fl=fp.rounded(32,(-1 if np else 1)*va*vz,c['frm'])
 r,af=fp.arithmetic(64,'vfadd',widen(p),d^(nc<<63),c['frm']);return r,fl|af

def witnesses(c):
 k=fp.constants(32);d=fp.constants(64);wide=c['form'].startswith('w')
 out=[]
 for name,a,z in fp.pairs(32):out.append((name,widen(a) if wide else a,z,d['half']))
 out += [('negative-zero',d['negzero'] if wide else k['negzero'],k['zero'],d['negzero'])]
 if wide:
  out += [('wide-halfway',d['one'],0x25000000,d['zero']),('wide-negative-halfway',d['negone'],0xa5000000,d['zero']),('wide-overflow',d['maxfinite'],k['maxfinite'],d['zero']),('wide-subnormal',d['minsub'],k['zero'],d['zero'])]
 if c['mnemonic'] in SIGNS:
  out += [('zero-inf-qnan',k['zero'],k['inf'],d['qnan']),('inf-zero-qnan',k['inf'],k['zero'],d['qnan']),('snan-addend',k['one'],k['two'],d['snan']),('wide-subnormal-addend',k['zero'],k['one'],d['minsub']),('destructive-role',k['two'],k['three'],d['half']),('fused-cancel',k['nextone'],k['one']-2,d['negone']),('fused-overflow-rescue',k['maxfinite'],k['two'],widen(k['maxfinite'])^(1<<63)),('wide-halfway',k['one'],k['one'],d['halfulp']),('wide-negative-halfway',k['negone'],k['one'],d['halfulp']^(1<<63))]
 return out

def cases():
 import vadd as v
 rows=[]
 for w in (128,256,512,1024,2048,4096):
  for lm,exp in v.LMUL:
   if not -1<=exp<=2:continue
   n=int(w/32*2**exp);dr=max(1,2**(exp+1));nr=max(1,2**exp)
   for op,forms in FORMS.items():
    for form in forms:
     for rm in range(5):
      prefix=f'{op}-{form}-w{w}-{lm}-rm{rm}-'
      base=dict(family='fpwiden173',mnemonic=op,form=form,vlen=w,sew=32,dest_eew=64,source_emul=lm,dest_emul=v.LMUL[exp+4][0],lmul=lm,lmul_exp=exp,emul=v.LMUL[exp+4][0],vlmax=n,vl=n,vstart=0,mask='none',ta=False,ma=False,vd=8,vs2=16,vs1=24,operand=0x80000001,group_registers=dr,seed=173,frm=rm,fflags_initial=0)
      def add(tag,**kw):
       c=dict(base,tag=tag,**kw);c['id']=prefix+tag;c['unit']=prefix+('start' if c['vstart'] else 'zero');legal(c);rows.append(c)
      for name,a,z,d in witnesses(base):
       add('fp-'+name,vl=1,fp_a=a,fp_b=z,fp_d=d)
       if name in ('snan','zero-inf','zero-inf-qnan','wide-overflow','wide-halfway'):
        add('suppress-'+name,vl=1,mask='off',fp_a=a,fp_b=z,fp_d=d)
      k=fp.constants(32);dk=fp.constants(64)
      for vl in sorted({0,1,n,n-1,max(1,n//2)}|{x for x in (7,8,9,15,16,17) if x<=n}):add('length'+str(vl),vl=vl)
      for mask in ('all','off','alternating','odd','single-on','single-off'):add('mask-'+mask,mask=mask)
      for ta,ma in ((False,True),(True,False),(True,True)):add('policy'+str(int(ta))+str(int(ma)),vl=n-1,mask='alternating',ta=ta,ma=ma)
      add('end-group',vd=32-dr,vs1=4)
      if form in ('vv','wv'):add('same-sources',vs1=16 if form=='vv' else 24)
      if op not in SIGNS and exp>=0:
       if form.startswith('w'):add('wide-dest-source',vd=16)
       else:add('high-overlap-source2',vs2=8+dr-nr)
       if not form.endswith('f'):add('high-overlap-source1',vs1=8+dr-nr)
      for start in sorted({1,n-1}|{x for x in (7,8,9,15,16,17) if 0<x<n}):add('start'+str(start),vstart=start,mask='alternating',ta=True,ma=True)
      for tag,vl,start in (('start-equal',max(1,n//2),max(1,n//2)),('start-above',1,2),('start-zero-vl',0,1)):
       if start<n:add(tag,vl=vl,vstart=start,fflags_initial=9)
      add('tail-exception',vl=1,fp_a=dk['snan'] if form.startswith('w') else k['snan'],fp_b=k['one'],fp_d=dk['zero'],exception_lane=1)
      add('masked-exception',vl=2,mask='alternating',fp_a=dk['snan'] if form.startswith('w') else k['snan'],fp_b=k['one'],fp_d=dk['zero'],exception_lane=1)
      add('prestart-exception',vstart=1,fp_a=dk['snan'] if form.startswith('w') else k['snan'],fp_b=k['one'],fp_d=dk['zero'],exception_lane=0)
      add('sticky-flags',vl=1,fflags_initial=9,fp_a=dk['snan'] if form.startswith('w') else k['snan'],fp_b=k['one'])
      if form.endswith('f'):
       for name in ('one','snan','inf'):add('bad-box-'+name,vl=1,fp_a=dk['one'] if form.startswith('w') else k['one'],fp_b=k[name],bad_box=True)
      vectors=QEMU[op+'_'+form]
      for name,mask in (('partial','none'),('even','alternating'),('odd','odd')):add('qemu-'+name,vl=n-1 if mask=='none' else n,mask=mask,qemu_vectors=vectors,fp_b=vectors['fp_b'][0])
 assert len(rows)==len({c['id'] for c in rows})
 return rows
