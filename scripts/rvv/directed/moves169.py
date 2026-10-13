#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Scalar-element, FP splat and whole-register transfer predicates (RVV1.0)."""
import inspect,struct
import mask158 as observer
FAMILY='moves169'
FORMS={'vmv':('x.s','s.x'),'vfmv':('f.s','s.f','v.f'),**{f'vmv{n}r':('v',) for n in [1,2,4,8]}}

def cases():
 import vadd as v
 rows=[]
 for w in [128,256,512,1024,2048,4096]:
  for e in [8,16,32,64]:
   for lm,exp in v.LMUL:
    if e>64*2**exp:continue
    n=int(w/e*2**exp)
    for op,forms in FORMS.items():
     if op=='vfmv' and e not in [32,64]:continue
     for form in forms:
      whole=op not in ['vmv','vfmv'];nr=int(op[3]) if whole else 1
      regs=nr if whole else max(1,2**exp) if form=='v.f' else 1
      unit=f'{op}-{form.replace(".","-")}-w{w}-e{e}-{lm}';evl=nr*w//e if whole else n
      def add(tag,**kw):
       c=dict(id=unit+'-'+tag,unit=unit+'-zero',family=FAMILY,mnemonic=op,form=form,kind='whole' if whole else 'splat' if form=='v.f' else 'scalar',nreg=nr,vlen=w,sew=e,lmul=lm,lmul_exp=exp,emul=f'm{nr}' if whole else lm,group_registers=regs,vlmax=n,evl=evl,vl=n,vstart=0,vd=8,vs2=16,vs1=24,rs1=8,rd=9,frs1=8,frd=9,mask='none',ta=False,ma=False,operand=0x81234567,element0=0x87654321812345c2 & ((1<<e)-1),fp_scalar=0xffffffff81234567 if e==32 else 0x8123456787654321,seed=169,tag=tag,vxrm_initial=2,vxsat_initial=1,execution='NOT_RUN')
       c.update(kw)
       if c['vstart']:c['unit']=unit+'-start'
       validate(c);rows.append(c)
      for vl in sorted({0,1,n,n-1,n//2}):add('length'+str(vl),vl=vl)
      for ta,ma in [(False,False),(False,True),(True,False),(True,True)]:add(f'policy{int(ta)}{int(ma)}',vl=max(1,n-1),ta=ta,ma=ma)
      add('end-register',vd=32-regs,vs2=31 if not whole else 32-nr)
      add('destination-v0',vd=0)
      add('source-v0',vs2=0)
      add('csr-clear',vxrm_initial=0,vxsat_initial=0)
      if whole:
       add('self-copy',vd=16)
       add('v0-self-copy',vd=0,vs2=0)
       add('adjacent-groups',vd=16-nr)
       starts={1,evl-1,evl}|{x for x in [w//e-1,w//e,w//e+1,512//e-1,512//e,512//e+1] if 0<x<evl}
       for start in sorted(starts):
        if 0<start<w:add('start'+str(start),vstart=start,vl=0)
       if evl+1<w:add('start-above',vstart=evl+1,vl=0)
       add('start-self',vd=16,vstart=1,vl=0)
      else:
       for s,vl in [(1,0),(1,1),(1,n),(max(1,n//2),max(1,n//2))]:
        if s<w and s<n:add(f'start{s}-vl{vl}',vstart=s,vl=vl)
       if form in ['x.s','s.x']:
        for value in [0,1,0x7fffffff,0x80000000,0xffffffff,0x12345678]:add('integer-'+str(value),operand=value,element0=(value|0x7654321000000000)&((1<<e)-1))
        for value in [0,(1<<(e-1))-1,1<<(e-1),(1<<e)-1]:add('element-'+str(value),element0=value)
        if form=='x.s':
         for rd in [0,8,9]:add('rd'+str(rd),rd=rd)
        else:
         for rs in [0,8,9]:add('rs'+str(rs),rs1=rs)
       else:
        # Transfers preserve payload/sign, including signaling NaNs, without flags.
        vals=[0,1,1<<(e-1),(0x7f800000 if e==32 else 0x7ff0000000000000),(0x7fc12345 if e==32 else 0x7ff8123456789abc),(0x7f812345 if e==32 else 0x7ff0123456789abc),(0xff800000 if e==32 else 0xfff0000000000000)]
        for value in vals:add('fp-'+str(value),element0=value,fp_scalar=value|((0xffffffff<<32) if e==32 else 0))
        if form in ['s.f','v.f'] and e==32:
         for upper in [0,0x7fffffff,0xfffffffe]:add('unboxed-'+str(upper),fp_scalar=upper<<32|0x3f812345)
        for f in [0,8,31]:add('freg'+str(f),frs1=f,frd=f)
      if form=='v.f':
       for start in sorted({1,n-1}|{x for x in [512//e-1,512//e,512//e+1] if x<n}):
        if 0<start<min(n,w):add('splat-start'+str(start),vstart=start,vl=n,ta=True)
 unique={}
 for c in rows:
  if c['id'] in unique:assert unique[c['id']]==c
  unique[c['id']]=c
 return list(unique.values())

def validate(c):
 r=c['group_registers']
 assert c['vd']%r==0 and c['vd']+r<=32
 if c['kind']=='whole':assert c['vs2']%r==0 and c['vs2']+r<=32
 assert 0<=c['vstart']<c['vlen'] and 0<=c['vl']<=c['vlmax']
 assert c['mask']=='none'

def restrictions():
 return [dict(form=op+'.'+form,scenario='vm=0',expected='reserved encoding',execution='NOT_RUN') for op,forms in FORMS.items() for form in forms]+[dict(form='vmvNr.v',scenario='NREG not 1/2/4/8; misaligned/out-of-file groups',expected='reserved encoding',execution='NOT_RUN'),dict(form='vfmv.*',scenario='SEW8/16 unsupported mandatory FP width; invalid selector fields',expected='reserved encoding',execution='NOT_RUN')]

def initial(c):
 b=c['vlen']//8;raw=bytearray((r*37+i*13+0x53)&255 for r in range(32) for i in range(b))
 e=c['sew']//8;raw[c['vs2']*b:c['vs2']*b+e]=c['element0'].to_bytes(e,'little')
 return bytes(raw)

def fprs(c,post=False):
 vals=[(0x4010000000000000+r*0x100000001)&0xffffffffffffffff for r in range(32)]
 vals[c['frs1']]=c['fp_scalar']
 if post and c['form']=='f.s':vals[c['frd']]=c['element0']|(((1<<64)-1)^((1<<c['sew'])-1))
 return vals

def sign_extend(value,bits,to):
 value&=(1<<bits)-1
 return (value-(1<<bits) if value>>(bits-1) else value)&((1<<to)-1)

def scalar_pair(c,post=False):
 pair=[c['operand']&0xffffffff,0x6badcafe]
 if post and c['form']=='x.s' and c['rd']:pair[c['rd']-8]=sign_extend(c['element0'],c['sew'],32)
 return pair

def scalar_value(c):
 if c['form']=='s.x':return sign_extend(0 if c['rs1']==0 else scalar_pair(c)[c['rs1']-8],32,c['sew'])
 value=c['fp_scalar'];e=c['sew']
 return 0x7fc00000 if e==32 and value>>32!=0xffffffff else value&((1<<e)-1)

def packet_size(c):return 616+64*(c['vlen']//8)
def decode(c,raw):
 if len(raw)!=packet_size(c):raise ValueError('missing/extra packet bytes')
 if struct.unpack_from('<2I',raw)!=(0x145add,c['ordinal']):raise ValueError('marker/order')
 b=c['vlen']//8
 return list(struct.unpack_from('<12I',raw,8)),list(struct.unpack_from('<12I',raw,56)),raw[616:616+32*b],raw[616+32*b:]

def check_isa(c,raw,rc=0,timeout=False):
 import vadd as v
 validate(c)
 if rc or timeout:raise ValueError('failed execution/timeout')
 pre,post,before,after=decode(c,raw)
 if pre!=v.csr_expected(c)+scalar_pair(c) or post!=v.csr_expected(c,True)+scalar_pair(c,True):raise ValueError('CSR/scalar result/preservation')
 if list(struct.unpack_from('<32Q',raw,104))!=fprs(c) or list(struct.unpack_from('<32Q',raw,360))!=fprs(c,True):raise ValueError('FP register result/boxing/preservation')
 if before!=initial(c):raise ValueError('pre-register mismatch')
 if c['form'] in ['x.s','f.s']:
  if after!=before:raise ValueError('scalar extraction changed vector state')
  return True
 b=c['vlen']//8;e=c['sew']//8;d=c['vd']*b;extent=c['group_registers']*b
 if after[:d]!=before[:d] or after[d+extent:]!=before[d+extent:]:raise ValueError('non-destination vector preservation')
 if c['kind']=='whole':
  skip=min(c['vstart']*e,extent);expected=before[d:d+skip]+before[c['vs2']*b+skip:c['vs2']*b+extent]
  if after[d:d+extent]!=expected:raise ValueError('whole move/start/independent VL')
  return True
 for i in range(extent//e):
  old=before[d+i*e:d+(i+1)*e];got=after[d+i*e:d+(i+1)*e];ones=b'\xff'*e;allowed={old}
  if c['vstart']<c['vl']:
   if c['kind']=='scalar':
    if i==0 and c['vstart']==0:allowed={scalar_value(c).to_bytes(e,'little')}
    elif i>=c['vstart'] and i>0 and c['ta']:allowed={old,ones}
   elif c['vstart']<=i<c['vl']:allowed={scalar_value(c).to_bytes(e,'little')}
   elif i>=c['vl'] and c['ta']:allowed={old,ones}
  if got not in allowed:raise ValueError('element transfer/splat/tail/prestart '+str(i))
 return True

def check_reference(c,raw,ref):
 check_isa(c,ref)
 _,p,_,a=decode(c,raw);_,rp,_,ra=decode(c,ref)
 if p!=rp or raw[360:616]!=ref[360:616]:raise ValueError('independent scalar/FPR/CSR result')
 b=c['vlen']//8;e=c['sew']//8;d=c['vd']*b
 indices=range(c['vstart'],c['evl']) if c['kind']=='whole' else range(c['vstart'],c['vl']) if c['kind']=='splat' else [0] if c['form'] in ['s.x','s.f'] and c['vstart']==0 and c['vl']>0 else []
 for i in indices:
  if a[d+i*e:d+(i+1)*e]!=ra[d+i*e:d+(i+1)*e]:raise ValueError('independent transferred bytes')
 return True

def target(c):
 op=c['mnemonic'];form=c['form']
 if c['kind']=='whole':return f'{op}.v v{c["vd"]},v{c["vs2"]}'
 lhs=f'x{c["rd"]}' if form=='x.s' else f'f{c["frd"]}' if form=='f.s' else f'v{c["vd"]}'
 rhs=f'v{c["vs2"]}' if form in ['x.s','f.s'] else f'x{c["rs1"]}' if form=='s.x' else f'f{c["frs1"]}'
 return f'{op}.{form} {lhs},{rhs}'
def instruction(c):
 form=c['form']
 if c['kind']=='whole':f6=39;f3=3;vs2=c['vs2'];rs=c['nreg']-1;rd=c['vd']
 else:
  f6=23 if form=='v.f' else 16;f3={'x.s':2,'s.x':6,'f.s':1,'s.f':5,'v.f':5}[form];vs2=c['vs2'] if form in ['x.s','f.s'] else 0;rs=0 if form in ['x.s','f.s'] else c['rs1'] if form=='s.x' else c['frs1'];rd=c['rd'] if form=='x.s' else c['frd'] if form=='f.s' else c['vd']
 return f6<<26|1<<25|vs2<<20|rs<<15|f3<<12|rd<<7|0x57
# Reuse the existing observer body, extending its header with all 32 FPRs.
src=inspect.getsource(observer.assembly).replace('104','616')
src=src.replace("for j,csr in enumerate(v.CSRS):lines += [f'csrr t0,{csr}',f'sw t0,{8+4*j}(a3)']", "lines += [f'la t0,fpr_{tag}']\n        for r in range(32):lines += [f'fld f{r},{8*r}(t0)',f'fsd f{r},{104+8*r}(a3)']\n        for j,csr in enumerate(v.CSRS):lines += [f'csrr t0,{csr}',f'sw t0,{8+4*j}(a3)']")
src=src.replace("for j,csr in enumerate(v.CSRS):lines += [f'csrr t0,{csr}',f'sw t0,{56+4*j}(a3)']", "for r in range(32):lines += [f'fsd f{r},{360+8*r}(a3)']\n        for j,csr in enumerate(v.CSRS):lines += [f'csrr t0,{csr}',f'sw t0,{56+4*j}(a3)']")
src=src.replace("lines += ['.balign 16','.globl begin_signature,end_signature'", "for c in cs:lines += ['.balign 8',f'fpr_{c[\"ordinal\"]}:','.dword '+','.join(map(str,fprs(c)))]\n    lines += ['.balign 16','.globl begin_signature,end_signature'")
exec(compile(src,__file__+' [existing observer + FPR header]','exec'),globals())
def install(v):
 original=v.manifest_cases
 v.manifest_cases=lambda family:cases() if family==FAMILY else original(family)
 for name in ['initial','packet_size','decode','check_isa','check_reference','assembly']:setattr(v,name,globals()[name])
