#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""RVV1.0 reductions. Rational ordered fold; proven tree-invariant subsets.

Unordered ordinary packets contain only bounded exact dyadic sums or a
homogeneous special-value class. Never compare arbitrary Spike sum bits.
Every finite subset sum is exactly representable at the minimum permitted
precision/range, so all permitted wider node formats produce the same value
and flags. This excludes general inexact unordered sums deliberately.
"""
import struct,json
from pathlib import Path
from fractions import Fraction
from functools import lru_cache
import fp157 as fp
import fpcompare170 as cmp
FORMS=('vfredosum.vs','vfredusum.vs','vfredmin.vs','vfredmax.vs','vfwredosum.vs','vfwredusum.vs')
unpack=lru_cache(maxsize=8192)(fp.unpack)
QEMU=json.loads(Path(__file__).with_name('qemu_fpreduce174.json').read_text())
F6=dict(zip(FORMS,(3,1,5,7,51,49)))
def unordered(c):return 'usum' in c['mnemonic']
def wide(c):return c['mnemonic'].startswith('vfw')
def scalar(c):return 0x123456789abcdef0
def target(c):return c['mnemonic']+f' v{c["vd"]},v{c["vs2"]},v{c["vs1"]}'+(',v0.t' if c['mask']!='none' else '')
def instruction(c):return F6[c['mnemonic']]<<26|int(c['mask']=='none')<<25|c['vs2']<<20|c['vs1']<<15|1<<12|c['vd']<<7|0x57

def validate(c):
 assert c['sew'] in (32,64) and (not wide(c) or c['sew']==32)
 assert c['lmul_exp'] in range(-1 if c['sew']==32 else 0,4)
 assert c['vlmax']==int(Fraction(c['vlen'],c['sew'])*Fraction(2)**c['lmul_exp'])
 assert c['group_registers']==max(1,2**c['lmul_exp'])
 assert c['vs2']%c['group_registers']==0 and c['vs2']+c['group_registers']<=32
 if wide(c):assert not c['vs2']<=c['vs1']<c['vs2']+c['group_registers']
 assert c['mask']=='none' or (c['vs1']!=0 and c['vs2']!=0)
 assert all(0<=c[x]<32 for x in ('vd','vs1'))
 assert 0<=c['vl']<=c['vlmax'] and c['vstart']==0 and c['frm'] in range(5)
 return True

def initial(c):
 import vadd as v
 b=c['vlen']//8;e=c['sew']//8;d=c['dst_eew']//8
 raw=bytearray((r*37+i*13+0x53)&255 for r in range(32) for i in range(b))
 values=c['values']
 for i in range(c['group_registers']*b//e):
  x=values[i%len(values)];raw[c['vs2']*b+i*e:c['vs2']*b+(i+1)*e]=x.to_bytes(e,'little')
 raw[c['vs1']*b:c['vs1']*b+d]=c['seed_word'].to_bytes(d,'little')
 raw[:b]=sum(1<<i for i in range(c['vlmax']) if i%2).to_bytes(b,'little') if c['mask']=='odd' else v.mask_bytes(c)
 return bytes(raw)

def operands(c,before):
 b=c['vlen']//8;e=c['sew']//8;d=c['dst_eew']//8
 seed=int.from_bytes(before[c['vs1']*b:c['vs1']*b+d],'little')
 xs=[int.from_bytes(before[c['vs2']*b+i*e:c['vs2']*b+(i+1)*e],'little') for i in range(c['vl']) if c['mask']=='none' or (before[i//8]>>(i%8)&1)]
 return seed,xs

def promote(c,x):
 if not wide(c):return x,0
 s,k,val,snan=unpack(32,x)
 if k=='nan':return fp.constants(64)['canonical'],16 if snan else 0
 if k=='inf':return s<<63|fp.constants(64)['inf'],0
 return fp.rounded(64,val,c['frm'],s)

@lru_cache(maxsize=65536)
def fold(form,bits,rm,seed,xs):
 acc=seed;flags=0
 for x in xs:
  if 'min' in form or 'max' in form:
   acc,fl=cmp.element(bits,'vfmax' if 'max' in form else 'vfmin',acc,x)
  else:acc,fl=fp.arithmetic(bits,'vfadd',acc,x,rm)
  flags|=fl
 return acc,flags

def allowed(c,before):
 seed,xs=operands(c,before)
 return _allowed(c['mnemonic'],c['sew'],c['dst_eew'],c['frm'],c['fflags_initial'],seed,tuple(xs))

@lru_cache(maxsize=8192)
def _allowed(form,sew,bits,rm,sticky,seed,xs):
 c=dict(mnemonic=form,sew=sew,dst_eew=bits,frm=rm,fflags_initial=sticky);flags=0;ys=[]
 for x in xs:
  y,fl=promote(c,x);ys.append(y);flags|=fl
 if unordered(c) and xs:
  # Prove predicate admission from actual observer prestate, not case labels.
  decoded=[unpack(bits,x) for x in [seed]+ys]
  classes={x[1] for x in decoded}
  if classes=={'finite'}:
   vals=[x[2] for x in decoded];bound=sum(abs(x) for x in vals)
   # All values integral multiples of a common power-of-two quantum. The
   # absolute coefficient sum bounds EVERY subtree, independent of order.
   den=max(x.denominator for x in vals);assert den&(den-1)==0
   coeff=sum(abs(x*den) for x in vals);assert coeff.denominator==1
   assert coeff<=2**(fp.layout(bits)[0]+1)
   assert bound<=unpack(bits,fp.constants(bits)['maxfinite'])[2]
   # Inputs/subtree sums cannot underflow: the quantum is representable.
   assert not bound or Fraction(1,den)>=unpack(bits,1)[2]
  else:
   assert classes<={'finite','nan'} or classes<={'finite','inf'}
   if 'inf' in classes:assert len({x[0] for x in decoded if x[1]=='inf'})==1
   assert all(x[1]!='finite' or x[2]==0 for x in decoded)
 value,fl=fold(c['mnemonic'],bits,c['frm'],seed,tuple(ys));result={(value,c['fflags_initial']|flags|fl)}
 if unordered(c) and not xs:
  s,k,val,snan=unpack(bits,seed)
  if k=='nan':result.add((fp.constants(bits)['canonical'],c['fflags_initial']|(16 if snan else 0)))
 return result

def csr_expected(c,post=False,before=None):
 import vadd as v
 rows=v.csr_expected(c,post);fl=c['fflags_initial']
 if post and c['vl']:fl=next(iter(allowed(c,initial(c) if before is None else before)))[1]
 rows[7:]=[fl,c['frm'],c['frm']<<5|fl];return rows

def check_isa(c,raw,rc=0,timeout=False):
 import vadd as v
 if rc or timeout:raise ValueError('execution/timeout')
 pre,post,before,after=v.decode(c,raw);x=c['operand']&0xffffffff
 if pre!=csr_expected(c)+[x] or before!=initial(c):raise ValueError('reduction prestate/CSR')
 if raw[-16:]!=struct.pack('<2Q',scalar(c),scalar(c)):raise ValueError('scalar FP preservation')
 if post[:7]!=csr_expected(c,True,before)[:7] or post[8]!=c['frm'] or post[9]!=c['frm']<<5|post[7] or post[10]!=x:raise ValueError('post CSR')
 b=c['vlen']//8;e=c['dst_eew']//8;start=c['vd']*b;end=start+b
 if after[:start]!=before[:start] or after[end:]!=before[end:]:raise ValueError('other register preservation')
 if not c['vl']:
  if after!=before or post[7]!=c['fflags_initial']:raise ValueError('VL0 preservation')
 else:
  actual=int.from_bytes(after[start:start+e],'little')
  if (actual,post[7]) not in allowed(c,before):raise ValueError('reduction result/flags')
  for off in range(start+e,end,e):
   if after[off:off+e]!=before[off:off+e] and not(c['ta'] and after[off:off+e]==b'\xff'*e):raise ValueError('scalar destination tail')
 return True

def check_reference(c,raw,reference):
 # Both independent executions must satisfy the mathematical allowed set.
 # Set-valued no-active NaN choices can differ legitimately.
 check_isa(c,raw);check_isa(c,reference)
 return True

def cases():
 rows=[]
 for form in FORMS:
  for w in (128,256,512,1024,2048,4096):
   for bits in ((32,) if form.startswith('vfw') else (32,64)):
    for exp in range(-1 if bits==32 else 0,4):
     lm='mf2' if exp==-1 else 'm'+str(1<<exp);n=int(Fraction(w,bits)*Fraction(2)**exp);dst=bits*2 if form.startswith('vfw') else bits
     prefix=form.replace('.','-')+f'-w{w}-e{bits}-{lm}-';k=fp.constants(bits);dk=fp.constants(dst)
     def add(tag,**kw):
      c=dict(family='fpreduce174',mnemonic=form,form='vs',vlen=w,sew=bits,dst_eew=dst,lmul=lm,lmul_exp=exp,vlmax=n,group_registers=max(1,1<<max(exp,0)),vs2=16,vs1=24,vd=8,operand=0x81234567,seed=174,frm=0,fflags_initial=0,vl=n,vstart=0,mask='none',ta=False,ma=False,values=[k['one'],k['negone'],k['two']],seed_word=dk['one'],tag=tag);c.update(kw);c['id']=prefix+tag;c['unit']=prefix+'zero';validate(c);rows.append(c)
     edges=sorted({0,1,n,n//2,max(0,n-1)}|{x for q in (512//bits,512//dst,w//bits) for x in (q-1,q,q+1) if 0<=x<=n})
     for vl in edges:
      for mask in ('none','all','zero','alternating','odd','single-on','single-off'):
       for ta,ma in ((False,False),(True,True)):
        add(f'state-vl{vl}-{mask}-t{int(ta)}',vl=vl,mask=mask,ta=ta,ma=ma,fflags_initial=8)
     for rm in range(5):
      for name in ('zero','negzero','one','negone','minsub','maxsub','minnormal','inf','neginf','qnan','snan'):
       # Uniform finite subnormal/integer sequences have bounded exact sums.
       vals=[k[name]];seed=dk['zero']
       if name=='negzero':seed=dk['negzero']
       if 'usum' in form and name in ('maxsub','minnormal'):
        # Maxsub * many lanes would round in binary32: explicitly bound to VL1.
        vl=1
       else:vl=n
       add(f'semantic-{name}-rm{rm}',values=vals,seed_word=seed,frm=rm,vl=vl,fflags_initial=4)
       add(f'no-active-{name}-rm{rm}',values=[k['snan']],seed_word=dk[name],mask='zero',frm=rm,fflags_initial=8)
      if 'usum' not in form:
       for name,seed,a,b in [('order-cancel','one','maxfinite','negone'),('opposite-inf','zero','inf','neginf'),('overflow','maxfinite','maxfinite','maxfinite'),('tie','one','halfulp','halfulp'),('nan-seed','snan','one','negone'),('subnormal','minnormal','maxsub','minsub')]:
        add(f'ordered-{name}-rm{rm}',seed_word=dk[seed],values=[k[a],k[b]],frm=rm,vl=min(n,3))
     for rm in range(5):
      for sticky in (0,1,2,8,16,31):
       add(f'sticky-{sticky}-rm{rm}',frm=rm,fflags_initial=sticky,vl=min(3,n))
      if 'usum' not in form:
       big=fp.rounded(bits,Fraction(2)**(fp.layout(dst)[0]+1),0)[0]
       add(f'strict-order-rm{rm}',values=[big,k['one'],big|k['negzero']],seed_word=dk['zero'],frm=rm,vl=min(n,3))
     for lane in sorted({0,min(n-1,512//bits),n-1}):
      for mask in ('single-on','single-off'):
       values=[k['zero']]*n;values[lane]=k['snan']
       add(f'exception-lane{lane}-{mask}',values=values,seed_word=dk['zero'],mask=mask)
     q=QEMU[form][str(bits)]
     if 'usum' in form:
      for i,x in enumerate(q['data']):
       add(f'qemu-bounded-single-{i}',values=[x],seed_word=dk['zero'],vl=1)
      add('qemu-noactive-seed',values=q['data'],seed_word=q['seed'][0],mask='zero')
     else:
      for mask in ('none','alternating','odd'):
       add('qemu-'+mask,values=q['data'],seed_word=q['seed'][0],mask=mask,vl=max(1,min(n,len(q['data'])-1)))
     # Source scalar/destination are one register regardless of LMUL. All
     # overlap forms below are legal, including masked destination v0.
     for vd,vs1 in ((24,24),(16,24),(17,24),(31,31),(0,24),(8,16)):
      if form.startswith('vfw') and vs1==16:continue
      for mask in ('none','alternating'):
       add(f'alias-d{vd}-s{vs1}-{mask}',vd=vd,vs1=vs1,mask=mask,ta=True)
 return rows
