#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite normal/widening integer reductions; answers come from pinned references.

Scalar operands/results occupy one register regardless of source LMUL. Reduction
vstart is zero only. No trap handler, return, retry or DUT-derived golden.
"""
import struct
import permute162 as capture
FAMILY='reduction163'
FORMS={op:('vs',) for op in ['vredsum','vredand','vredor','vredxor','vredminu','vredmin','vredmaxu','vredmax','vwredsumu','vwredsum']}
FUNCT6=dict(vredsum=0,vredand=1,vredor=2,vredxor=3,vredminu=4,vredmin=5,vredmaxu=6,vredmax=7,vwredsumu=48,vwredsum=49)

def cases():
 import vadd as v
 rows=[]
 for w in [128,256,512,1024,2048,4096]:
  for e in [8,16,32,64]:
   for lm,exp in v.LMUL:
    if e>64*2**exp:continue
    n=int(w/e*2**exp);regs=max(1,2**exp);chunk=512//e
    for op in FORMS:
     wide=op.startswith('vw');ee=e*(2 if wide else 1)
     if ee>64:continue
     unit=f'{op}-vs-w{w}-e{e}-{lm}'
     def add(tag,**kw):
      c=dict(id=unit+'-'+tag,unit=unit+'-zero',family=FAMILY,mnemonic=op,form='vs',vlen=w,sew=e,result_eew=ee,lmul=lm,lmul_exp=exp,emul=lm,group_registers=regs,destination_registers=1,scalar_emul=1,vlmax=n,vl=n,vstart=0,vd=8,vs2=16,vs1=25,rs1=8,mask='none',ta=False,ma=False,operand=0x81234567,seed=163,tag=tag,data_pattern='boundary',accumulator='mixed',vxrm_initial=2,vxsat_initial=1,execution='NOT_RUN')
      c.update(kw);validate(c);rows.append(c)
     for vl in sorted({0,1,n,n-1,n//2}|{x for x in [7,8,9,chunk-1,chunk,chunk+1] if 0<=x<=n}):add('length'+str(vl),vl=vl)
     for ta,ma in [(False,False),(False,True),(True,False),(True,True)]:
      add(f'policy{int(ta)}{int(ma)}',vl=max(1,n-1),mask='alternating',ta=ta,ma=ma)
      add(f'zero-policy{int(ta)}{int(ma)}',vl=0,mask='off',ta=ta,ma=ma)
      add(f'empty-policy{int(ta)}{int(ma)}',mask='off',ta=ta,ma=ma)
     for mask in ['all','off','alternating','odd','single-on','single-off','chunk-pair','byte-pair','tail-only']:
      add('mask-'+mask,mask=mask,vl=max(1,n-1) if mask=='tail-only' else n)
     for p in ['zeros','ones','signed-min','signed-max','unsigned-max','boundary','position','last-extreme']:
      add('data-'+p,data_pattern=p,accumulator='zero')
      add('data-masked-'+p,data_pattern=p,mask='odd',accumulator='ones')
     for acc in ['zero','ones','signed-min','signed-max','mixed','upper-only']:
      add('acc-'+acc,accumulator=acc,vl=1)
      add('empty-acc-'+acc,accumulator=acc,mask='off',ma=True)
     add('csr-clear',vxrm_initial=0,vxsat_initial=0)
     add('end-register',vd=31,vs1=7)
     add('unaligned-scalars',vd=9,vs1=27)
     # Reduction-specific destination overlap is allowed at any position.
     for ta in [False,True]:
      for name,d in [('dest-source-first',16),('dest-source-last',16+regs-1),('dest-accumulator',25),('dest-mask',0)]:
       add(name+'-ta'+str(int(ta)),vd=d,mask='alternating',ta=ta,ma=True)
     add('source-v0',vs2=0)
     add('accumulator-v0',vs1=0)
     add('dest-v0-unmasked',vd=0)
     if not wide:
      add('same-sources',vs1=16)
      add('all-alias',vd=16,vs1=16)
 return rows

def validate(c):
 assert c['mnemonic'] in FORMS and c['form']=='vs'
 assert c['vstart']==0,'reduction nonzero vstart is illegal, not arithmetic'
 assert c['result_eew']==c['sew']*(2 if c['mnemonic'].startswith('vw') else 1)<=64
 assert c['sew']<=64*2**c['lmul_exp'] and c['group_registers']==max(1,2**c['lmul_exp'])
 r=c['group_registers'];assert c['vs2']%r==0 and c['vs2']+r<=32
 assert 0<=c['vd']<32 and 0<=c['vs1']<32 and c['destination_registers']==c['scalar_emul']==1
 assert 0<=c['vl']<=c['vlmax']
 if c['mnemonic'].startswith('vw'):assert not c['vs2']<=c['vs1']<c['vs2']+r,'different EEW scalar/data reads excluded'

def restrictions():
 out=[]
 for op in FORMS:
  for start,vl in [(1,0),(1,1),(7,4),(8,8)]:
   out.append(dict(form=op+'.vs',vstart=start,vl=vl,expected='illegal instruction; reduction traps report vstart=0',execution='NOT_RUN',ordinary_arithmetic=False))
  out.append(dict(form=op+'.vs',scenario='nonaligned/out-of-file data group or unsupported vtype',expected='reserved/unsupported',execution='NOT_RUN'))
  if op.startswith('vw'):
   out.append(dict(form=op+'.vs',scenario='SEW64 would require EEW128 beyond pinned ELEN64',expected='unsupported',execution='NOT_RUN'))
   out.append(dict(form=op+'.vs',scenario='different-EEW vs1/vs2 source alias',expected='excluded conservative source-read geometry',execution='NOT_RUN'))
 return out

def initial(c):
 b=c['vlen']//8;e=c['sew']//8;ee=c['result_eew']//8;n=c['vlmax'];limit=(1<<c['sew'])-1;sign=1<<(c['sew']-1)
 raw=bytearray((r*37+i*13+0x53)&255 for r in range(32) for i in range(b))
 for i in range(n):
  p=c['data_pattern'];boundary=[0,1,limit,sign,sign-1,sign+1,limit-1,0x55&limit,0xaa&limit]
  value={'zeros':0,'ones':1,'signed-min':sign,'signed-max':sign-1,'unsigned-max':limit,'position':(i*73+0x35)^(i>>8),'last-extreme':limit if i==n-1 else 0}.get(p,boundary[i%len(boundary)])&limit
  raw[c['vs2']*b+i*e:c['vs2']*b+(i+1)*e]=value.to_bytes(e,'little')
 # Identical-source scenarios use their actual shared element zero as seed.
 if not c['vs2']<=c['vs1']<c['vs2']+c['group_registers']:
  lim=(1<<c['result_eew'])-1;sgn=1<<(c['result_eew']-1)
  acc={'zero':0,'ones':lim,'signed-min':sgn,'signed-max':sgn-1,'mixed':0x87654321a5c3e719&lim,'upper-only':1<<c['sew'] if c['result_eew']>c['sew'] else sgn}[c['accumulator']]
  raw[c['vs1']*b:c['vs1']*b+ee]=acc.to_bytes(ee,'little')
 # Unmasked v0 source/scalar cases preserve those inputs. Mask is initialized
 # last only when it is a distinct operand. Destination v0 is explicitly legal.
 if c['vs2']!=0 and c['vs1']!=0:
  raw[:b]=capture.bits(c['mask'],c['vlen'],c['vl'],512//c['sew']).to_bytes(b,'little')
 return bytes(raw)

def enabled(c,before,i):return i<c['vl'] and (c['mask']=='none' or capture.bit(before,0,i,c['vlen']//8))

def result(c,before):
 b=c['vlen']//8;e=c['sew']//8;ee=c['result_eew']//8;mod=1<<c['result_eew'];op=c['mnemonic']
 acc=int.from_bytes(before[c['vs1']*b:c['vs1']*b+ee],'little')
 def signed(x,bits):return x-(1<<bits) if x&(1<<(bits-1)) else x
 for i in range(c['vl']):
  if not enabled(c,before,i):continue
  x=int.from_bytes(before[c['vs2']*b+i*e:c['vs2']*b+(i+1)*e],'little')
  if op in ['vredsum','vwredsumu','vwredsum']:acc=(acc+(signed(x,c['sew']) if op=='vwredsum' else x))%mod
  elif op=='vredand':acc&=x
  elif op=='vredor':acc|=x
  elif op=='vredxor':acc^=x
  elif op in ['vredmin','vredmax']:
   a,z=signed(acc,c['sew']),signed(x,c['sew']);acc=(min(a,z) if op=='vredmin' else max(a,z))%mod
  elif op=='vredminu':acc=min(acc,x)
  elif op=='vredmaxu':acc=max(acc,x)
 return acc.to_bytes(ee,'little')

packet_size=capture.packet_size
decode=capture.decode

def check_isa(c,raw,rc=0,timeout=False):
 import vadd as v
 if rc or timeout:raise ValueError('failed execution/timeout')
 validate(c);pre,post,before,after=decode(c,raw);pair=[c['operand']&0xffffffff,0x6badcafe]
 if pre!=v.csr_expected(c)+pair or post!=v.csr_expected(c,True)+pair:raise ValueError('CSR/scalar preservation mismatch')
 if before!=initial(c):raise ValueError('pre-register mismatch')
 b=c['vlen']//8;e=c['result_eew']//8;d=c['vd']*b
 if after[:d]!=before[:d] or after[d+b:]!=before[d+b:]:raise ValueError('preserved non-destination register')
 if c['vl']==0:
  if after!=before:raise ValueError('zero VL destination preservation')
  return True
 if after[d:d+e]!=result(c,before):raise ValueError('reduction element zero result')
 for off in range(d+e,d+b,e):
  got=after[off:off+e];old=before[off:off+e]
  if got!=old and not (c['ta'] and got==b'\xff'*e):raise ValueError('destination tail preservation/allowed set')
 return True

def check_reference(c,raw,reference):
 a=decode(c,raw);r=decode(c,reference)
 if a[1]!=r[1]:raise ValueError('independent CSR/scalar mismatch')
 if c['vl']:
  d=c['vd']*(c['vlen']//8);e=c['result_eew']//8
  if a[3][d:d+e]!=r[3][d:d+e]:raise ValueError('independent reduction result mismatch')
 return True

def target(c):return f'{c["mnemonic"]}.vs v{c["vd"]},v{c["vs2"]},v{c["vs1"]}'+(',v0.t' if c['mask']!='none' else '')
def instruction(c):return FUNCT6[c['mnemonic']]<<26|int(c['mask']=='none')<<25|c['vs2']<<20|c['vs1']<<15|(0 if c['mnemonic'].startswith('vw') else 2)<<12|c['vd']<<7|0x57

def assembly(cs):
 # Bind a private globals dictionary for the established capture function.
 # Builds run in threads; no shared module globals are mutated.
 import types
 observer=types.FunctionType(capture.assembly.__code__,dict(capture.assembly.__globals__,initial=initial,target=target))
 return observer(cs)

def install(v):
 original=v.manifest_cases
 v.manifest_cases=lambda family:cases() if family==FAMILY else original(family)
 for name in ['initial','packet_size','decode','check_isa','check_reference','assembly']:setattr(v,name,globals()[name])
