#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Ratified prefix/index predicates; independent executed references required."""
import inspect,struct
import mask158 as observer
FAMILY='prefix169'
PREFIX=('vmsbf','vmsif','vmsof')
FORMS={op:('m',) for op in (*PREFIX,'viota')}|{'vid':('v',)}

def cases():
 import vadd as v
 rows=[]
 for w in [128,256,512,1024,2048,4096]:
  for e in [8,16,32,64]:
   for lm,exp in v.LMUL:
    if e>64*2**exp:continue
    n=int(w/e*2**exp);regs=max(1,2**exp)
    for op in FORMS:
     unit=f'{op}-w{w}-e{e}-{lm}'
     def add(tag,**kw):
      c=dict(id=unit+'-'+tag,unit=unit+'-zero',family=FAMILY,mnemonic=op,form=FORMS[op][0],vlen=w,sew=e,lmul=lm,lmul_exp=exp,emul='m1' if op in PREFIX else lm,group_registers=1 if op in PREFIX else regs,vlmax=n,vl=n,vstart=0,vd=8,vs2=17,vs1=25,rd=9,mask='none',ta=False,ma=False,operand=0x81234567,seed=169,tag=tag,source_pattern='even',vxrm_initial=2,vxsat_initial=1,execution='NOT_RUN')
      c.update(kw)
      if c['vstart']:c['unit']=unit+'-start'
      validate(c);rows.append(c)
     for vl in sorted({0,1,n,n-1,n//2}|{i for i in [7,8,9,31,32,33,63,64,65,255,256,257,511,512,513] if i<=n}):add('length'+str(vl),vl=vl)
     for ta,ma in [(False,False),(False,True),(True,False),(True,True)]:add(f'policy{int(ta)}{int(ma)}',vl=max(1,n-1),mask='alternating',ta=ta,ma=ma)
     for mask in ['all','off','alternating','odd','single-on','single-off']:
      for pattern in ['off','all','even','odd']:add('mask-'+mask+'-source-'+pattern,mask=mask,source_pattern=pattern)
     for bit in sorted({0,n-1}|{i for i in [7,8,31,32,63,64,255,256,511,512] if i<n}):
      add('first'+str(bit),source_pattern='single',source_bit=bit)
      add('excluded-first'+str(bit),source_pattern='single',source_bit=bit,mask='odd' if bit%2==0 else 'alternating')
      add('tail-hit'+str(bit),source_pattern='single',source_bit=bit,vl=bit)
     add('source-v0',vs2=0)
     add('source-v0-masked',vs2=0,mask='alternating') # both reads EEW1
     add('destination-v0',vd=0)
     add('end-register',vd=31 if op in PREFIX else 32-regs)
     add('csr-clear',vxrm_initial=0,vxsat_initial=0)
     if op=='vid':
      for s in sorted({1,n-1}|{i for i in [7,8,31,32,63,64,511,512] if i<n}):
       if 0<s<min(n,w):add('start'+str(s),vstart=s,mask='alternating',ta=True,ma=True)
      if n>1:
       add('start-vl0',vstart=1,vl=0)
       add('start-equal',vstart=max(1,n//2),vl=max(1,n//2))
 return rows

def validate(c):
 op=c['mnemonic'];r=c['group_registers'];d=c['vd'];s=c['vs2']
 assert d%r==0 and d+r<=32
 if op!='vid':assert not d<=s<d+r
 if c['mask']!='none':assert d!=0
 if op!='vid':assert c['vstart']==0
 assert 0<=c['vstart']<min(c['vlmax'],c['vlen']) and 0<=c['vl']<=c['vlmax']

def restrictions():
 return [dict(form=op+'.m',vstart=s,vl=vl,execution='NOT_RUN',expected='illegal instruction',trap_state='BLOCKED exit-only observer') for op in (*PREFIX,'viota') for s,vl in [(1,0),(1,1),(7,4)]]+[dict(form=op+'.m',scenario='destination overlaps source or masked v0',execution='NOT_RUN',expected='reserved encoding') for op in (*PREFIX,'viota')]+[dict(form='vid.v',scenario='vs2 nonzero; masked destination v0; unaligned/out-of-file groups',execution='NOT_RUN',expected='reserved encoding')]

bit=observer.bit
packet_size=observer.packet_size
decode=observer.decode

def initial(c):
 b=c['vlen']//8;w=c['vlen'];raw=bytearray((r*37+i*13+0x53)&255 for r in range(32) for i in range(b))
 p=c['source_pattern'];src=sum(1<<i for i in range(w) if p=='all' or p=='even' and i%2==0 or p=='odd' and i%2==1 or p=='single' and i==c['source_bit'])
 raw[c['vs2']*b:(c['vs2']+1)*b]=src.to_bytes(b,'little')
 m=c['mask'];boundary=min(c['vlmax']-1,512)
 if c['vs2']==0 and m=='none':return bytes(raw)
 bits=sum(1<<i for i in range(w) if m in ['all','none'] or m=='alternating' and i%2==0 or m=='odd' and i%2 or m=='single-on' and i==boundary or m=='single-off' and i!=boundary)
 raw[:b]=bits.to_bytes(b,'little')
 return bytes(raw)

def scalar_pair(c,post=False):return [c['operand']&0xffffffff,0x6badcafe]

def values(c,before,limit):
 b=c['vlen']//8;hits=0;out=[];op=c['mnemonic']
 for i in range(limit):
  enabled=c['mask']=='none' or bit(before,0,i,b)
  hit=bool(bit(before,c['vs2'],i,b) and enabled)
  out.append(int(hits==0 and not hit) if op=='vmsbf' else int(hits==0) if op=='vmsif' else int(hits==0 and hit) if op=='vmsof' else hits if op=='viota' else i)
  hits+=hit
 return out

def check_isa(c,raw,rc=0,timeout=False):
 import vadd as v
 validate(c)
 if rc or timeout:raise ValueError('failed execution/timeout')
 pre,post,before,after=decode(c,raw)
 if pre!=v.csr_expected(c)+scalar_pair(c) or post!=v.csr_expected(c,True)+scalar_pair(c):raise ValueError('CSR/scalar preservation')
 if before!=initial(c):raise ValueError('pre-register mismatch')
 b=c['vlen']//8;d=c['vd']*b;r=c['group_registers'];op=c['mnemonic'];e=c['sew']//8;end=d+r*b
 if after[:d]!=before[:d] or after[end:]!=before[end:]:raise ValueError('non-destination preservation')
 vals=values(c,before,c['vlen'] if op in PREFIX else c['vlmax'])
 for i in range(c['vlen'] if op in PREFIX else r*b//e):
  old=bit(before,c['vd'],i,b) if op in PREFIX else int.from_bytes(before[d+i*e:d+(i+1)*e],'little')
  got=bit(after,c['vd'],i,b) if op in PREFIX else int.from_bytes(after[d+i*e:d+(i+1)*e],'little')
  ones=1 if op in PREFIX else (1<<c['sew'])-1
  allowed={old}
  if c['vstart']<c['vl'] and i>=c['vstart']:
   if i<c['vl']:
    allowed={vals[i]&ones} if c['mask']=='none' or bit(before,0,i,b) else {old,ones} if c['ma'] else {old}
   elif op in PREFIX:allowed={old,1,vals[i]}
   elif c['ta']:allowed={old,ones}
  if got not in allowed:raise ValueError('prefix/index result/policy '+str(i))
 return True

def check_reference(c,raw,ref):
 check_isa(c,ref)
 _,p,b,a=decode(c,raw);_,rp,_,ra=decode(c,ref)
 if p!=rp:raise ValueError('independent CSR/scalar mismatch')
 size=c['vlen']//8;e=c['sew']//8;d=c['vd']*size
 for i in range(c['vstart'],c['vl']):
  if c['mask']!='none' and not bit(b,0,i,size):continue
  x=bit(a,c['vd'],i,size) if c['mnemonic'] in PREFIX else a[d+i*e:d+(i+1)*e]
  y=bit(ra,c['vd'],i,size) if c['mnemonic'] in PREFIX else ra[d+i*e:d+(i+1)*e]
  if x!=y:raise ValueError('independent active result')
 return True

def target(c):return c['mnemonic']+'.'+c['form']+f' v{c["vd"]}'+('' if c['mnemonic']=='vid' else f',v{c["vs2"]}')+(',v0.t' if c['mask']!='none' else '')
def instruction(c):return (17 if c['mnemonic']=='vid' else 16 if c['mnemonic']=='viota' else {'vmsbf':1,'vmsif':3,'vmsof':2}[c['mnemonic']])<<15 | (0 if c['mnemonic']=='vid' else c['vs2'])<<20 | int(c['mask']=='none')<<25 | 20<<26 | 2<<12 | c['vd']<<7 | 0x57
# Rebind the reviewed full-vector/CSR/x8/x9 observer, without changing Task158.
exec(compile(inspect.getsource(observer.assembly),__file__+' [existing observer]','exec'),globals())
def install(v):
 original=v.manifest_cases
 v.manifest_cases=lambda family:cases() if family==FAMILY else original(family)
 for name in ['initial','packet_size','decode','check_isa','check_reference','assembly']:setattr(v,name,globals()[name])
