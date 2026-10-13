#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Whole-register, packed-mask and FOF memory; independent finite ISA predicate."""
import types
import memory165 as m
FAMILY='memory168'
FORMS={}
for nf in [1,2,4,8]:
 for e in [8,16,32,64]:FORMS[f'vl{nf}re{e}.v']=dict(kind='whole',store=False,nf=nf,eew=e)
 FORMS[f'vs{nf}r.v']=dict(kind='whole',store=True,nf=nf,eew=8)
for store in [False,True]:FORMS['vsm.v' if store else 'vlm.v']=dict(kind='mask',store=store,nf=1,eew=8)
for nf in range(1,9):
 for e in [8,16,32,64]:FORMS[('vle' if nf==1 else f'vlseg{nf}e')+str(e)+'ff.v']=dict(kind='fof',store=False,nf=nf,eew=e)

def evl(c):return c['nf']*c['vlen']//c['eew'] if c['kind']=='whole' else (c['vl']+7)//8 if c['kind']=='mask' else c['vl']
def cases():
 import vadd as v
 rows=[]
 for name,form in FORMS.items():
  for w in [128,256,512,1024,2048,4096]:
   for sew in [8,16,32,64]:
    for lm,exp in v.LMUL:
     if sew>64*2**exp:continue
     emexp=exp+(form['eew']//8).bit_length()-(sew//8).bit_length()
     if form['kind']=='fof' and (not -3<=emexp<=3 or 2**emexp*form['nf']>8):continue
     n=int(w/sew*2**exp);r=max(1,2**emexp) if form['kind']=='fof' else 1
     def add(tag,**kw):
      c=dict(id=f'{name}-w{w}-e{sew}-{lm}-{tag}',family=FAMILY,mnemonic=name[:-2],form='v',vlen=w,sew=sew,lmul=lm,lmul_exp=exp,emul_exp=emexp,emul=2**emexp,group_registers=r,destination_registers=r*form['nf'],vlmax=n,vl=n,vstart=0,vd=8,vs2=16,vs1=24,rs1=18,rs2=8,mask='none',ta=False,ma=False,operand=0x168,stride=form['nf']*form['eew']//8,strided=False,seed=168,tag=tag,vxrm_initial=2,vxsat_initial=1,suppress=False,**form)
      c.update(kw);c['unit']=f'{name}-w{w}'+('-start' if c['vstart'] else '-zero');validate(c);rows.append(c)
     add('zero',vl=0);add('partial',vl=max(1,n//2));add('full');add('end-group',vd=32-r*form['nf']);add('policy11',ta=True,ma=True,vl=max(1,n-1))
     if form['kind']=='fof':
      add('mask-even',mask='alternating',vl=max(1,n-1))
      if n>1:add('start',vstart=1,mask='odd')
     else:
      limit=min(w, form['nf']*w//form['eew'] if form['kind']=='whole' else (n+7)//8)
      if limit>1:add('start',vstart=1,vl=0 if form['kind']=='whole' else n)
      # Whole vstart can exceed current VL/VLMAX. Mask start counts bytes.
      if form['kind']=='whole' and n<limit:add('start-above-vlmax',vl=0,vstart=n)
     if sew==form['eew'] and exp==0:
      add('v0-unmasked',vd=0)
      for length in sorted({1,n-1}|{x for x in [7,8,9,63,64,65] if 0<=x<=n}):add('boundary'+str(length),vl=length)
      for ta,ma in [(False,True),(True,False)]:add(f'policy{int(ta)}{int(ma)}',ta=ta,ma=ma,vl=max(1,n-1))
      limit=min(w,evl(dict(form,vlen=w,vl=n)))
      for start in sorted({1,max(1,limit-1),limit//2}|{x for x in [7,8,9,63,64,65] if 0<x<limit}):
       if 0<start<w:add('start'+str(start),vstart=start)
      if form['kind']!='fof' and evl(dict(form,vlen=w,vl=n))<w:add('start-equal-evl',vstart=evl(dict(form,vlen=w,vl=n)))
      add('start-zero-vl',vstart=1,vl=0)
      if form['kind']=='fof':
       for mask in ['all','off','odd','single-on','single-off','byte-pair','chunk-pair','tail-only']:add('mask-'+mask,mask=mask,vl=max(1,n-1))
       add('suppress-all',mask='off',suppress=True);add('suppress-tail',vl=0,suppress=True);add('suppress-start',vstart=1,vl=1,suppress=True)
      elif form['kind']=='mask':add('suppress-tail',vl=0,suppress=True);add('suppress-start',vl=1,vstart=1,suppress=True)
      elif evl(dict(form,vlen=w,vl=n))<w:add('suppress-start',vstart=evl(dict(form,vlen=w,vl=n)),suppress=True)
 return rows

def validate(c):
 assert c['mnemonic']+'.v' in FORMS
 assert c['sew']<=64*2**c['lmul_exp'] and 0<=c['vl']<=c['vlmax'] and 0<=c['vstart']<c['vlen']
 if c['kind']=='fof':
  assert -3<=c['emul_exp']<=3 and c['emul']*c['nf']<=8
  assert c['mask']=='none' or c['vd']!=0
  assert c['vstart']<c['vlmax']
 else:assert c['mask']=='none'
 align=c['nf'] if c['kind']=='whole' else c['group_registers']
 assert c['vd']%align==0 and c['vd']+c['destination_registers']<=32
memory_size=m.memory_size;memory_initial=m.memory_initial;initial=m.initial;packet_size=m.packet_size;decode=m.decode

def address(c,i,f):return c.get('guard_base',128)+i*(c['nf'] if c['kind']=='fof' else 1)*(c['eew']//8)+f*c['eew']//8
def regoff(c,i,f):return c['vd']*(c['vlen']//8)+i*c['eew']//8+(f*c['group_registers']*(c['vlen']//8) if c['kind']=='fof' else 0)
def enabled(c,before,i):return c['vstart']<=i<evl(c) and (c['mask']=='none' or m.enabled(c,before,i))
def check_isa(c,raw,rc=0,timeout=False):
 import vadd as v
 if rc or timeout:raise ValueError('failed execution/timeout')
 validate(c);pre,post,before,after,mem,gotmem=decode(c,raw);pair=[c['operand']&0xffffffff,0x6badcafe]
 expected=v.csr_expected(c,True)+pair
 newvl=post[0]
 if c['kind']=='fof':
  minimum=1 if c['vstart']==0 and c['vl']>0 else 0
  if not minimum<=newvl<=c['vl']:raise ValueError('FOF invalid new vl')
  if c.get('fault_index') is not None and newvl>c['fault_index']:raise ValueError('FOF failed to trim before denied segment')
  if c['vstart']>=c['vl'] and newvl!=c['vl']:raise ValueError('FOF no-access vl changed')
  expected[0]=newvl
 if pre!=v.csr_expected(c)+pair or post!=expected:raise ValueError('CSR/scalar preservation mismatch')
 if before!=initial(c) or mem!=memory_initial(c):raise ValueError('independent initial register/buffer mismatch')
 out=bytearray(before);outmem=bytearray(mem);e=c['eew']//8;b=c['vlen']//8
 if c['store']:
  if before!=after:raise ValueError('store register preservation')
  for i in range(c['vstart'],evl(c)):
   p=address(c,i,0);q=regoff(c,i,0);outmem[p:p+e]=before[q:q+e]
  if gotmem!=outmem:raise ValueError('packed/whole exact store footprint or value')
 else:
  if gotmem!=mem:raise ValueError('load memory preservation')
  fields=c['nf'] if c['kind']=='fof' else 1
  capacity=c['group_registers']*b//e if c['kind']=='fof' else c['destination_registers']*b//e
  for f in range(fields):
   for i in range(capacity):
    q=regoff(c,i,f);old=before[q:q+e];got=after[q:q+e]
    active=enabled(c,before,i);value=mem[address(c,i,f):address(c,i,f)+e] if active else old
    # Only originally active elements between trimmed and original VL can be arbitrary.
    spurious=c['kind']=='fof' and active and newvl<=i<c['vl']
    tail=(i>=evl(c) and (c['kind']=='mask' or c['ta']))
    inactive=c['kind']=='fof' and i<newvl and not active and c['ma']
    agnostic=c['vstart']<evl(c) and i>=c['vstart'] and (tail or inactive)
    if not spurious and got!=value and not (agnostic and got==b'\xff'*e):raise ValueError(f'load field{f} element{i}: {got.hex()} != {value.hex()}')
    out[q:q+e]=got
  if after!=out:raise ValueError('non-destination preservation')
 return True

def check_reference(c,raw,reference):
 a=decode(c,raw);r=decode(c,reference)
 if a[0]!=r[0] or a[2]!=r[2] or a[4]!=r[4]:raise ValueError('reference input mismatch')
 if c['store']:
  if a[5]!=r[5]:raise ValueError('reference store mismatch')
 else:
  count=min(a[1][0],r[1][0]) if c['kind']=='fof' else evl(c)
  for i in range(c['vstart'],count):
   if enabled(c,a[2],i):
    for f in range(c['nf'] if c['kind']=='fof' else 1):
     q=regoff(c,i,f);e=c['eew']//8
     if a[3][q:q+e]!=r[3][q:q+e]:raise ValueError('independent active load mismatch')
 return True

def target(c):return f'{c["mnemonic"]}.v v{c["vd"]},(s2)'+(',v0.t' if c['mask']!='none' else '')
def instruction(c):
 op=8 if c['kind']=='whole' else 11 if c['kind']=='mask' else 16
 return (c['nf']-1)<<29|int(c['mask']=='none')<<25|op<<20|18<<15|{8:0,16:5,32:6,64:7}[c['eew']]<<12|c['vd']<<7|(0x27 if c['store'] else 7)
assembly=types.FunctionType(m.assembly.__code__,dict(m.assembly.__globals__,initial=initial,target=target,base_offset=lambda c:c.get('guard_base',128)))
def install(v):
 old=v.manifest_cases;v.manifest_cases=lambda family:cases() if family==FAMILY else old(family)
 for name in ['initial','packet_size','decode','check_isa','check_reference','assembly']:setattr(v,name,globals()[name])
