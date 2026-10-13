#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Disjoint Task175 movement and narrowing shifts; exact integer bit predicates."""
import struct
from functools import lru_cache
import fp157 as fp
import fpslide175_next as slide
FORMS={'fpslide175':slide.FORMS,'fpmerge175':('vfmerge.vfm',),'narrow175':tuple(op+'.'+form for op in ('vnsrl','vnsra') for form in ('wv','wx','wi'))}
def isfp(c):return c['family']!='narrow175'
def scalar(c):return fp.scalar(dict(c,family='gap175-baseline'))
def target(c):
 op=c['mnemonic'];rhs='fs0' if isfp(c) else f'v{c["vs1"]}' if c['form']=='wv' else 's0' if c['form']=='wx' else str(c['operand'])
 return f'{op}.{c["form"]} v{c["vd"]},v{c["vs2"]},{rhs}'+(',v0' if op=='vfmerge' else ',v0.t' if c['mask']!='none' else '')
def instruction(c):
 funct={'vfslide1up':14,'vfslide1down':15,'vfmerge':23,'vnsrl':44,'vnsra':45}[c['mnemonic']]
 rhs=8 if isfp(c) or c['form']=='wx' else c['vs1'] if c['form']=='wv' else c['operand']&31
 f3=5 if isfp(c) else {'wv':0,'wx':4,'wi':3}[c['form']]
 return funct<<26|int(c['mask']=='none' and c['mnemonic']!='vfmerge')<<25|c['vs2']<<20|rhs<<15|f3<<12|c['vd']<<7|0x57
@lru_cache(maxsize=8192)
def initial_cached(key):
 c=dict(key);import vadd as v
 raw=bytearray(v.initial(dict(c,family='gap175-baseline')));b,e=c['vlen']//8,c['sew']//8;n=c['vlmax'];wide=not isfp(c)
 values=c.get('values')
 if values is None:
  if isfp(c):values=tuple(fp.constants(c['sew']).values())
  else:
   bits=c['sew']*2;values=(0,1,(1<<bits)-1,1<<(bits-1),(1<<(bits-1))-1,0x76543210abcdef01&((1<<bits)-1),0xaaaaaaaaaaaaaaaa&((1<<bits)-1))
 ee=e*(2 if wide else 1)
 for i in range(c['src_registers']*b//ee):
  val=values[i%len(values)]^(i//len(values) if c.get('unique') else 0)
  raw[c['vs2']*b+i*ee:c['vs2']*b+(i+1)*ee]=val.to_bytes(ee,'little')
 if wide and c['form']=='wv':
  for i in range(c['group_registers']*b//e):
   val=(c['shift_values'][i%len(c['shift_values'])] if c.get('shift_values') else i*7+c['operand'])&((1<<c['sew'])-1)
   raw[c['vs1']*b+i*e:c['vs1']*b+(i+1)*e]=val.to_bytes(e,'little')
 raw[:b]=(int(c['mask_bits']).to_bytes(b,'little') if 'mask_bits' in c else sum(1<<i for i in range(n) if i%2).to_bytes(b,'little') if c['mask']=='odd' else v.mask_bytes(c))
 return bytes(raw)
def initial(c):
 # Exclude names/ordinals from the physical prestate cache.
 keys=('family','vlen','sew','vlmax','mask','vs2','vs1','src_registers','group_registers','form','operand','unique','values','shift_values','mask_bits','seed')
 return initial_cached(tuple((k,tuple(c[k]) if isinstance(c[k],list) else c[k]) for k in keys if k in c))
def active(c,before,i):
 return c['vstart']<=i<c['vl'] and (c['mnemonic']=='vfmerge' or c['mask']=='none' or bool(before[i//8]&(1<<(i%8))))
def lane(c,before,i):
 b,e=c['vlen']//8,c['sew']//8;op=c['mnemonic']
 def src(j,ee=e):return int.from_bytes(before[c['vs2']*b+j*ee:c['vs2']*b+(j+1)*ee],'little')
 if op=='vfmerge':return slide.scalar_bits(c['sew'],scalar(c)) if before[i//8]&(1<<(i%8)) else src(i)
 if op=='vfslide1up':return slide.scalar_bits(c['sew'],scalar(c)) if i==0 else src(i-1)
 if op=='vfslide1down':return slide.scalar_bits(c['sew'],scalar(c)) if i==c['vl']-1 else src(i+1)
 bits=c['sew']*2;a=src(i,e*2)
 shift=int.from_bytes(before[c['vs1']*b+i*e:c['vs1']*b+(i+1)*e],'little') if c['form']=='wv' else c['operand']&0xffffffff
 if op=='vnsra' and a>>(bits-1):a-=1<<bits
 return (a>>(shift&(bits-1)))&((1<<c['sew'])-1)
def csr_expected(c,post=False):
 import vadd as v
 rows=v.csr_expected(c,post);rows[7:]=[c['fflags_initial'],c['frm'],c['frm']<<5|c['fflags_initial']];return rows
def check_isa(c,raw,rc=0,timeout=False):
 import vadd as v
 if rc or timeout:raise ValueError('execution/timeout')
 pre,post,before,after=v.decode(c,raw);x=c['operand']&0xffffffff
 if pre!=csr_expected(c)+[x] or post!=csr_expected(c,True)+[x]:raise ValueError('CSR/flags/scalar')
 if raw[-16:]!=struct.pack('<2Q',scalar(c),scalar(c)):raise ValueError('raw FP scalar preservation')
 if before!=initial(c):raise ValueError('prestate')
 b,e=c['vlen']//8,c['sew']//8;lo=c['vd']*b;hi=lo+c['group_registers']*b
 if after[:lo]!=before[:lo] or after[hi:]!=before[hi:]:raise ValueError('other vector register')
 for i in range((hi-lo)//e):
  old=before[lo+i*e:lo+(i+1)*e];out=after[lo+i*e:lo+(i+1)*e]
  if active(c,before,i):
   if out!=lane(c,before,i).to_bytes(e,'little'):raise ValueError('active result '+str(i))
  else:
   agnostic=c['vstart']<c['vl'] and i>=c['vstart'] and ((i>=c['vl'] and c['ta']) or (i<c['vl'] and c['ma'] and c['mnemonic']!='vfmerge'))
   if out!=old and not (agnostic and out==b'\xff'*e):raise ValueError('preserved element '+str(i))
 return True
def check_reference(c,raw,reference):
 import vadd as v
 check_isa(c,raw);check_isa(c,reference)
 _,_,before,after=v.decode(c,raw);_,_,_,ref=v.decode(c,reference);b,e=c['vlen']//8,c['sew']//8
 for i in range(c['vstart'],c['vl']):
  if active(c,before,i):
   off=c['vd']*b+i*e
   if after[off:off+e]!=ref[off:off+e]:raise ValueError('independent reference')
 return True
def validate(c):
 assert c['src_registers']<=8 and c['vs2']%c['src_registers']==0 and c['vd']%c['group_registers']==0
 assert c['vs2']+c['src_registers']<=32 and c['vd']+c['group_registers']<=32
 if c['mnemonic']=='vfslide1up':assert not (c['vd']<c['vs2']+c['src_registers'] and c['vs2']<c['vd']+c['group_registers'])
 assert c['mask']=='none' or c['vd']!=0
 assert c['vstart']<c['vlen']
def cases(family):
 import vadd as v
 rows=[]
 for full in FORMS[family]:
  op,form=full.split('.')
  for w in (128,256,512,1024,2048,4096):
   for sew in ((8,16,32) if family=='narrow175' else (32,64)):
    for lm,exp in v.LMUL:
     if sew>64*2**exp or (family=='narrow175' and exp>2):continue
     n=int(w//sew*2**exp);regs=max(1,2**exp);sr=max(1,2**(exp+(family=='narrow175')));chunk=512//sew
     prefix=f'{op}-{form}-w{w}-e{sew}-{lm}'
     def add(tag,**kw):
      c=dict(family=family,mnemonic=op,form=form,vlen=w,sew=sew,lmul=lm,lmul_exp=exp,emul=lm,vlmax=n,vl=n,mask='alternating' if op=='vfmerge' else 'none',ta=False,ma=False,vstart=0,vd=8,vs2=16,vs1=24,operand=3,group_registers=regs,src_registers=sr,seed=175,frm=0,fflags_initial=21,unique=True)
      c.update(kw);c['tag']=tag;c['id']=prefix+'-'+tag;c['unit']=prefix+('-start' if c['vstart'] else '-zero');validate(c);rows.append(c)
     for vl in sorted({0,1,n,n-1,max(1,n//2)}|{x for x in (chunk-1,chunk,chunk+1,2*chunk+1) if 0<=x<=n}):add('length'+str(vl),vl=vl)
     for mask in ('all','off','alternating','single-on','single-off'):add('mask-'+mask,mask=mask)
     for ta,ma in ((False,True),(True,False),(True,True)):add('policy'+str(int(ta))+str(int(ma)),vl=max(1,n-1),mask='alternating',ta=ta,ma=ma)
     add('end-group',vd=32-regs)
     if op!='vfmerge':add('source-v0',vs2=0,mask='none')
     if op!='vfslide1up':add('dest-source2',vd=16,mask='alternating')
     if family=='narrow175' and form=='wv':add('dest-source1',vd=24,mask='alternating')
     for start in sorted({1,n-1,min(w-1,n),min(w-1,n+1)}|{x for x in (chunk-1,chunk,chunk+1) if 0<x<min(w,n)}):
      if start>0:
       add('start'+str(start),vstart=start,mask='alternating',ta=True,ma=True)
       add('no-body'+str(start),vstart=start,vl=min(start,n),mask='off')
     add('start-vl0',vl=0,vstart=1)
     if family!='narrow175':
      for name,value in fp.constants(sew).items():
       add('bits-'+name,fp_b=value,values=(value,),unique=False,vl=min(n,chunk+1),mask='alternating')
      for rm in range(5):add('sticky-rm'+str(rm),frm=rm,fflags_initial=(rm*7)&31,fp_b=fp.constants(sew)['snan'])
      if sew==32:
       for name in ('one','snan','qnan'):add('malformed-'+name,fp_b=fp.constants(sew)[name],bad_box=True)
     else:
      for shift in (0,1,sew-1,sew,sew*2-1,sew*2,sew*2+1,0xffffffff):
       if form=='wi' and shift>31:continue
       add('shift'+str(shift),operand=shift)
     if family!='fpslide175':
      import json
      from pathlib import Path
      inp=json.loads(Path(__file__).with_name('qemu_gaps175.json').read_text())[full][str(sew)]
      for tag,mask in (('partial','none'),('even','alternating'),('odd','single-off')):
       kw=dict(inp,unique=False,vl=max(0,n-1) if tag=='partial' else n,mask=mask)
       if form=='wi':kw['operand']=16 if tag=='partial' else 5
       add('qemu-'+tag,**kw)
 return rows
