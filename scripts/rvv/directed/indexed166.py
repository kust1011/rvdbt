#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite indexed RAM observations; Task165 capture with private semantic bindings.

No assertion about within-segment field ordering or multi-element atomicity.
Overlaps are complete naturally aligned SEW elements in idempotent RAM.
"""
import types
import memory165 as memory
FAMILY='indexed166'
FORMS={}
for store in [False,True]:
 for ordered in [False,True]:
  for nf in range(1,9):
   for ieew in [8,16,32]:
    name=('vs' if store else 'vl')+('ox' if ordered else 'ux')+(f'seg{nf}ei' if nf>1 else 'ei')+str(ieew)+'.v'
    FORMS[name]=dict(store=store,ordered=ordered,nf=nf,index_eew=ieew)
def overlap(c):
 d=set(range(c['vd'],c['vd']+c['destination_registers']));s=set(range(c['vs2'],c['vs2']+c['index_registers']))
 return bool(d&s)
def validate(c):
 assert c['mnemonic']+'.v' in FORMS
 assert c['eew']==c['sew'] and c['emul_exp']==c['lmul_exp']
 assert c['sew']<=64*2**c['lmul_exp'] and -3<=c['index_emul_exp']<=3 and c['emul']*c['nf']<=8
 r=c['group_registers'];ir=c['index_registers']
 assert c['vd']%r==0 and c['vd']+r*c['nf']<=32 and c['vs2']%ir==0 and c['vs2']+ir<=32
 assert c['store'] or c['mask']=='none' or c['vd']!=0
 assert 0<=c['vstart']<c['vlmax'] and 0<=c['vl']<=c['vlmax']
 if c['store'] and overlap(c):assert c['sew']==c['index_eew']
 if c['mask']!='none':
  assert c['vs2']!=0
  if c['store']:assert c['vd']!=0
 if not c['store'] and overlap(c):
  assert c['nf']==1
  if c['sew']<c['index_eew']:assert c['vd']==c['vs2']
  if c['sew']>c['index_eew']:assert c['index_emul_exp']>=0 and c['vs2']+ir==c['vd']+r

def cases():
 import vadd as v
 rows=[]
 for name,form in FORMS.items():
  for w in [128,256,512,1024,2048,4096]:
   for sew in [8,16,32,64]:
    for lm,exp in v.LMUL:
     ix=exp+(form['index_eew']//8).bit_length()-(sew//8).bit_length()
     if sew>64*2**exp or not -3<=ix<=3 or 2**exp*form['nf']>8:continue
     n=int(w/sew*2**exp);r=max(1,2**exp);ir=max(1,2**ix);unit=f'{name}-w{w}-e{sew}-{lm}'
     def add(tag,**kw):
      c=dict(id=unit+'-'+tag,family=FAMILY,mnemonic=name[:-2],form='v',vlen=w,sew=sew,eew=sew,lmul=lm,lmul_exp=exp,emul_exp=exp,emul=2**exp,index_emul_exp=ix,index_registers=ir,group_registers=r,destination_registers=r*form['nf'],vlmax=n,vl=n,vstart=0,vd=8,vs2=16,vs1=24,rs1=18,rs2=8,mask='none',ta=False,ma=False,operand=0x166,stride=0,strided=False,seed=166,tag=tag,vxrm_initial=2,vxsat_initial=1,suppress=False,index_pattern='permuted',**form)
      c.update(kw);c['unit']=f'{name}-w{w}'+('-start' if c['vstart'] else '-zero');validate(c);rows.append(c)
     add('zero',vl=0);add('partial',vl=max(1,n//2));add('full');add('mask-even',mask='alternating',vl=max(1,n-1));add('end-group',vd=32-r*form['nf'],vs2=0)
     if n>1:add('start',vstart=1,mask='odd')
     # Legal source/destination overlaps throughout geometries, not only equal EEW.
     if form['store'] and sew==form['index_eew']:add('source-index-overlap',vs2=8)
     elif not form['store'] and form['nf']==1:
      if sew==form['index_eew'] or sew<form['index_eew']:add('destination-index-low',vs2=8)
      elif ix>=0:add('destination-index-high',vs2=8+r-ir)
     if sew==form['index_eew'] and exp==0:
      for mask in ['all','off','odd','single-on','single-off','byte-pair','chunk-pair','tail-only']:add('mask-'+mask,mask=mask,vl=max(1,n-1))
      for ta,ma in [(False,True),(True,False),(True,True)]:add(f'policy{int(ta)}{int(ma)}',ta=ta,ma=ma,mask='alternating',vl=max(1,n-1))
      for length in sorted({1,n-1}|{x for x in [7,8,9,512//sew-1,512//sew,512//sew+1] if 0<=x<=n}):add('boundary'+str(length),vl=length)
      for start in sorted({1,n-1,max(1,n//2)}|{x for x in [7,8,9,512//sew-1,512//sew,512//sew+1] if 0<x<n}):add('start'+str(start),vstart=start,ta=True,ma=True,mask='alternating')
      add('start-equal',vstart=max(1,n//2),vl=max(1,n//2));add('start-above-partial',vstart=min(n-1,n//2+1),vl=n//2);add('start-zero-vl',vstart=1,vl=0)
      add('suppress-all',mask='off',suppress=True);add('suppress-tail',vl=0,suppress=True);add('suppress-start',vstart=1,vl=1,suppress=True)
      for pat in ['disjoint','repeated','field-overlap','unsigned-high']:add(pat,index_pattern=pat,vl=min(n,index_slots(dict(form,eew=sew,vlen=w))) if pat=='disjoint' else n)
      add('v0-unmasked',vd=0)
      add('index-v0-unmasked',vs2=0)
 return rows

def index_slots(c):return max(1,min((2**c['index_eew']-1)//(c['nf']*c['eew']//8),(memory.memory_size(c)-128)//(c['nf']*c['eew']//8)))
def index_value(c,i):
 e=c['eew']//8;packed=e*c['nf'];slots=index_slots(c);pat=c['index_pattern']
 if pat=='repeated':off=0
 elif pat=='field-overlap':off=(i%max(1,min(slots,7)))*e
 elif pat=='disjoint':off=(i%slots)*packed
 else:off=((i*5+3)%slots)*packed
 if pat=='unsigned-high':off=(1<<(c['index_eew']-1))+off//2//e*e
 return off

def base_offset(c):return 128-((1<<(c['index_eew']-1)) if c['index_pattern']=='unsigned-high' else 0)
def initial(c):
 raw=bytearray(memory.initial(c));b=c['vlen']//8;e=c['index_eew']//8
 for i in range(c['vlmax']):
  p=c['vs2']*b+i*e;raw[p:p+e]=index_value(c,i).to_bytes(e,'little')
 return bytes(raw)
def address(c,i,f):
 return ((base_offset(c)+index_value(c,i))&0xffffffff)+f*c['eew']//8

def bind(fn,**kw):return types.FunctionType(fn.__code__,dict(fn.__globals__,**kw),argdefs=fn.__defaults__)
memory_size=memory.memory_size;memory_initial=memory.memory_initial;regoff=memory.regoff;enabled=memory.enabled;packet_size=memory.packet_size;decode=memory.decode
_candidates=bind(memory.store_candidates,address=address)
def store_candidates(c,before):
 if not c['ordered']:return _candidates(c,before)
 # Ordered segment order chooses the greatest enabled element writer. Fields
 # within one segment are disjoint here; do not claim a field execution order.
 winners={};e=c['eew']//8
 for i in range(c['vstart'],c['vl']):
  if enabled(c,before,i):
   for f in range(c['nf']):
    p=regoff(c,i,f);winners[address(c,i,f)]={before[p:p+e]}
 return winners
check_isa=bind(memory.check_isa,validate=validate,initial=initial,address=address,store_candidates=store_candidates)
check_reference=bind(memory.check_reference,store_candidates=store_candidates)
def target(c):return f'{c["mnemonic"]}.v v{c["vd"]},(s2),v{c["vs2"]}'+(',v0.t' if c['mask']!='none' else '')
def instruction(c):return (c['nf']-1)<<29|(3 if c['ordered'] else 1)<<26|int(c['mask']=='none')<<25|c['vs2']<<20|18<<15|{8:0,16:5,32:6}[c['index_eew']]<<12|c['vd']<<7|(0x27 if c['store'] else 7)
assembly=bind(memory.assembly,initial=initial,target=target,base_offset=base_offset)
def restrictions():
 return [dict(form=name,scenario=s,execution='NOT_RUN',ordinary_legal=False) for name in FORMS for s in ['unsupported vtype','index EMUL outside 1/8..8','data LMUL*NF > 8','misaligned or out-of-range groups','reserved masked load destination-v0 overlap','reserved indexed segment destination-index overlap','reserved nonsegment width-changing overlap','reserved source overlap at different EEWs including v0 mask','vstart >= VLMAX reserved region']]
def install(v):
 old=v.manifest_cases;v.manifest_cases=lambda family:cases() if family==FAMILY else old(family)
 for name in ['initial','packet_size','decode','check_isa','check_reference','assembly']:setattr(v,name,globals()[name])
