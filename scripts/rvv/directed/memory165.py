#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Ordinary vector memory family, sharing Task162 capture and Task145 runner.

Aligned overlap is checked as whole-EEW allowed winners, never reference order.
Each guest case has independent register inputs and a full canaried buffer.
"""
import re, struct, types
import permute162 as capture
FAMILY='memory165'
FORMS={}
for store in [False,True]:
 for strided in [False,True]:
  for nf in range(1,9):
   for eew in [8,16,32,64]:
    name=('vs' if store else 'vl')+('s' if strided else '')+(f'seg{nf}e' if nf>1 else 'e')+str(eew)+'.v'
    FORMS[name]=dict(store=store,strided=strided,nf=nf,eew=eew)

def cases():
 import vadd as v
 rows=[]
 for name,form in FORMS.items():
  for w in [128,256,512,1024,2048,4096]:
   for sew in [8,16,32,64]:
    for lm,exp in v.LMUL:
     emexp=exp+(form['eew']//8).bit_length()-(sew//8).bit_length()
     if sew>64*2**exp or not -3<=emexp<=3 or 2**emexp*form['nf']>8:continue
     n=int(w/sew*2**exp);r=max(1,2**emexp);unit=f'{name}-w{w}-e{sew}-{lm}'
     def add(tag,**kw):
      stride=form['nf']*form['eew']//8
      c=dict(id=unit+'-'+tag,unit=unit+'-zero',family=FAMILY,mnemonic=name[:-2],form='v',vlen=w,sew=sew,lmul=lm,lmul_exp=exp,emul_exp=emexp,emul=2**emexp,group_registers=r,destination_registers=r*form['nf'],vlmax=n,vl=n,vstart=0,vd=8,vs2=16,vs1=24,rs1=18,rs2=8,mask='none',ta=False,ma=False,operand=stride,stride=stride,seed=165,tag=tag,vxrm_initial=2,vxsat_initial=1,suppress=False,execution='NOT_RUN',**form)
      c.update(kw);c['operand']=c['stride'];c['unit']=f'{name}-w{w}'+('-start' if c['vstart'] else '-zero');validate(c);rows.append(c)
     # All legal geometries get zero/partial/full and masked partial with preservation.
     add('zero',vl=0);add('partial',vl=max(1,n//2));add('full');add('mask-even',mask='alternating',vl=max(1,n-1))
     add('end-group',vd=32-r*form['nf'])
     if n>1:add('start',vstart=1,vl=n,mask='odd')
     # Remaining semantic branches use SEW=EEW/LMUL=m1 per form and VLEN.
     if sew==form['eew'] and exp==0:
      for mask in ['all','off','odd','single-on','single-off','byte-pair','chunk-pair','tail-only']:
       add('mask-'+mask,mask=mask,vl=max(1,n-1))
      for ta,ma in [(False,True),(True,False),(True,True)]:add(f'policy{int(ta)}{int(ma)}',ta=ta,ma=ma,mask='alternating',vl=max(1,n-1))
      for length in sorted({1,n-1}|{x for x in [7,8,9,512//sew-1,512//sew,512//sew+1] if 0<=x<=n}):add('boundary'+str(length),vl=length)
      for start in sorted({1,n-1,max(1,n//2)}|{x for x in [7,8,9,512//sew-1,512//sew,512//sew+1] if 0<x<n}):
       add('start'+str(start),vstart=start,ta=True,ma=True,mask='alternating')
      add('start-equal',vstart=max(1,n//2),vl=max(1,n//2));add('start-above-partial',vstart=min(n-1,n//2+1),vl=n//2)
      add('start-zero-vl',vstart=1,vl=0)
      add('suppress-all',mask='off',suppress=True)
      add('suppress-tail',vl=0,suppress=True)
      add('suppress-start',vstart=1,vl=1,suppress=True)
      if form['strided']:
       e=form['eew']//8;packed=e*form['nf']
       for tag,stride in [('positive-gap',packed+e),('negative',-packed),('negative-gap',-packed-e),('zero-stride',0),('positive-overlap',e),('negative-overlap',-e)]:add(tag,stride=stride,mask='odd')
       add('stride-x0',stride=0,rs2=0)
      # Stores can read v0 while masked; loads cannot overwrite the mask.
      add('v0-unmasked',vd=0)
      if form['store']:add('v0-masked',vd=0,mask='alternating')
      elif r==1:add('adjacent-mask',vd=1,mask='odd')
 return rows

def validate(c):
 assert c['mnemonic']+'.v' in FORMS
 assert c['sew']<=64*2**c['lmul_exp'] and -3<=c['emul_exp']<=3
 assert c['emul']==c['eew']/c['sew']*2**c['lmul_exp'] and c['emul']*c['nf']<=8
 r=c['group_registers'];assert r==max(1,2**c['emul_exp'])
 assert c['vd']%r==0 and c['vd']+r*c['nf']<=32
 assert c['store'] or c['mask']=='none' or c['vd']!=0
 assert 0<=c['vstart']<min(c['vlen'],c['vlmax']) and 0<=c['vl']<=c['vlmax']
 assert c['stride']%(c['eew']//8)==0,'only whole-EEW overlap in finite scope'

def restrictions():
 return [dict(form=name,scenario=scenario,execution='NOT_RUN',ordinary_legal=False) for name in FORMS for scenario in ['EMUL outside 1/8..8','EMUL*NF > 8','misaligned vector group','register group beyond v31','masked load destination overlaps v0' if not FORMS[name]['store'] else 'unsupported vtype','vstart >= VLMAX reserved region']]

def memory_size(c):return 16*(c['vlen']//8)+256
def memory_initial(c):return bytes((i*29+(i>>8)*17+0xa7)&255 for i in range(memory_size(c)))
def initial(c):
 b=c['vlen']//8
 raw=bytearray((r*37+i*13+(i>>8)*11+0x53)&255 for r in range(32) for i in range(b))
 raw[:b]=capture.bits(c['mask'],c['vlen'],c['vl'],512//c['eew']).to_bytes(b,'little')
 return bytes(raw)
def base_offset(c):
 step=c['stride'] if c['strided'] else c['nf']*c['eew']//8
 return 128+max(0,-step*(c['vlmax']-1))
def address(c,i,f):return base_offset(c)+i*(c['stride'] if c['strided'] else c['nf']*c['eew']//8)+f*(c['eew']//8)
def enabled(c,before,i):return c['vstart']<=i<c['vl'] and (c['mask']=='none' or capture.bit(before,0,i,c['vlen']//8))
def regoff(c,i,f):return (c['vd']+f*c['group_registers'])*(c['vlen']//8)+i*(c['eew']//8)
def packet_size(c):return 104+64*(c['vlen']//8)+2*memory_size(c)
def decode(c,raw):
 if len(raw)!=packet_size(c):raise ValueError('packet extent')
 b=c['vlen']//8;n=32*b;m=memory_size(c)
 if struct.unpack_from('<II',raw)!= (0x145add,c['ordinal']):raise ValueError('packet identity')
 return list(struct.unpack_from('<12I',raw,8)),list(struct.unpack_from('<12I',raw,56)),raw[104:104+n],raw[104+n:104+2*n],raw[104+2*n:104+2*n+m],raw[104+2*n+m:]

def store_candidates(c,before):
 candidates={};e=c['eew']//8
 for i in range(c['vstart'],c['vl']):
  if not enabled(c,before,i):continue
  for f in range(c['nf']):
   off=address(c,i,f);r=regoff(c,i,f)
   candidates.setdefault(off,set()).add(before[r:r+e])
 return candidates

def check_isa(c,raw,rc=0,timeout=False):
 import vadd as v
 if rc or timeout:raise ValueError('failed execution/timeout')
 validate(c);pre,post,before,after,mem,gotmem=decode(c,raw);pair=[c['operand']&0xffffffff,0x6badcafe]
 if pre!=v.csr_expected(c)+pair or post!=v.csr_expected(c,True)+pair:raise ValueError('CSR/scalar preservation mismatch')
 if before!=initial(c) or mem!=memory_initial(c):raise ValueError('independent initial register/buffer mismatch')
 if c['store']:
  if before!=after:raise ValueError('store register preservation')
  expected=bytearray(mem);e=c['eew']//8
  for off,choices in store_candidates(c,before).items():
   if gotmem[off:off+e] not in choices:raise ValueError(f'store allowed winner at {off}')
   expected[off:off+e]=gotmem[off:off+e]
  if gotmem!=expected:raise ValueError('exact store footprint/canary/inactive preservation')
 else:
  if gotmem!=mem:raise ValueError('load memory preservation')
  expected=bytearray(before);e=c['eew']//8;b=c['vlen']//8
  for f in range(c['nf']):
   d=(c['vd']+f*c['group_registers'])*b
   for i in range(c['group_registers']*b//e):
    off=d+i*e;old=before[off:off+e];got=after[off:off+e]
    active=enabled(c,before,i)
    value=mem[address(c,i,f):address(c,i,f)+e] if active else old
    agnostic=c['vstart']<c['vl'] and i>=c['vstart'] and ((i>=c['vl'] and c['ta']) or (i<c['vl'] and not active and c['ma']))
    if got!=value and not (not active and agnostic and got==b'\xff'*e):raise ValueError(f'load field {f} element {i}: {got.hex()} != {value.hex()}')
    expected[off:off+e]=got
  if after!=expected:raise ValueError('non-destination preservation')
 return True

def check_reference(c,raw,reference):
 a=decode(c,raw);r=decode(c,reference)
 if a[:1]!=r[:1] or a[1]!=r[1] or a[2]!=r[2] or a[4]!=r[4]:raise ValueError('reference input/CSR mismatch')
 if not c['store']:
  e=c['eew']//8
  for i in range(c['vstart'],c['vl']):
   if enabled(c,a[2],i):
    for f in range(c['nf']):
     off=regoff(c,i,f)
     if a[3][off:off+e]!=r[3][off:off+e]:raise ValueError('reference active load mismatch')
 else:
  e=c['eew']//8
  for off,choices in store_candidates(c,a[2]).items():
   # Overlapping unordered stores have an allowed set, not a Spike/Sail order.
   if len(choices)==1 and a[5][off:off+e]!=r[5][off:off+e]:raise ValueError('reference nonoverlapping store mismatch')
 return True

def target(c):return f'{c["mnemonic"]}.v v{c["vd"]},(s2)'+(f',x{c["rs2"]}' if c['strided'] else '')+(',v0.t' if c['mask']!='none' else '')
def instruction(c):return (c['nf']-1)<<29|int(c['strided'])*2<<26|int(c['mask']=='none')<<25|(c['rs2'] if c['strided'] else 0)<<20|18<<15|{8:0,16:5,32:6,64:7}[c['eew']]<<12|c['vd']<<7|(0x27 if c['store'] else 7)

def copy_memory(c,post=False):
 tag=c['ordinal'];off=104+64*(c['vlen']//8)+(memory_size(c) if post else 0);label=f'copy_{tag}_{int(post)}'
 return [f'la t3,memory_{tag}',f'li t0,{off}','add t4,a3,t0',f'li t5,{memory_size(c)}',label+':','lbu t0,0(t3)','sb t0,0(t4)','addi t3,t3,1','addi t4,t4,1','addi t5,t5,-1',f'bnez t5,{label}']

def assembly(cs):
 # Extend the established full-register observer; terminal IO/Sail adapter unchanged.
 observer=types.FunctionType(capture.assembly.__code__,dict(capture.assembly.__globals__,initial=initial,target=target,packet_size=packet_size))
 src=observer(cs)
 for c in cs:
  tag=c['ordinal'];pre=f'csrwi vcsr,{c["vxrm_initial"]*2+c["vxsat_initial"]}'
  # This string occurs per case. Bind through the preceding unique target region.
  start=src.index(f'la t0,initial_{tag}\n');end=src.index(f'target_{tag}:\n',start)
  head=src[start:end];head=head.replace(pre,'\n'.join(copy_memory(c))+ '\n'+pre)
  base='li s2,0' if c['suppress'] else f'la s2,memory_{tag}\nli t0,{base_offset(c)}\nadd s2,s2,t0'
  head=head.replace(f'.globl target_{tag}',base+'\n'+f'.globl target_{tag}')
  src=src[:start]+head+src[end:]
  start=src.index(f'target_{tag}:\n');end=src.find('csrwi vstart,0\nla t0,initial_',start)
  if end<0:end=src.index('#ifdef SAIL\nla t0,tohost',start)
  src=src[:end]+'\n'.join(copy_memory(c,True))+'\n'+src[end:]
 # append independently initialized memory buffers outside the output signature.
 data='\n'.join(f'.balign 16\nmemory_{c["ordinal"]}:\n.byte '+','.join(map(str,memory_initial(c))) for c in cs)+'\n'
 src=src.replace('.globl begin_signature,end_signature',data+'.globl begin_signature,end_signature')
 return src

def install(v):
 old=v.manifest_cases
 v.manifest_cases=lambda family:cases() if family==FAMILY else old(family)
 for name in ['initial','packet_size','decode','check_isa','check_reference','assembly']:setattr(v,name,globals()[name])
