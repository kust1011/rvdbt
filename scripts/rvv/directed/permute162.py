#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite RVV1.0 integer permutation scenarios and independently checked predicates.

Pinned Spike/Sail execution supplies answers; these predicates constrain every
packet, including all preserved vector registers, CSRs and scalar s0/s1.
"""
import struct
FAMILY='permute162'
FORMS={'vslideup':('vx','vi'),'vslidedown':('vx','vi'),'vslide1up':('vx',),'vslide1down':('vx',),'vrgather':('vv','vx','vi'),'vrgatherei16':('vv',),'vcompress':('vm',)}
FUNCT6={'vslideup':14,'vslidedown':15,'vslide1up':14,'vslide1down':15,'vrgather':12,'vrgatherei16':14,'vcompress':23}

def cases():
 import vadd as v
 rows=[]
 for w in [128,256,512,1024,2048,4096]:
  for e in [8,16,32,64]:
   for lm,exp in v.LMUL:
    if e>64*2**exp:continue
    n=int(w/e*2**exp);regs=max(1,2**exp);chunk=512//e
    for op,forms in FORMS.items():
     iexp=exp+({8:1,16:0,32:-1,64:-2}[e] if op=='vrgatherei16' else 0)
     if not -3<=iexp<=3:continue
     for form in forms:
      unit=f'{op}-{form}-w{w}-e{e}-{lm}'
      def add(tag,**kw):
       c=dict(id=unit+'-'+tag,unit=unit+'-zero',family=FAMILY,mnemonic=op,form=form,vlen=w,sew=e,lmul=lm,lmul_exp=exp,emul=lm,group_registers=regs,index_exp=iexp,index_registers=max(1,2**iexp),vlmax=n,vl=n,vstart=0,vd=8,vs2=16,vs1=24,rs1=8,mask='none',ta=False,ma=False,operand=1,seed=162,tag=tag,index_pattern='boundary',selection='alternating',vxrm_initial=2,vxsat_initial=1,execution='NOT_RUN')
       c.update(kw)
       if c['vstart']:c['unit']=unit+'-start'
       validate(c);rows.append(c)
      for vl in sorted({0,1,n,n-1,n//2}|{x for x in [7,8,9,chunk-1,chunk,chunk+1] if 0<=x<=n}):add('length'+str(vl),vl=vl)
      for ta,ma in [(False,False),(False,True),(True,False),(True,True)]:add(f'policy{int(ta)}{int(ma)}',vl=max(1,n-1),mask='none' if op=='vcompress' else 'alternating',ta=ta,ma=ma)
      add('end-group',vd=32-regs,vs1=7 if op=='vcompress' else 8)
      add('csr-clear',vxrm_initial=0,vxsat_initial=0)
      if op=='vcompress':
       for p in ['off','all','alternating','odd','single-on','single-off','chunk-pair','byte-pair']:
        for ta in [False,True]:add('select-'+p+'-ta'+str(int(ta)),selection=p,ta=ta,vl=max(1,n-1))
       add('mask-source-v0',vs1=0)
       add('destination-v0',vd=0)
       add('source-mask-alias',vs1=16)
       add('mask-tail-only',selection='tail-only',vl=max(1,n//2),ta=True)
      else:
       for m in ['all','off','alternating','odd','single-on','single-off']:
        add('mask-'+m,mask=m,vl=min(n,chunk+1))
       add('source-v0',vs2=0)
       add('destination-v0',vd=0)
       if op in ['vslidedown','vslide1down']:
        add('dest-source2',vd=16,mask='alternating',ta=True,ma=True)
        add('dest-source2-tu',vd=16,vl=max(1,n-1))
       if form=='vv':
        for p in ['reverse','zero','out-of-range','cross-chunk','beyond-vl']:
         add('indices-'+p,index_pattern=p,vl=max(1,n//2))
        if op=='vrgather':add('source-index-alias',vs1=16)
        # Different EEW reads of an overlapping source group are reserved.
        add('indices-v0',vs1=0)
       else:
        values={0,1,7,8,15,16,31} if form=='vi' else {0,1,n-1,n,n+1,chunk-1,chunk,chunk+1,255,256,0x7fffffff,0x80000000,0xffffffff}
        for value in sorted(values):add('operand'+str(value),operand=value)
        add('scalar-x0',rs1=0)
       for start in sorted({1,n-1}|{x for x in [7,8,chunk-1,chunk,chunk+1] if 0<x<n}):
        if 0<start<min(n,w):add('start'+str(start),vstart=start,mask='alternating',ta=True,ma=True)
       partial=max(1,n//2)
       if partial<n and partial<w:
        add('start-equal-partial',vl=partial,vstart=partial,ta=True,ma=True)
        if partial+1<min(n,w):add('start-above-partial',vl=partial,vstart=partial+1)
       if n>1:
        add('start-zero-vl',vl=0,vstart=1,ta=True,ma=True)
        add('start-active-tu',vstart=1,vl=n)
       if n>chunk+2:
        add('start-cross-chunk-partial',vstart=chunk-1,vl=chunk+2,mask='alternating')
 return rows

def overlap(a,na,b,nb):return max(a,b)<min(a+na,b+nb)

def validate(c):
 r=c['group_registers'];ir=c['index_registers'];op=c['mnemonic']
 for base,count in [(c['vd'],r),(c['vs2'],r)]+([(c['vs1'],ir)] if c['form']=='vv' else []):
  assert base%count==0 and base+count<=32
 if c['mask']!='none':assert c['vd']!=0
 if op in ['vslideup','vslide1up','vrgather','vrgatherei16','vcompress']:assert not overlap(c['vd'],r,c['vs2'],r)
 if c['form']=='vv':
  assert not overlap(c['vd'],r,c['vs1'],ir)
  if op=='vrgatherei16' and c['sew']!=16:assert not overlap(c['vs2'],r,c['vs1'],ir)
 if op=='vcompress':assert c['vstart']==0 and c['mask']=='none' and not overlap(c['vd'],r,c['vs1'],1)
 assert 0<=c['vstart']<min(c['vlmax'],c['vlen']) and 0<=c['vl']<=c['vlmax']
 assert c['form']!='vi' or 0<=c['operand']<=31

def restrictions():
 out=[]
 for op,forms in FORMS.items():
  for form in forms:
   if op in ['vslideup','vslide1up','vrgather','vrgatherei16','vcompress']:
    out.append(dict(form=op+'.'+form,scenario='destination overlaps data source',expected='reserved encoding',execution='NOT_RUN'))
   if form=='vv' or op=='vcompress':out.append(dict(form=op+'.'+form,scenario='destination overlaps index/mask source',expected='reserved encoding',execution='NOT_RUN'))
   if op=='vrgatherei16':out.append(dict(form=op+'.'+form,scenario='different-EEW sources overlap; index EMUL outside 1/8..8',expected='reserved encoding',execution='NOT_RUN'))
 for start,vl in [(1,0),(1,1),(7,4)]:out.append(dict(form='vcompress.vm',vstart=start,vl=vl,expected='illegal instruction',execution='NOT_RUN'))
 out.append(dict(form='vcompress.vm',scenario='vm=0',expected='reserved encoding',execution='NOT_RUN'))
 for op,forms in FORMS.items():
  for form in forms:
   if op!='vcompress':out.append(dict(form=op+'.'+form,scenario='masked destination includes v0; nonaligned/out-of-file group; vstart>=VLMAX',expected='reserved encoding/profile',execution='NOT_RUN'))
 return out

def bits(pattern,n,vl,chunk):
 return sum(1<<i for i in range(n) if pattern in ['none','all'] or pattern=='alternating' and i%2==0 or pattern=='odd' and i%2==1 or pattern=='single-on' and i==min(n-1,chunk) or pattern=='single-off' and i!=min(n-1,chunk) or pattern=='chunk-pair' and i in [chunk-1,chunk] or pattern=='byte-pair' and i in [7,8] or pattern=='tail-only' and i>=vl)

def initial(c):
 b=c['vlen']//8;e=c['sew']//8;n=c['vlmax'];limit=(1<<c['sew'])-1;chunk=512//c['sew']
 raw=bytearray((r*37+i*13+0x53)&255 for r in range(32) for i in range(b))
 # Position-dependent source values distinguish cross-register/chunk permutations.
 for i in range(n):
  value=((i*73+0x35)^(i>>8)^(0x8765432100000000 if i%2 else 0x1234567800000000))&limit
  raw[c['vs2']*b+i*e:c['vs2']*b+(i+1)*e]=value.to_bytes(e,'little')
 if c['form']=='vv' and c['vs1']!=c['vs2']:
  ie=2 if c['mnemonic']=='vrgatherei16' else e;imax=(1<<(ie*8))-1
  boundary=[0,n-1,n,n+1,chunk-1,chunk,chunk+1,255,256,512,513,imax]
  for i in range(n):
   p=c['index_pattern'];value={'reverse':n-1-i,'zero':0,'out-of-range':n,'cross-chunk':(i+chunk)%n,'beyond-vl':min(n-1,c['vl']+i)}.get(p,boundary[i%len(boundary)])&imax
   raw[c['vs1']*b+i*ie:c['vs1']*b+(i+1)*ie]=value.to_bytes(ie,'little')
 if c['mnemonic']=='vcompress' and c['vs1']!=c['vs2']:
  raw[c['vs1']*b:(c['vs1']+1)*b]=bits(c['selection'],c['vlen'],c['vl'],chunk).to_bytes(b,'little')
 # v0 data/index/mask-source scenarios retain their source interpretation.
 if c['vs2']!=0 and not (c['form']=='vv' and c['vs1']==0) and not (c['mnemonic']=='vcompress' and c['vs1']==0):raw[:b]=bits(c['mask'],c['vlen'],c['vl'],chunk).to_bytes(b,'little')
 elif c['mnemonic']=='vcompress' and c['vs1']==0:raw[:b]=bits(c['selection'],c['vlen'],c['vl'],chunk).to_bytes(b,'little')
 return bytes(raw)

def bit(raw,reg,i,b):return raw[reg*b+i//8]>>(i%8)&1

def value(c,before,i):
 b=c['vlen']//8;e=c['sew']//8;op=c['mnemonic'];operand=0 if c['rs1']==0 and c['form']=='vx' else c['operand']&0xffffffff
 if op=='vslide1up' and i==0 or op=='vslide1down' and i==c['vl']-1:
  scalar=operand-(1<<32) if operand&(1<<31) else operand
  return (scalar% (1<<c['sew'])).to_bytes(e,'little')
 if op in ['vslideup','vslidedown']:j=i-operand if op=='vslideup' else i+operand
 elif op in ['vslide1up','vslide1down']:j=i-1 if op=='vslide1up' else i+1
 else:
  if c['form']=='vv':
   ie=2 if op=='vrgatherei16' else e;j=int.from_bytes(before[c['vs1']*b+i*ie:c['vs1']*b+(i+1)*ie],'little')
  else:j=operand
 return before[c['vs2']*b+j*e:c['vs2']*b+(j+1)*e] if 0<=j<c['vlmax'] else bytes(e)

def selected(c,before):return [i for i in range(c['vl']) if bit(before,c['vs1'],i,c['vlen']//8)]

def active(c,before,i):
 if not c['vstart']<=i<c['vl']:return False
 if c['mnemonic']=='vslideup' and i<(0 if c['rs1']==0 and c['form']=='vx' else c['operand']&0xffffffff):return False
 return c['mask']=='none' or bit(before,0,i,c['vlen']//8)

def packet_size(c):return 104+64*(c['vlen']//8)

def decode(c,raw):
 if len(raw)!=packet_size(c):raise ValueError('missing/extra packet bytes')
 if struct.unpack_from('<2I',raw)!=(0x145add,c['ordinal']):raise ValueError('packet marker/order')
 b=c['vlen']//8
 return list(struct.unpack_from('<12I',raw,8)),list(struct.unpack_from('<12I',raw,56)),raw[104:104+32*b],raw[104+32*b:]

def check_isa(c,raw,rc=0,timeout=False):
 import vadd as v
 if rc or timeout:raise ValueError('failed execution/timeout')
 validate(c);pre,post,before,after=decode(c,raw);pair=[c['operand']&0xffffffff,0x6badcafe]
 if pre!=v.csr_expected(c)+pair or post!=v.csr_expected(c,True)+pair:raise ValueError('CSR/scalar preservation mismatch')
 if before!=initial(c):raise ValueError('pre-register mismatch')
 b=c['vlen']//8;e=c['sew']//8;d=c['vd']*b;end=d+c['group_registers']*b
 if after[:d]!=before[:d] or after[end:]!=before[end:]:raise ValueError('preserved non-destination register')
 chosen=selected(c,before) if c['mnemonic']=='vcompress' else None
 for i in range((end-d)//e):
  old=before[d+i*e:d+(i+1)*e];got=after[d+i*e:d+(i+1)*e]
  if chosen is not None:
   enabled=i<len(chosen);expected=before[c['vs2']*b+chosen[i]*e:c['vs2']*b+(chosen[i]+1)*e] if enabled else old
   agnostic=c['vl']>0 and not enabled and c['ta']
  else:
   enabled=active(c,before,i);expected=value(c,before,i) if enabled else old
   below_offset=c['mnemonic']=='vslideup' and i<(0 if c['rs1']==0 and c['form']=='vx' else c['operand']&0xffffffff) and i<c['vl']
   agnostic=c['vstart']<c['vl'] and i>=c['vstart'] and not below_offset and ((i>=c['vl'] and c['ta']) or (i<c['vl'] and not enabled and c['ma']))
  if got!=expected and not (not enabled and agnostic and got==b'\xff'*e):raise ValueError(f'element {i}: {got.hex()} != {expected.hex()}')
 return True

def check_reference(c,raw,reference):
 a=decode(c,raw);r=decode(c,reference)
 if a[1]!=r[1]:raise ValueError('independent CSR/scalar mismatch')
 b=c['vlen']//8;e=c['sew']//8;count=len(selected(c,a[2])) if c['mnemonic']=='vcompress' else c['vl']
 for i in range(count):
  if c['mnemonic']=='vcompress' or active(c,a[2],i):
   off=c['vd']*b+i*e
   if a[3][off:off+e]!=r[3][off:off+e]:raise ValueError('independent active result mismatch '+str(i))
 return True

def target(c):
 arg=f'v{c["vs1"]}' if c['form'] in ['vv','vm'] else f'x{c["rs1"]}' if c['form']=='vx' else str(c['operand'])
 return f'{c["mnemonic"]}.{c["form"]} v{c["vd"]},v{c["vs2"]},'+arg+(',v0.t' if c['mask']!='none' else '')

def instruction(c):
 op=c['mnemonic'];f3=2 if op=='vcompress' else 6 if op in ['vslide1up','vslide1down'] else {'vv':0,'vx':4,'vi':3}[c['form']]
 arg=c['vs1'] if c['form'] in ['vv','vm'] else c['rs1'] if c['form']=='vx' else c['operand']
 return FUNCT6[op]<<26|int(c['mask']=='none')<<25|c['vs2']<<20|arg<<15|f3<<12|c['vd']<<7|0x57

# Capture body adapted from mask158; no semantic/golden reuse.
def assembly(cs):
    import vadd as v
    b=cs[0]['vlen']//8;size=packet_size(cs[0])
    lines=['.option norvc','.option norelax','.text','.globl _start','_start:','#ifdef SAIL','li t0,0x6600','csrs mstatus,t0','#endif']
    for c in cs:
        tag=c['ordinal'];lines+=['csrwi vstart,0',f'la t0,initial_{tag}']
        for r in range(32):lines += [f'vl1re8.v v{r},(t0)',f'addi t0,t0,{b}']
        lines += [f'la a3,packet_{tag}','li t0,0x145add','sw t0,0(a3)',f'li t0,{tag}','sw t0,4(a3)','addi t1,a3,104']
        for r in range(32):lines += [f'vs1r.v v{r},(t1)',f'addi t1,t1,{b}']
        lines += [f'csrwi vcsr,{c["vxrm_initial"]*2+c["vxsat_initial"]}','li t0,117','csrw fcsr,t0',f'li t0,{c["vl"]}',f'vsetvli t2,t0,e{c["sew"]},{c["lmul"]},{"ta" if c["ta"] else "tu"},{"ma" if c["ma"] else "mu"}',f'li s0,{c["operand"]&0xffffffff}','li s1,0x6badcafe',f'li t0,{c["vstart"]}','csrw vstart,t0']
        for j,csr in enumerate(v.CSRS):lines += [f'csrr t0,{csr}',f'sw t0,{8+4*j}(a3)']
        lines += ['sw s0,48(a3)','sw s1,52(a3)',f'.globl target_{tag}',f'target_{tag}:',target(c)]
        for j,csr in enumerate(v.CSRS):lines += [f'csrr t0,{csr}',f'sw t0,{56+4*j}(a3)']
        lines += ['sw s0,96(a3)','sw s1,100(a3)','csrwi vstart,0',f'li t0,{104+32*b}','add t1,a3,t0']
        for r in range(32):lines += [f'vs1r.v v{r},(t1)',f'addi t1,t1,{b}']
    lines += ['#ifdef SAIL','la t0,tohost','li t1,1','sw t1,0(t0)','1: j 1b','#else','li a0,1','la a1,begin_signature',f'li a2,{size*len(cs)}','li a7,64','ecall',f'li t0,{size*len(cs)}','bne a0,t0,write_failed','li a0,0','li a7,93','ecall','write_failed:','li a0,99','li a7,93','ecall','#endif','.data','.balign 16']
    for c in cs:lines += [f'initial_{c["ordinal"]}:','.byte '+','.join(map(str,initial(c)))]
    lines += ['.balign 16','.globl begin_signature,end_signature','begin_signature:']
    for c in cs:lines += [f'packet_{c["ordinal"]}:',f'.zero {size}']
    return '\n'.join(lines+['end_signature:','.balign 64','.globl tohost,fromhost','tohost: .dword 0','fromhost: .dword 0'])+'\n'

def install(v):
 original=v.manifest_cases
 v.manifest_cases=lambda family:cases() if family==FAMILY else original(family)
 for name in ['initial','packet_size','decode','check_isa','check_reference','assembly']:
  setattr(v,name,globals()[name])
