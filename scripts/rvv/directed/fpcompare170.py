#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Disjoint ordinary FP min/max, sign injection, comparisons and classification.

Bit predicates follow ratified V1.0 and F2.2. No DUT-derived NaN or host FP golden.
"""
from functools import lru_cache
import struct
import fp157 as fp
FORMS={'vfmin':('vv','vf'),'vfmax':('vv','vf'),
       'vfsgnj':('vv','vf'),'vfsgnjn':('vv','vf'),'vfsgnjx':('vv','vf'),
       'vmfeq':('vv','vf'),'vmfne':('vv','vf'),'vmflt':('vv','vf'),
       'vmfle':('vv','vf'),'vmfgt':('vf',),'vmfge':('vf',),'vfclass':('v',)}
FUNCT6={'vfmin':4,'vfmax':6,'vfsgnj':8,'vfsgnjn':9,'vfsgnjx':10,
        'vmfeq':24,'vmfle':25,'vmflt':27,'vmfne':28,'vmfgt':29,'vmfge':31,'vfclass':19}
def comparison(c):return c['mnemonic'].startswith('vmf')
scalar=fp.scalar
scalar_operand=fp.scalar_operand
active=fp.active

def target(c):
 rhs='' if c['form']=='v' else ','+(f'v{c["vs1"]}' if c['form']=='vv' else 'fs0')
 return f'{c["mnemonic"]}.{c["form"]} v{c["vd"]},v{c["vs2"]}'+rhs+(',v0.t' if c['mask']!='none' else '')
def instruction(c):
 rhs=16 if c['form']=='v' else c['vs1'] if c['form']=='vv' else 8
 return FUNCT6[c['mnemonic']]<<26 | int(c['mask']=='none')<<25 | c['vs2']<<20 | rhs<<15 | (5 if c['form']=='vf' else 1)<<12 | c['vd']<<7 | 0x57

@lru_cache(maxsize=65536)
def element(bits,op,a,z):
 sign=1<<(bits-1);sa,ka,va,sna=fp.unpack(bits,a);sz,kz,vz,snz=fp.unpack(bits,z)
 if op.startswith('vfsgnj'):
  s=sz if op=='vfsgnj' else sz^1 if op=='vfsgnjn' else sa^sz
  return (a&~sign)|(s*sign),0
 if op=='vfclass':
  if ka=='nan':index=8 if sna else 9
  elif ka=='inf':index=0 if sa else 7
  elif a&~sign==0:index=3 if sa else 4
  elif a&~sign < fp.constants(bits)['minnormal']:index=2 if sa else 5
  else:index=1 if sa else 6
  return 1<<index,0
 nv=16 if sna or snz else 0
 # Total numeric key orders infinity and treats both zeros as equal.
 def key(s,k,v):return (0,0) if k=='inf' and s else (2,0) if k=='inf' else (1,v)
 if op in ('vfmin','vfmax'):
  if ka==kz=='nan':return fp.constants(bits)['canonical'],nv
  if ka=='nan':return z,nv
  if kz=='nan':return a,nv
  if a&~sign==z&~sign==0:return ((a|z) if op=='vfmin' else (a&z)),nv
  smaller=key(sa,ka,va)<key(sz,kz,vz)
  return (a if smaller==(op=='vfmin') else z),nv
 if ka=='nan' or kz=='nan':
  return int(op=='vmfne'),(nv if op in ('vmfeq','vmfne') else 16)
 x,y=key(sa,ka,va),key(sz,kz,vz)
 return int({'vmfeq':x==y,'vmfne':x!=y,'vmflt':x<y,'vmfle':x<=y,'vmfgt':x>y,'vmfge':x>=y}[op]),0

def initial(c):
 raw=bytearray(fp.initial(dict(c,family='fp170-baseline')))
 if c.get('qemu_vectors'):
  b,e=c['vlen']//8,c['sew']//8
  for reg,key in ((c['vs2'],'fp_a'),(c['vs1'],'fp_b')):
   values=c['qemu_vectors'].get(key,[0])
   for i in range(c['group_registers']*b//e):raw[reg*b+i*e:reg*b+(i+1)*e]=values[i%len(values)].to_bytes(e,'little')
 return bytes(raw)

def lane(c,before,i):
 b,e=c['vlen']//8,c['sew']//8
 a=int.from_bytes(before[c['vs2']*b+i*e:c['vs2']*b+(i+1)*e],'little')
 z=int.from_bytes(before[c['vs1']*b+i*e:c['vs1']*b+(i+1)*e],'little') if c['form']=='vv' else scalar_operand(c)
 return element(c['sew'],c['mnemonic'],a,z)
def expected_flags(c,before):
 flags=c['fflags_initial']
 for i in range(c['vstart'],c['vl']):
  if active(c,before,i):flags|=lane(c,before,i)[1]
 return flags
def csr_expected(c,post=False,before=None):
 import vadd as v
 rows=v.csr_expected(c,post);flags=expected_flags(c,before if before is not None else initial(c)) if post else c['fflags_initial']
 rows[7:]=[flags,c['frm'],(c['frm']<<5)|flags];return rows

def allowed_mask(c,before,i):
 b=c['vlen']//8;off=c['vd']*b+i//8;old=(before[off]>>(i%8))&1
 if active(c,before,i):return {lane(c,before,i)[0]}
 if c['vstart']>=c['vl'] or i<c['vstart']:return {old}
 if i>=c['vl']:
  allowed={old,1}
  # V1.0 permits computed mask tails as if vl=VLMAX, but no tail flags.
  if i<c['vlmax']:allowed.add(lane(c,before,i)[0])
  return allowed
 return {old,1} if c['ma'] else {old}
def overlaps(c):
 return c['vs2']<=c['vd']<c['vs2']+c['group_registers'] or (c['form']=='vv' and c['vs1']<=c['vd']<c['vs1']+c['group_registers'])
def check_isa(c,raw,rc=0,timeout=False):
 import vadd as v
 if rc or timeout:raise ValueError('execution/timeout')
 pre,post,before,after=v.decode(c,raw);x=c['operand']&0xffffffff
 if pre!=csr_expected(c)+[x] or post!=csr_expected(c,True,before)+[x]:raise ValueError('FP CSR/fflags/frm/scalar')
 if raw[-16:]!=struct.pack('<2Q',scalar(c),scalar(c)):raise ValueError('FP scalar bits/boxing/preservation')
 if before!=initial(c):raise ValueError('FP prestate')
 b,e=c['vlen']//8,c['sew']//8;start=c['vd']*b;end=start+(b if comparison(c) else c['group_registers']*b)
 if after[:start]!=before[:start] or after[end:]!=before[end:]:raise ValueError('other register')
 if comparison(c):
  for i in range(c['vlen']):
   if (after[start+i//8]>>(i%8))&1 not in allowed_mask(c,before,i):raise ValueError('FP packed mask bit '+str(i))
 else:
  for i in range((end-start)//e):
   old=before[start+i*e:start+(i+1)*e];actual=after[start+i*e:start+(i+1)*e]
   if active(c,before,i):
    if actual!=lane(c,before,i)[0].to_bytes(e,'little'):raise ValueError('FP active result')
   else:
    agnostic=c['vstart']<c['vl'] and i>=c['vstart'] and ((i>=c['vl'] and c['ta']) or (i<c['vl'] and c['ma']))
    if actual!=old and not (agnostic and actual==b'\xff'*e):raise ValueError('FP inactive/prestart/tail/no-body')
 return True

def check_reference(c,raw,reference):
 # Each packet independently satisfies the same ISA set predicate; compare ONLY
 # deterministic active results and flags, never agnostic tail bytes.
 import vadd as v
 _,post,before,after=v.decode(c,raw);_,refpost,_,refafter=v.decode(c,reference)
 if post[7:10]!=refpost[7:10]:raise ValueError('independent FP flags/frm')
 b,e=c['vlen']//8,c['sew']//8
 for i in range(c['vstart'],c['vl']):
  if active(c,before,i):
   if comparison(c):
    off=c['vd']*b+i//8
    if ((after[off]^refafter[off])>>(i%8))&1:raise ValueError('independent active mask bit')
   else:
    off=c['vd']*b+i*e
    if after[off:off+e]!=refafter[off:off+e]:raise ValueError('independent active FP result')
 return True

def pairs(bits):
 k=fp.constants(bits);s=k['negzero'];names=['zero','negzero','one','negone','two','minsub','maxsub','minnormal','maxfinite','inf','neginf','qnan','snan']
 out=[(n,n,k[n],k[n]) for n in names]
 for a,z in [('zero','negzero'),('negzero','zero'),('one','two'),('two','one'),('negone','one'),('minsub','zero'),('maxsub','minnormal'),('inf','maxfinite'),('neginf','negone')]:out.append((a,z,k[a],k[z]))
 for a in ('qnan','snan'):
  for z in ('one','qnan','snan','inf','zero'):
   out.extend([(a,z,k[a],k[z]),(z,a,k[z],k[a])])
 out.extend([('negative-snan','negative-qnan',k['snan']|s,k['qnan']|s),('negative-minsub','minsub',k['minsub']|s,k['minsub']),('negative-maxsub','negative-minnormal',k['maxsub']|s,k['minnormal']|s)])
 return list(dict.fromkeys(out))

def cases():
 import vadd as v
 template=[c for c in v.integer_cases() if c['mnemonic']=='vadd' and c['form'] in ('vv','vx') and c['sew'] in (32,64) and not c['tag'].startswith('operand') and c['vstart']<c['vlmax']]
 rows=[]
 for op,forms in FORMS.items():
  for form in forms:
   source=[c for c in template if c['form']==('vx' if form=='vf' else 'vv')]
   for old in source:
    if form=='v' and old['tag'] in ('dest-source1','same-sources'):continue
    c=dict(old,family='fpcompare170',mnemonic=op,form=form,frm=0,fflags_initial=0,seed=170)
    prefix=f'{op}-{form}-';suffix=f'w{c["vlen"]}-e{c["sew"]}-{c["lmul"]}-'
    c['id']=prefix+suffix+c['tag'];c['unit']=prefix+suffix+('start' if c['vstart'] else 'zero')
    if comparison(c) and c['tag']=='end-group':
     c['vd']=31
     if form=='vv' and c['group_registers']==8:c['vs1']=8
    rows.append(c)
   for base in [c for c in rows[:] if c['mnemonic']==op and c['form']==form and c['tag']=='length0']:
    k=fp.constants(base['sew']);prefix=base['id'].removesuffix('length0')
    def add(tag,**kw):
     c=dict(base,tag=tag,vl=base['vlmax']);c.update(kw);c['id']=prefix+tag;c['unit']=prefix+('start' if c['vstart'] else 'zero');rows.append(c)
    for na,nz,a,z in pairs(base['sew']):add('semantic-'+na+'-'+nz,vl=1,fp_a=a,fp_b=z)
    for frm in range(5):add('sticky-rm'+str(frm),vl=1,frm=frm,fp_a=k['snan'],fp_b=k['one'],fflags_initial=9)
    for name,vl,start,mask,badlane in [('off',1,0,'off',0),('masked',min(2,base['vlmax']),0,'alternating',1),('tail',1,0,'none',1),('prestart',base['vlmax'],1,'none',0),('zero-vl',0,0,'none',0),('no-body',0,1,'none',0)]:
     if start>=base['vlmax']:continue
     add('suppress-'+name,vl=vl,vstart=start,mask=mask,fp_a=k['snan'],fp_b=k['one'],exception_lane=badlane,fflags_initial=9)
    if form=='vf' and base['sew']==32:
     for name in ('snan','negone','inf'):add('malformed-box-'+name,vl=1,fp_a=k['one'],fp_b=k[name],bad_box=True)
    if comparison(base):
     add('dest-v0-unmasked',vd=0)
     add('dest-v0-masked',vd=0,mask='alternating')
     for source_reg in (base['vs2'],base['vs1']) if form=='vv' else (base['vs2'],):
      add(('mask-source-interior-' if base['group_registers']==1 else 'mask-source-lowest-')+str(source_reg),vd=source_reg,mask='alternating',ta=True,ma=True)
    # QEMU partial and complementary masks use actual old-suite source arrays.
    if QEMU_INPUTS:
     vectors=QEMU_INPUTS[op+'_'+form][str(base['sew'])]
     for name,mask in [('partial','none'),('even','alternating'),('odd','odd')]:
      add('qemu-'+name,vl=base['vlmax']-1 if mask=='none' else base['vlmax'],mask=mask,qemu_vectors=vectors,fp_b=vectors.get('fp_b',[k['one']])[0],qemu_pad=True)
 assert len(rows)==len({c['id'] for c in rows})
 return rows

import json
from pathlib import Path
QEMU_INPUTS=json.loads(Path(__file__).with_name('qemu_fpcompare170.json').read_text()) if Path(__file__).with_name('qemu_fpcompare170.json').exists() else {}
def reserved_declarations():
 return [dict(form=op+'.'+form,obligation=kind,execution='NOT_RUN',expected='reserved encoding') for op,forms in FORMS.items() for form in forms for kind in ('unsupported-EEW8-or16','misaligned-source-group')]+[dict(form=op+'.'+form,obligation='masked-destination-v0',execution='NOT_RUN',expected='reserved encoding') for op,forms in FORMS.items() if not op.startswith('vmf') for form in forms]
