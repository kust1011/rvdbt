#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite single-width shift and signed/unsigned min/max forms."""
FORMS={'vsll':('vv','vx','vi'),'vsrl':('vv','vx','vi'),'vsra':('vv','vx','vi'),
       'vmin':('vv','vx'),'vminu':('vv','vx'),'vmax':('vv','vx'),'vmaxu':('vv','vx')}
FUNCT6={'vsll':37,'vsrl':40,'vsra':41,'vminu':4,'vmin':5,'vmaxu':6,'vmax':7}

def cases():
    import vadd as v
    # Inherit all geometry, masks, policies, length, overlap and start obligations.
    template=[c for c in v.integer_cases() if c['mnemonic']=='vadd']
    rows=[]
    for op,forms in FORMS.items():
      for old in template:
        if old['form'] not in forms:continue
        c=dict(old,mnemonic=op,family='shiftminmax148',seed=148)
        c['id']=old['id'].replace('vadd-',op+'-',1);c['unit']=old['unit'].replace('vadd-',op+'-',1)
        if c['form']=='vi':
          c['operand']=old['operand']&31 if c['tag'].startswith('operand') else 31
          # Existing operand tag must match unsigned encoding.
          if c['tag'].startswith('operand'):
            c['tag']='operand'+str(c['operand']);c['id']=c['unit'].removesuffix('-zero')+'-'+c['tag']
        rows.append(c)
      bases=[c for c in rows if c['mnemonic']==op and c['tag']=='length0']
      for base in bases:
        e=base['sew'];n=base['vlmax'];form=base['form']
        def add(tag,operand=None,mask='none',start=0,vd=8,vl=None,ta=False,ma=False):
          c=dict(base,tag=tag,operand=base['operand'] if operand is None else operand,mask=mask,vstart=start,vd=vd,vl=n if vl is None else vl,ta=ta,ma=ma)
          c['unit']=base['unit'].removesuffix('-zero')+('-start' if start else '-zero')
          c['id']=base['id'].removesuffix('length0')+tag
          rows.append(c)
        if form=='vi':
          existing={c['operand'] for c in rows if c['unit']==base['unit'] and c['tag'].startswith('operand')}
          for value in range(32):
            if value not in existing:add('operand'+str(value),value)
        elif form=='vx':
          existing={c['operand'] for c in rows if c['unit']==base['unit'] and c['tag'].startswith('operand')}
          edges={1,7,8,15,16,31,32,63,64,127,128,255,e-1,e,e+1,0x8000001f,0xffffffdf}
          for value in sorted(edges-existing):add('operand'+str(value),value)
        else:add('count-edges' if op.startswith('vs') else 'comparison-edges')
        # Default baseline has diverse pairs; equal operand tie preserves value.
        if form=='vv':add('equal-operands',vd=8);rows[-1]['vs1']=16
        # Count/scalar edges combined with overlap, partial VL, mask and start.
        if form!='vv':
          edge=31 if form=='vi' else 0xffffffff
          add('edge-start-overlap',edge,'alternating',1,16,max(1,n-1),True,True)
    assert len(rows)==len({c['id'] for c in rows})
    return rows

def arithmetic(c,a,z):
    e=c['sew'];mask=(1<<e)-1;a&=mask;z&=mask
    signed=lambda x:x-(1<<e) if x&(1<<(e-1)) else x
    op=c['mnemonic'];count=z&(e-1)
    if op=='vsll':result=a<<count
    elif op=='vsrl':result=a>>count
    elif op=='vsra':result=signed(a)>>count
    elif op=='vmin':result=min(signed(a),signed(z))
    elif op=='vmax':result=max(signed(a),signed(z))
    elif op=='vminu':result=min(a,z)
    elif op=='vmaxu':result=max(a,z)
    else:raise ValueError('unknown shift/minmax operation')
    return (result&mask).to_bytes(e//8,'little')

def initial(c):
    import vadd as v
    raw=bytearray(v.initial(dict(c,family='baseline148',seed=146)))
    b=c['vlen']//8;e=c['sew'];size=e//8;mask=(1<<e)-1;sign=1<<(e-1)
    data=[mask,sign,sign-1,0,1,sign+1,mask-1,0x1122334480000001,0x80000000,0x7fffffff,0xffffffff]
    other=([e-1,e+1,0,1,e,2*e-1,2*e,mask,31,32,63,64,0x80000001]
           if c['mnemonic'].startswith('vs') else [1,sign-1,sign,mask,0,sign+1,mask-1,0x1122334480000001,0xffffffff,0x80000000,0x7fffffff])
    for base,patterns in [(16,data),(24,other)]:
      for i in range(c['group_registers']*b//size):
        raw[base*b+i*size:base*b+(i+1)*size]=(patterns[i%len(patterns)]&mask).to_bytes(size,'little')
    return bytes(raw)
