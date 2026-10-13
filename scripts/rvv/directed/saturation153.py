#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""RVV1.0 single-width saturation: spec predicates plus executed Spike/Sail.

Scalar/immediate operands sign extend to SEW, including unsigned operations.
Only active lanes accrue vxsat. No predicate is sourced from the DUT.
"""
FORMS={'vsadd':('vv','vx','vi'),'vsaddu':('vv','vx','vi'),'vssub':('vv','vx'),'vssubu':('vv','vx')}
FUNCT6={'vsaddu':32,'vsadd':33,'vssubu':34,'vssub':35}

def signed(x,e):
    x &= (1<<e)-1
    return x-(1<<e) if x&(1<<(e-1)) else x

def result(c,a,z):
    e=c['sew'];unsigned=c['mnemonic'].endswith('u');limit=(1<<e)-1
    a=a&limit if unsigned else signed(a,e);z=z&limit if unsigned else signed(z,e)
    value=a+z if c['mnemonic'].startswith('vsadd') else a-z
    low,high=(0,limit) if unsigned else (-(1<<(e-1)),(1<<(e-1))-1)
    return min(high,max(low,value))&limit,not low<=value<=high

def arithmetic(c,a,z):return result(c,a,z)[0].to_bytes(c['sew']//8,'little')

def pair(c,which):
    e=c['sew'];top=(1<<(e-1))-1;bottom=1<<(e-1);limit=(1<<e)-1
    op=c['mnemonic']
    if which=='safe':return (0,1) if op!='vssubu' else (1,1)
    if which=='negative':return (bottom,-1) if op=='vsadd' else (bottom,1) if op=='vssub' else (0,1) if op=='vssubu' else (limit,1)
    return (top,1) if op=='vsadd' else (top,-1) if op=='vssub' else (0,1) if op=='vssubu' else (limit,1)

def initial(c):
    import vadd as v
    raw=bytearray(v.initial(dict(c,family='baseline153',seed=146)))
    b=c['vlen']//8;size=c['sew']//8;limit=(1<<c['sew'])-1
    top=limit>>1;bottom=top+1
    patterns=[(top,1),(bottom,-1),(top,0),(bottom,0),(limit,1),(0,1),(1,1),(top,-1),(bottom,1),(limit,0),(0,0),(limit,limit)]
    for i in range(c['group_registers']*b//size):
        a,z=c.get('pair_override',patterns[i%len(patterns)])
        if 'witness' in c:
            a,z=pair(c,c['witness'] if i==c.get('sat_lane',-1) else 'safe')
        for reg,value in [(16,a),(24,z)]:raw[reg*b+i*size:reg*b+(i+1)*size]=(value&limit).to_bytes(size,'little')
    return bytes(raw)

def saturation(c):
    import vadd as v
    before=initial(c);b=c['vlen']//8;size=c['sew']//8;sat=c['vxsat_initial']
    scalar=signed(c['operand'],32) if c['form']=='vx' else c['operand']
    for i in range(c['vstart'],c['vl']):
        if c['mask']!='none' and not(before[i//8]>>(i%8)&1):continue
        a=int.from_bytes(before[c['vs2']*b+i*size:c['vs2']*b+(i+1)*size],'little')
        z=int.from_bytes(before[c['vs1']*b+i*size:c['vs1']*b+(i+1)*size],'little') if c['form']=='vv' else scalar
        sat |= result(c,a,z)[1]
    return int(sat)

def cases():
    import vadd as v
    template=[c for c in v.integer_cases() if c['mnemonic']=='vadd'];rows=[]
    for op,forms in FORMS.items():
      for old in template:
        if old['form'] not in forms:continue
        for sat in [0,1]:
            c=dict(old,mnemonic=op,family='saturation153',seed=153,vxsat_initial=sat,vxrm_initial=2)
            c['id']=old['id'].replace('vadd-',op+'-',1)+'-sat'+str(sat)
            c['unit']=old['unit'].replace('vadd-',op+'-',1)
            rows.append(c)
      bases=[c for c in rows if c['mnemonic']==op and c['tag']=='length0' and c['vxsat_initial']==0]
      for base in bases:
        n=base['vlmax'];chunk=512//base['sew']
        def add(tag,**kw):
            c=dict(base,tag=tag,vl=n,mask='none',vd=8,witness='positive',sat_lane=0);c.update(kw)
            c['id']=base['id'].removesuffix('length0-sat0')+tag
            c['unit']=base['unit'].removesuffix('zero')+('start' if c['vstart'] else 'zero')
            rows.append(c)
        # Fixed scalar for witnesses; the safe pair matches subtraction operand.
        operand=pair(base,'positive')[1]
        for mode in ['positive','negative']:
          for sticky in [0,1]:
            add('witness-'+mode+'-sat'+str(sticky),witness=mode,operand=pair(base,mode)[1],vxsat_initial=sticky,vl=1)
        add('witness-safe-clear',witness='safe',operand=1)
        add('witness-safe-sticky',witness='safe',operand=1,vxsat_initial=1)
        add('witness-masked-only',operand=operand,mask='off',ta=True,ma=True)
        add('witness-zero-only',operand=operand,vl=0,ta=True,ma=True)
        if n>1:
            add('witness-prestart-only',operand=operand,vstart=1,ta=True,ma=True)
            add('witness-tail-only',operand=operand,sat_lane=n-1,vl=n-1,ta=True,ma=True)
            add('witness-masked-partial',operand=operand,sat_lane=1,mask='alternating',vl=min(n,chunk+1),ta=True,ma=True)
        for lane in [chunk-1,chunk,chunk+1]:
            if lane<n and lane<base['vlen']:
                add('witness-chunk'+str(lane),operand=operand,sat_lane=lane,vstart=lane,vl=min(n,lane+2),mask='all',vd=16)
        if base['form']=='vi':
            for imm in range(-16,16):
                if imm not in [-16,-1,0,15]:add('immediate'+str(imm),operand=imm,witness='positive')
    assert len(rows)==len({c['id'] for c in rows})
    return rows

def reserved_declarations():
    return [dict(form=op+'.vi',status='RESERVED_NOT_EXECUTED',reason='RVV1.0 defines no saturating subtract immediate') for op in ['vssub','vssubu']]

def boundary_cases():
    """Exact range endpoints versus one-step overflow, isolated active lane.

    All legal geometries at VLEN128 plus all SEWs at m1 for other VLENs.
    This finite supplement never changes cases() or the original full manifest.
    """
    rows=[]
    for base in cases():
      if base['tag']!='length0' or base['vxsat_initial']!=0:continue
      if base['vlen']!=128 and base['lmul']!='m1':continue
      e=base['sew'];top=(1<<(e-1))-1;bottom=1<<(e-1);limit=(1<<e)-1;op=base['mnemonic']
      if op=='vsadd':pairs=[('upper-exact',top,0),('lower-exact',bottom,0),('upper-inside-step',top-1,1),('lower-inside-step',bottom+1,-1),('upper-overflow',top,1),('lower-overflow',bottom,-1)]
      elif op=='vssub':pairs=[('upper-exact',top,0),('lower-exact',bottom,0),('upper-inside-step',top-1,-1),('lower-inside-step',bottom+1,1),('upper-overflow',top,-1),('lower-overflow',bottom,1)]
      elif op=='vsaddu':pairs=[('upper-exact',limit,0),('lower-exact',0,0),('upper-inside-step',limit-1,1),('upper-overflow',limit,1)]
      else:pairs=[('upper-exact',limit,0),('lower-exact',0,0),('lower-inside-step',1,1),('lower-overflow',0,1)]
      for tag,a,z in pairs:
        for sat in [0,1]:
          c=dict(base,family='saturation153-boundary',tag='boundary-'+tag,vl=1,mask='none',vstart=0,vd=8,operand=z,pair_override=[a,z],vxsat_initial=sat)
          c['unit']=base['unit'].removesuffix('zero')+'boundary-zero'
          c['id']=c['unit']+'-'+tag+'-sat'+str(sat);rows.append(c)
    assert len(rows)==len({c['id'] for c in rows})
    return rows
