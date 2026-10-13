#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepared RVV1.0 averaging family. Runner routed; guest validation NOT_RUN.

Spec sections vxrm and single-width averaging; Spike/Sail packets required
before guest validation credit. Exact SEW+1 sum/difference precedes rounding.
"""
FORMS={op:('vv','vx') for op in ['vaadd','vaaddu','vasub','vasubu']}
FUNCT6={'vaaddu':8,'vaadd':9,'vasubu':10,'vasub':11}

def arithmetic(c,a,z):
    import saturation153 as s
    e=c['sew'];unsigned=c['mnemonic'].endswith('u');limit=(1<<e)-1
    a=a&limit if unsigned else s.signed(a,e);z=z&limit if unsigned else s.signed(z,e)
    value=a+z if c['mnemonic'].startswith('vaadd') else a-z
    if unsigned:value &= (1<<(e+1))-1
    rm=c['vxrm_initial'];discard=value&1;retained=(value>>1)&1
    increment=[discard,discard&retained,0,discard&(1-retained)][rm]
    return (((value>>1)+increment)&limit).to_bytes(e//8,'little')

def initial(c):
    import vadd as v
    raw=bytearray(v.initial(dict(c,family='rounding-baseline',seed=146)))
    b=c['vlen']//8;e=c['sew'];size=e//8;limit=(1<<e)-1;top=limit>>1;bottom=top+1
    pairs=[(0,1),(0,3),(0,5),(0,-1),(0,-3),(0,-5),(1,0),(3,0),(5,0),(-1,0),(-3,0),(-5,0),(2,0),(-2,0),(top,top),(bottom,bottom),(top,bottom),(bottom,top),(limit,limit),(0,limit),(limit,0)]
    for i in range(c['group_registers']*b//size):
        a,z=c.get('tie_pair',pairs[i%len(pairs)])
        for reg,value in [(16,a),(24,z)]:raw[reg*b+i*size:reg*b+(i+1)*size]=(value&limit).to_bytes(size,'little')
    return bytes(raw)

def instruction(c):
    operand=c['vs1'] if c['form']=='vv' else 8
    return (FUNCT6[c['mnemonic']]<<26)|(int(c['mask']=='none')<<25)|(c['vs2']<<20)|(operand<<15)|({'vv':2,'vx':6}[c['form']]<<12)|(c['vd']<<7)|0x57

def check_isa(c,raw,rc=0,timeout=False):
    import vadd as v
    import saturation153 as s
    if rc or timeout:raise ValueError('failed execution/timeout')
    pre,post,before,after=v.decode(c,raw);scalar=c['operand']&0xffffffff
    if pre!=v.csr_expected(c)+[scalar] or post!=v.csr_expected(c,True)+[scalar]:raise ValueError('CSR/scalar mismatch (averaging preserves vxsat/vcsr)')
    if before!=initial(c):raise ValueError('pre-register mismatch')
    b=c['vlen']//8;size=c['sew']//8;vd=c['vd']*b;end=vd+c['group_registers']*b
    if after[:vd]!=before[:vd] or after[end:]!=before[end:]:raise ValueError('non-destination changed')
    for i in range((end-vd)//size):
        off=vd+i*size;old=before[off:off+size];actual=after[off:off+size]
        active=c['vstart']<=i<c['vl'] and (c['mask']=='none' or before[i//8]>>(i%8)&1)
        agnostic=c['vstart']<c['vl'] and i>=c['vstart'] and ((i>=c['vl'] and c['ta']) or (i<c['vl'] and not active and c['ma']))
        if active:
            a=int.from_bytes(before[c['vs2']*b+i*size:c['vs2']*b+(i+1)*size],'little')
            z=int.from_bytes(before[c['vs1']*b+i*size:c['vs1']*b+(i+1)*size],'little') if c['form']=='vv' else s.signed(scalar,32)
            if actual!=arithmetic(c,a,z):raise ValueError('active rounded lane '+str(i))
        elif actual!=old and not(agnostic and actual==b'\xff'*size):raise ValueError('preserved/agnostic lane '+str(i))
    return True

def check_reference(c,raw,reference):
    import vadd as v
    if v.decode(c,raw)[1][4:7]!=v.decode(c,reference)[1][4:7]:raise ValueError('independent reference fixed-point CSR mismatch')
    return v.check_reference(dict(c,family='rounding-baseline'),raw,reference)

def cases():
    import vadd as v
    rows=[];template=[c for c in v.integer_cases() if c['mnemonic']=='vadd' and c['form'] in ('vv','vx')]
    for op in FORMS:
      for old in template:
        for rm in range(4):
          for sat in [0]:
            c=dict(old,mnemonic=op,family='rounding153-next',seed=154,vxrm_initial=rm,vxsat_initial=sat,execution='NOT_RUN')
            c['id']=old['id'].replace('vadd-',op+'-',1)+f'-rm{rm}-sat{sat}'
            c['unit']=old['unit'].replace('vadd-',op+'-',1)+f'-rm{rm}'
            rows.append(c)
      bases=[r for r in rows if r['mnemonic']==op and r['tag']=='length0' and r['vxsat_initial']==0]
      for base in bases:
        e=base['sew'];top=(1<<(e-1))-1;bottom=1<<(e-1)
        for a,z in [(1,0),(3,0),(5,0),(-1,0),(-3,0),(-5,0),(2,0),(-2,0),(top,bottom),(bottom,top),(top,top),(bottom,bottom)]:
            tag=f'tie-pair{a},{z}';c=dict(base,tag=tag,vl=1,mask='none',vd=8,tie_pair=[a,z],operand=z)
            c['id']=base['id'].removesuffix('length0-rm'+str(base['vxrm_initial'])+'-sat0')+tag+'-rm'+str(base['vxrm_initial'])
            rows.append(c)
        for sat in [1]:
            c=dict(base,tag='sticky-no-saturation',vl=base['vlmax'],mask='none',tie_pair=[1,0],operand=0,vxsat_initial=sat)
            c['id']=base['id'].removesuffix('length0-rm'+str(base['vxrm_initial'])+'-sat0')+'sticky-rm'+str(base['vxrm_initial'])
            rows.append(c)
    assert len(rows)==len({c['id'] for c in rows})
    return rows

def reserved_declarations():
    return [dict(form=op+'.vi',status='RESERVED_NOT_EXECUTED',reason='averaging has vv/vx forms only') for op in FORMS]
