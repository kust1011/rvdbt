#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepared integer comparisons; independent fixed-reference pilot still required.

Shared geometry/capture only. Mask results have EEW=1 and occupy one register.
"""
FORMS={'vmseq':('vv','vx','vi'),'vmsne':('vv','vx','vi'),
       'vmsltu':('vv','vx'),'vmslt':('vv','vx'),
       'vmsleu':('vv','vx','vi'),'vmsle':('vv','vx','vi'),
       'vmsgtu':('vx','vi'),'vmsgt':('vx','vi')}
FUNCT6={name:24+i for i,name in enumerate(FORMS)}

def scalar(c):
    value=c['operand']&0xffffffff
    return value-(1<<32) if value&0x80000000 else value

def element(c,a,z):
    e=c['sew'];mask=(1<<e)-1;a&=mask;z&=mask;op=c['mnemonic']
    if op in ('vmslt','vmsle','vmsgt'):
        a=a-(1<<e) if a>>(e-1) else a
        z=z-(1<<e) if z>>(e-1) else z
    if op=='vmseq':return int(a==z)
    if op=='vmsne':return int(a!=z)
    if op in ('vmslt','vmsltu'):return int(a<z)
    if op in ('vmsle','vmsleu'):return int(a<=z)
    if op in ('vmsgt','vmsgtu'):return int(a>z)
    raise ValueError(op)

def initial(c):
    import vadd as v
    raw=bytearray(v.initial(dict(c,family='next-baseline',seed=146)))
    b=c['vlen']//8;e=c['sew'];size=e//8;mask=(1<<e)-1;sign=1<<(e-1)
    pairs=[(0,0),(mask,mask),(0,1),(1,0),(sign,sign-1),(sign-1,sign),(mask,0),(0,mask),(sign,sign),(1,1)]
    for i in range(c['group_registers']*b//size):
        a,z=pairs[i%len(pairs)]
        for reg,value in [(16,a),(24,z)]:raw[reg*b+i*size:reg*b+(i+1)*size]=value.to_bytes(size,'little')
    if c.get('relocated_source1'):
        raw[c['vs1']*b:(c['vs1']+c['group_registers'])*b]=raw[24*b:(24+c['group_registers'])*b]
    raw[:b]=v.mask_bytes(c)
    return bytes(raw)

def lane(c,before,i):
    b=c['vlen']//8;e=c['sew']//8
    a=int.from_bytes(before[c['vs2']*b+i*e:c['vs2']*b+(i+1)*e],'little')
    z=int.from_bytes(before[c['vs1']*b+i*e:c['vs1']*b+(i+1)*e],'little') if c['form']=='vv' else scalar(c) if c['form']=='vx' else c['operand']
    return element(c,a,z)

def target(c):
    operand=f'v{c["vs1"]}' if c['form']=='vv' else 's0' if c['form']=='vx' else str(c['operand'])
    return f'{c["mnemonic"]}.{c["form"]} v{c["vd"]},v{c["vs2"]},{operand}'+(',v0.t' if c['mask']!='none' else '')

def instruction(c):
    operand=c['vs1'] if c['form']=='vv' else 8 if c['form']=='vx' else c['operand']&31
    return (FUNCT6[c['mnemonic']]<<26)|(int(c['mask']=='none')<<25)|(c['vs2']<<20)|(operand<<15)|({'vv':0,'vx':4,'vi':3}[c['form']]<<12)|(c['vd']<<7)|0x57

def overlap(c):
    return c['vs2']<=c['vd']<c['vs2']+c['group_registers'] or (c['form']=='vv' and c['vs1']<=c['vd']<c['vs1']+c['group_registers'])

def check_isa(c,raw,rc=0,timeout=False):
    import vadd as v
    if rc or timeout:raise ValueError('failed execution/timeout')
    pre,post,before,after=v.decode(c,raw);x=c['operand']&0xffffffff
    if pre!=v.csr_expected(c)+[x] or post!=v.csr_expected(c,True)+[x]:raise ValueError('CSR/scalar mismatch')
    if before!=initial(c):raise ValueError('pre-register mismatch')
    b=c['vlen']//8;vd=c['vd']*b
    if after[:vd]!=before[:vd] or after[vd+b:]!=before[vd+b:]:raise ValueError('preserved non-destination register')
    for i in range(c['vlen']):
        old=before[vd+i//8]>>(i%8)&1;actual=after[vd+i//8]>>(i%8)&1
        enabled=c['mask']=='none' or before[i//8]>>(i%8)&1
        if c['vstart']<=i<c['vl'] and enabled:
            allowed={lane(c,before,i)}
        elif c['vstart']<c['vl'] and i>=c['vl']:
            allowed={old,1}
            if i<c['vlmax']:allowed.add(lane(c,before,i))
        elif c['vstart']<=i<c['vl'] and (c['ma'] or overlap(c)):
            allowed={old,1}
        else:allowed={old}
        if actual not in allowed:raise ValueError('comparison/preserved mask bit '+str(i))
    return True

def check_reference(c,raw,reference):
    import vadd as v
    _,_,before,after=v.decode(c,raw);ref=v.decode(c,reference)[3];vd=c['vd']*(c['vlen']//8)
    for i in range(c['vstart'],c['vl']):
        if c['mask']=='none' or before[i//8]>>(i%8)&1:
            if (after[vd+i//8]>>(i%8)&1)!=(ref[vd+i//8]>>(i%8)&1):raise ValueError('independent comparison bit')
    return True

def cases():
    import vadd as v
    template=[c for c in v.integer_cases() if c['mnemonic']=='vadd'];rows=[]
    for op,forms in FORMS.items():
      for form in forms:
        current=[]
        for old in template:
            if old['form']!=form:continue
            c=dict(old,mnemonic=op,family='compare-next151',seed=152,destination_eew=1,destination_registers=1,execution='NOT_RUN')
            c['id']=old['id'].replace('vadd-',op+'-',1);c['unit']=old['unit'].replace('vadd-',op+'-',1)
            if c['tag']=='end-group':
                c['vd']=31
                if form=='vv' and c['group_registers']>1:c['vs1']=8;c['relocated_source1']=True
            rows.append(c);current.append(c)
        for base in [c for c in current if c['tag']=='length0']:
            def add(tag,**kw):
                c=dict(base,tag=tag,vl=base['vlmax']);c.update(kw);c['id']=base['id'].removesuffix('length0')+tag
                if c['vstart']:c['unit']=base['unit'].removesuffix('zero')+'start'
                rows.append(c)
            add('dest-v0-unmasked',vd=0)
            add('dest-v0-masked',vd=0,mask='alternating')
            if form=='vi':
                for imm in range(-16,16):
                    if imm not in [-16,-1,0,15]:add('operand'+str(imm),operand=imm)
            for bit in [7,8,31,32,63,64,511,512]:
                if 0<bit<min(base['vlmax'],base['vlen']):add('packed-start-partial'+str(bit),vstart=bit,vl=bit+1,mask='alternating',vd=16,ma=False)
    assert len(rows)==len({c['id'] for c in rows})
    return rows

def reserved_declarations():
    return [dict(form=op+'.'+form,kind='mask-destination-overlap-nonlowest-source',requires='LMUL>=2',execution='NOT_RUN',expected='reserved encoding') for op,forms in FORMS.items() for form in forms]
