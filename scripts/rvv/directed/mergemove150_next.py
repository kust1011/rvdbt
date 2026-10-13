#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepared independent merge/move family; no guest admission or runner routing.

v0 is selection data for merge, never an execution mask. Move encodes vs2=0
but does not read it; vm=1. Fixed Spike/Sail packets remain required at admission.
"""
FORMS={'vmerge':('vvm','vxm','vim'),'vmv':('v.v','v.x','v.i')}

def kind(c):return {'v.v':'vv','v.x':'vx','v.i':'vi'}.get(c['form'],c['form'][:2])
def scalar(c):
    value=c['operand']&0xffffffff
    return value-(1<<32) if value&0x80000000 else value

def initial(c):
    import vadd as v
    raw=bytearray(v.initial(dict(c,family='next-baseline',seed=151)))
    b=c['vlen']//8;e=c['sew'];size=e//8;mask=(1<<e)-1
    # Unequal sources, zero/sign boundaries and recognizable complements.
    pairs=[(0,mask),(mask,0),(1,mask-1),(1<<(e-1),(1<<(e-1))-1),
           (0x55&mask,0xaa&mask),(mask//3,mask-mask//3)]
    for i in range(c['group_registers']*b//size):
        a,z=pairs[i%len(pairs)]
        for reg,value in [(16,a),(24,z)]:raw[reg*b+i*size:reg*b+(i+1)*size]=(value&mask).to_bytes(size,'little')
    if c.get('selection_bit') is not None:raw[:b]=(1<<c['selection_bit']).to_bytes(b,'little')
    else:raw[:b]=v.mask_bytes(dict(c,mask=c['selection_pattern']))
    return bytes(raw)

def lane(c,before,i):
    b=c['vlen']//8;e=c['sew']//8;k=kind(c)
    z=int.from_bytes(before[c['vs1']*b+i*e:c['vs1']*b+(i+1)*e],'little') if k=='vv' else scalar(c) if k=='vx' else c['operand']
    if c['mnemonic']=='vmerge' and not (before[i//8]>>(i%8)&1):
        return before[c['vs2']*b+i*e:c['vs2']*b+(i+1)*e]
    return (z&((1<<c['sew'])-1)).to_bytes(e,'little')

def target(c):
    k=kind(c);other=f'v{c["vs1"]}' if k=='vv' else 's0' if k=='vx' else str(c['operand'])
    if c['mnemonic']=='vmv':return f'vmv.{c["form"]} v{c["vd"]},{other}'
    return f'vmerge.{c["form"]} v{c["vd"]},v{c["vs2"]},{other},v0'

def instruction(c):
    k=kind(c);operand=c['vs1'] if k=='vv' else 8 if k=='vx' else c['operand']&31
    return (23<<26)|(int(c['mnemonic']=='vmv')<<25)|(c['vs2']<<20)|(operand<<15)|({'vv':0,'vx':4,'vi':3}[k]<<12)|(c['vd']<<7)|0x57

def check_isa(c,raw,rc=0,timeout=False):
    import vadd as v
    if rc or timeout:raise ValueError('failed execution/timeout')
    pre,post,before,after=v.decode(c,raw);scalar_value=c['operand']&0xffffffff
    if pre!=v.csr_expected(c)+[scalar_value] or post!=v.csr_expected(c,True)+[scalar_value]:raise ValueError('CSR/scalar mismatch')
    if before!=initial(c):raise ValueError('pre-register mismatch')
    b=c['vlen']//8;e=c['sew']//8;vd=c['vd']*b;size=c['group_registers']*b
    if after[:vd]!=before[:vd] or after[vd+size:]!=before[vd+size:]:raise ValueError('preserved non-destination register')
    for i in range(size//e):
        off=vd+i*e;old=before[off:off+e];actual=after[off:off+e]
        if c['vstart']<=i<c['vl']:
            if actual!=lane(c,before,i):raise ValueError('active merge/move element '+str(i))
        elif c['vstart']<c['vl'] and i>=c['vl'] and c['ta']:
            if actual not in (old,b'\xff'*e):raise ValueError('tail allowed set '+str(i))
        elif actual!=old:raise ValueError('preserved prestart/no-body/tail '+str(i))
    return True

def check_reference(c,raw,reference):
    import vadd as v
    # Selection never suppresses comparison of body lanes.
    return v.check_reference(dict(c,family='next-baseline',mask='none'),raw,reference)

def cases():
    import vadd as v
    template=[c for c in v.integer_cases() if c['mnemonic']=='vadd'];rows=[]
    for op,forms in FORMS.items():
      for form in forms:
        k={'v.v':'vv','v.x':'vx','v.i':'vi'}.get(form,form[:2]);current=[]
        for old in template:
            if old['form']!=k:continue
            c=dict(old,mnemonic=op,form=form,family='mergemove-next150',seed=151,mask='none',selection_pattern=old['mask'],execution='NOT_RUN')
            c['id']=old['id'].replace('vadd-',op+'-',1).replace('-'+k+'-','-'+form+'-',1)
            c['unit']=old['unit'].replace('vadd-',op+'-',1).replace('-'+k+'-','-'+form+'-',1)
            if op=='vmv':
                c['vs2']=0
                # The move encoding has no data-source2. Keep the declaration
                # names literal instead of implying a second source operand.
                newtag={'dest-source2':'dest-register16','same-sources':'source-register16'}.get(c['tag'],c['tag'])
                if newtag!=c['tag']:c['id']=c['id'].removesuffix(c['tag'])+newtag;c['tag']=newtag
            rows.append(c);current.append(c)
        for base in [c for c in current if c['tag']=='length0']:
            def add(tag,**kw):
                c=dict(base,tag=tag,vl=base['vlmax']);c.update(kw);c['id']=base['id'].removesuffix('length0')+tag
                if c['vstart']:c['unit']=base['unit'].removesuffix('zero')+'start'
                rows.append(c)
            if k=='vi':
                for imm in range(-16,16):
                    if imm not in [-16,-1,0,15]:add('operand'+str(imm),operand=imm)
            if op=='vmv':
                add('dest-v0',vd=0)
                if k=='vv':
                    add('source-v0',vs1=0,selection_pattern='alternating')
                    add('self-source-v0',vs1=0,vd=0,selection_pattern='alternating')
            else:
                for bit in [0,7,8,31,32,63,64,511,512]:
                    if bit>=base['vlmax']:continue
                    add('select-bit'+str(bit),selection_bit=bit)
                    if 0<bit<base['vlen']:add('select-start-partial'+str(bit),selection_bit=bit,vstart=bit,vl=bit+1,vd=16,ta=True,ma=True)
    assert len(rows)==len({c['id'] for c in rows})
    return rows

def reserved_declarations():
    return [dict(form='vmerge.'+f,kind='destination-v0',execution='NOT_RUN',expected='reserved encoding') for f in FORMS['vmerge']]+[dict(form='vmv.'+f,kind='nonzero-vs2-encoding',execution='NOT_RUN',expected='reserved encoding') for f in FORMS['vmv']]
