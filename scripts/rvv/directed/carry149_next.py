#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Carry/borrow finite family, routed through the shared runner as carry150.

Reuse capture state and fixed independent packets after separate pilot admission.
Carry input is data, never an execution mask. Mask results have EEW=1/EMUL=1.
"""
FORMS={'vadc':('vvm','vxm','vim'), 'vsbc':('vvm','vxm'),
       'vmadc':('vvm','vxm','vim','vv','vx','vi'),
       'vmsbc':('vvm','vxm','vv','vx')}
FUNCT6={'vadc':16,'vmadc':17,'vsbc':18,'vmsbc':19}

def mask_result(c):return c['mnemonic'] in ('vmadc','vmsbc')
def with_input(c):return c['form'].endswith('m')
def operand_form(c):return c['form'][:2]
def scalar(c):
    value=c['operand']&0xffffffff
    return value-(1<<32) if value&0x80000000 else value

def element(c,a,z,cin):
    e=c['sew'];mask=(1<<e)-1;a&=mask;z&=mask
    carry=cin if with_input(c) else 0
    if c['mnemonic'] in ('vadc','vmadc'):wide=a+z+carry
    else:wide=a-z-carry
    if c['mnemonic']=='vmadc':return int(wide>mask)
    if c['mnemonic']=='vmsbc':return int(wide<0)
    return (wide&mask).to_bytes(e//8,'little')

def initial(c):
    import vadd as v
    raw=bytearray(v.initial(dict(c,family='next-baseline',seed=146)))
    b=c['vlen']//8;e=c['sew'];size=e//8;mask=(1<<e)-1
    # Carry toggles a==MAX,z==0; borrow toggles a==z==0. Also unsigned sign edges.
    pairs=[(mask,0),(0,0),(mask,1),(0,1),(1,mask),(mask,mask),(1<<(e-1),(1<<(e-1))-1),(0,mask)]
    for i in range(c['group_registers']*b//size):
        a,z=(c['witness_a'],c['witness_z']) if 'witness_a' in c else pairs[i%len(pairs)]
        for base,value in [(16,a),(24,z)]:raw[base*b+i*size:base*b+(i+1)*size]=(value&mask).to_bytes(size,'little')
    if c.get('relocated_source1'):
        raw[c['vs1']*b:(c['vs1']+c['group_registers'])*b]=raw[24*b:(24+c['group_registers'])*b]
    raw[:b]=((1<<c['carry_bit']).to_bytes(b,'little') if 'carry_bit' in c else v.mask_bytes(dict(c,mask=c['carry_pattern'])))
    return bytes(raw)

def target(c):
    form=operand_form(c);other=f'v{c["vs1"]}' if form=='vv' else 's0' if form=='vx' else str(c['operand'])
    return f'{c["mnemonic"]}.{c["form"]} v{c["vd"]},v{c["vs2"]},{other}'+(',v0' if with_input(c) else '')

def instruction(c):
    form=operand_form(c);f3={'vv':0,'vx':4,'vi':3}[form]
    operand=c['vs1'] if form=='vv' else 8 if form=='vx' else c['operand']&31
    return (FUNCT6[c['mnemonic']]<<26)|(int(not with_input(c))<<25)|(c['vs2']<<20)|(operand<<15)|(f3<<12)|(c['vd']<<7)|0x57

def lane(c,before,i):
    b=c['vlen']//8;e=c['sew']//8
    a=int.from_bytes(before[c['vs2']*b+i*e:c['vs2']*b+(i+1)*e],'little')
    form=operand_form(c)
    z=int.from_bytes(before[c['vs1']*b+i*e:c['vs1']*b+(i+1)*e],'little') if form=='vv' else scalar(c) if form=='vx' else c['operand']
    cin=(before[i//8]>>(i%8))&1
    return element(c,a,z,cin)

def check_isa(c,raw,rc=0,timeout=False):
    import vadd as v
    if rc or timeout:raise ValueError('failed execution/timeout')
    pre,post,before,after=v.decode(c,raw)
    scalar_value=c['operand']&0xffffffff
    if pre!=v.csr_expected(c)+[scalar_value] or post!=v.csr_expected(c,True)+[scalar_value]:raise ValueError('CSR/scalar mismatch')
    if before!=initial(c):raise ValueError('pre-register mismatch')
    b=c['vlen']//8;vd=c['vd']*b;size=b if mask_result(c) else c['group_registers']*b
    if after[:vd]!=before[:vd] or after[vd+size:]!=before[vd+size:]:raise ValueError('preserved non-destination register')
    executed=c['vstart']<c['vl']
    if mask_result(c):
        for i in range(c['vlen']):
            old=before[vd+i//8]>>(i%8)&1;actual=after[vd+i//8]>>(i%8)&1
            if c['vstart']<=i<c['vl']:
                if actual!=lane(c,before,i):raise ValueError('active carry/borrow bit '+str(i))
            elif executed and i>=c['vl']:
                allowed={old,1}
                if i<c['vlmax']:allowed.add(lane(c,before,i))
                if actual not in allowed:raise ValueError('mask-tail allowed set '+str(i))
            elif actual!=old:raise ValueError('prestart/no-body mask bit '+str(i))
    else:
        e=c['sew']//8
        for i in range(size//e):
            off=vd+i*e;old=before[off:off+e];actual=after[off:off+e]
            if c['vstart']<=i<c['vl']:
                if actual!=lane(c,before,i):raise ValueError('active sum/difference '+str(i))
            elif executed and i>=c['vl'] and c['ta']:
                if actual not in (old,b'\xff'*e):raise ValueError('sum-tail allowed set '+str(i))
            elif actual!=old:raise ValueError('preserved sum/difference '+str(i))
    return True

def check_reference(c,raw,reference):
    import vadd as v
    after=v.decode(c,raw)[3];ref=v.decode(c,reference)[3];b=c['vlen']//8;vd=c['vd']*b;e=c['sew']//8
    for i in range(c['vstart'],c['vl']):
        if mask_result(c):
            if (after[vd+i//8]>>(i%8)&1)!=(ref[vd+i//8]>>(i%8)&1):raise ValueError('independent carry/borrow bit')
        elif after[vd+i*e:vd+(i+1)*e]!=ref[vd+i*e:vd+(i+1)*e]:raise ValueError('independent sum/difference')
    return True

def cases():
    import vadd as v
    template=[c for c in v.integer_cases() if c['mnemonic']=='vadd'];rows=[]
    for op,forms in FORMS.items():
      for form in forms:
        underlying=form[:2];current=[]
        for old in template:
          if old['form']!=underlying:continue
          c=dict(old,mnemonic=op,form=form,family='carry150',seed=150,mask='none',carry_pattern=old['mask'],carry_input=form.endswith('m'),destination_eew=1 if op.startswith('vm') else old['sew'],destination_registers=1 if op.startswith('vm') else old['group_registers'])
          c['id']=old['id'].replace('vadd-',op+'-',1).replace('-'+underlying+'-','-'+form+'-',1)
          c['unit']=old['unit'].replace('vadd-',op+'-',1).replace('-'+underlying+'-','-'+form+'-',1)
          if op.startswith('vm') and c['tag']=='end-group':
              c['vd']=31
              if underlying=='vv' and c['group_registers']>1:
                  c['vs1']=8;c['relocated_source1']=True
          rows.append(c);current.append(c)
        for base in [c for c in current if c['tag']=='length0']:
          def add(tag,**kwargs):
            c=dict(base,tag=tag,vl=base['vlmax']);c.update(kwargs);c['id']=base['id'].removesuffix('length0')+tag;rows.append(c);return c
          e=base['sew'];m=(1<<e)-1
          for label,a,z in [('toggle-carry',m,0),('toggle-borrow',0,0),('max-plus-one',m,1),('zero-minus-one',0,1),('unsigned-order',1<<(e-1),(1<<(e-1))-1)]:
            for bit,pattern in [(0,'off'),(1,'all')]:
              values=dict(witness_a=a,witness_z=z,carry_pattern=pattern)
              if underlying=='vx':
                  values['operand']=z if e<=32 or z<0x80000000 else 0x80000000
                  reg=values['operand']&0xffffffff
                  values['witness_z']=(reg-(1<<32) if reg&0x80000000 else reg)&m
              elif underlying=='vi':
                  values['operand']=-1 if z==m else 0 if z==0 else 1
                  values['witness_z']=values['operand']&m
              add('witness-'+label+'-cin'+str(bit),**values)
          # Packed carry-bit boundaries and source-chunk crossings, with active
          # single-bit input plus start/partial VL/overlap interaction.
          for bit in [0,7,8,31,32,63,64,511,512]:
              if bit>=base['vlmax']:continue
              values=dict(carry_pattern='single-on',carry_bit=bit,witness_a=m if op in ('vadc','vmadc') else 0,witness_z=0,operand=0)
              add('carry-bit'+str(bit),**values)
              if 0<bit<base['vlen']:
                  add('carry-bit-start-partial'+str(bit),**dict(values,vstart=bit,vl=bit+1,vd=16,ta=True,ma=True))
                  rows[-1]['unit']=base['unit'].removesuffix('zero')+'start'
          if underlying=='vi':
            for imm in range(-16,16):
              if imm not in [-16,-1,0,15]:add('operand'+str(imm),operand=imm)
          if op.startswith('vm'):add('dest-v0',vd=0,carry_pattern='alternating')
    assert len(rows)==len({c['id'] for c in rows})
    return rows

def reserved_declarations():
    # Explicit denominator kept separate from legal execution; no trap handler tests.
    result=[]
    for op,forms in FORMS.items():
      for form in forms:
        if op in ('vadc','vsbc'):
          result.append(dict(form=op+'.'+form,kind='vd-v0',expected='reserved encoding',execution='NOT_RUN'))
          result.append(dict(form=op+'.'+form,kind='vm1-no-carry',expected='reserved encoding',execution='NOT_RUN'))
        if form.endswith('m'):result.append(dict(form=op+'.'+form,kind='v0-vector-source-and-carry-EEW-conflict',expected='reserved encoding',execution='NOT_RUN'))
        if op.startswith('vm'):result.append(dict(form=op+'.'+form,kind='mask-destination-overlap-nonlowest-source-register',requires='LMUL>=2',expected='reserved encoding',execution='NOT_RUN'))
    return result
