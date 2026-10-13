#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepared destructive integer multiply-add; independent fixed-reference execution."""
FORMS={op:('vv','vx') for op in ('vmacc','vnmsac','vmadd','vnmsub')}
FUNCT6={'vmadd':41,'vnmsub':43,'vmacc':45,'vnmsac':47}

def element(c,a,z,d):
    op=c['mnemonic'];e=c['sew']
    if op=='vmacc':r=z*a+d
    elif op=='vnmsac':r=d-z*a
    elif op=='vmadd':r=z*d+a
    elif op=='vnmsub':r=a-z*d
    else:raise ValueError(op)
    return (r% (1<<e)).to_bytes(e//8,'little')

def initial(c):
    import vadd as v
    raw=bytearray(v.initial(dict(c,family='baseline-mac152',seed=146)))
    b=c['vlen']//8;e=c['sew']//8;m=(1<<c['sew'])-1
    triples=[(3,5,7),(m,2,1),(1<<(c['sew']-1),m,3),(0,m,9),(9,0,m),(m,m,m),(17,19,23)]
    for reg,col in [(8,2),(16,0),(24,1)]:
      for i in range(c['group_registers']*b//e):
        value=c.get(('witness_a','witness_z','witness_d')[col],triples[i%len(triples)][col])&m
        raw[reg*b+i*e:reg*b+(i+1)*e]=value.to_bytes(e,'little')
    if c.get("qemu_odd"):raw[:b]=bytes([0xaa])*b
    return bytes(raw)

def lane(c,before,i):
    b=c['vlen']//8;e=c['sew']//8
    def get(reg):return int.from_bytes(before[reg*b+i*e:reg*b+(i+1)*e],'little')
    x=c['operand']&0xffffffff;z=get(c['vs1']) if c['form']=='vv' else x-(1<<32) if x>>31 else x
    return element(c,get(c['vs2']),z,get(c['vd']))

def target(c):
    z=f'v{c["vs1"]}' if c['form']=='vv' else 's0'
    return f'{c["mnemonic"]}.{c["form"]} v{c["vd"]},{z},v{c["vs2"]}'+(',v0.t' if c['mask']!='none' else '')

def instruction(c):
    z=c['vs1'] if c['form']=='vv' else 8
    return FUNCT6[c['mnemonic']]<<26|int(c['mask']=='none')<<25|c['vs2']<<20|z<<15|({'vv':2,'vx':6}[c['form']])<<12|c['vd']<<7|0x57

def check_isa(c,raw,rc=0,timeout=False):
    import vadd as v
    if rc or timeout:raise ValueError('execution/timeout')
    pre,post,before,after=v.decode(c,raw);x=c['operand']&0xffffffff
    if pre!=v.csr_expected(c)+[x] or post!=v.csr_expected(c,True)+[x]:raise ValueError('CSR/scalar')
    if before!=initial(c):raise ValueError('prestate')
    b=c['vlen']//8;e=c['sew']//8;vd=c['vd']*b;end=vd+c['group_registers']*b
    if after[:vd]!=before[:vd] or after[end:]!=before[end:]:raise ValueError('other register')
    for i in range((end-vd)//e):
      old=before[vd+i*e:vd+(i+1)*e];actual=after[vd+i*e:vd+(i+1)*e]
      active=c['vstart']<=i<c['vl'] and (c['mask']=='none' or before[i//8]>>(i%8)&1)
      agnostic=c['vstart']<c['vl'] and i>=c['vstart'] and ((i>=c['vl'] and c['ta']) or (i<c['vl'] and not active and c['ma']))
      if active:
        if actual!=lane(c,before,i):raise ValueError('destructive active lane '+str(i))
      elif actual!=old and not (agnostic and actual==b'\xff'*e):raise ValueError('preserved lane '+str(i))
    return True

def check_reference(c,raw,reference):
    import vadd as v
    if not c.get('qemu_odd'):return v.check_reference(dict(c,family='baseline-mac152'),raw,reference)
    before=v.decode(c,raw)[2];after=v.decode(c,raw)[3];expected=v.decode(c,reference)[3];b=c['vlen']//8;e=c['sew']//8
    for i in range(c['vstart'],c['vl']):
      if before[i//8]>>(i%8)&1:
        off=c['vd']*b+i*e
        if after[off:off+e]!=expected[off:off+e]:raise ValueError('independent reference active mismatch')
    return True

def cases():
    import vadd as v
    template=[c for c in v.integer_cases() if c['mnemonic']=='vadd' and c['form']!='vi'];rows=[]
    for op in FORMS:
      current=[]
      for old in template:
        c=dict(old,mnemonic=op,family='mac154',seed=154)
        c['id']=old['id'].replace('vadd-',op+'-',1);c['unit']=old['unit'].replace('vadd-',op+'-',1)
        rows.append(c);current.append(c)
      for base in [c for c in current if c['tag']=='length0']:
        for label,a,z,d in [('distinct',3,5,7),('wrap',(1<<base['sew'])-1,2,1),('zero-product',0,7,9),('negative-scalar',17,0xffffffff,23)]:
          c=dict(base,tag='witness-'+label,vl=base['vlmax'],witness_a=a,witness_z=z,witness_d=d,operand=z)
          c['id']=base['id'].removesuffix('length0')+c['tag'];rows.append(c)
        c=dict(base,tag='dest-both-sources',vd=16,vs1=16,vl=base['vlmax'])
        c['id']=base['id'].removesuffix('length0')+c['tag'];rows.append(c)
    assert len(rows)==len({c['id'] for c in rows})
    return rows

def reserved_declarations():
    return [dict(form=op+'.'+form,kind=kind,execution='NOT_RUN',expected='reserved encoding') for op,forms in FORMS.items() for form in forms for kind in ('masked-nonmask-destination-overlap-v0','misaligned-integer-LMUL-group')]


def qemu_cases():
    """New Task154 source-inspired scenarios; distinct from prepared full manifest."""
    rows=[]
    for base in cases():
      if base['tag']!='length0' or (base['vlen'],base['sew'],base['lmul']) not in [(128,8,'m1'),(128,64,'m4'),(1024,8,'m8'),(4096,8,'m8')]:continue
      for tag,mask,vl,odd in [('qemu-partial','none',base['vlmax']-1,False),('qemu-even','alternating',base['vlmax'],False),('qemu-odd','alternating',base['vlmax'],True)]:
        c=dict(base,tag=tag,mask=mask,vl=vl,qemu_odd=odd,witness_d=int.from_bytes(bytes([0x11])*(base['sew']//8),'little'),operand=0x55667788)
        c['id']=base['id'].removesuffix('length0')+tag;c['unit']=base['unit']+'-qemu';rows.append(c)
    return rows
