#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Widening integer MAC: captured wide addend and narrow signedness roles."""
import widen154_next as w
FORMS={'vwmaccu':('vv','vx'),'vwmacc':('vv','vx'),'vwmaccsu':('vv','vx'),'vwmaccus':('vx',)}
FUNCT6={'vwmaccu':60,'vwmacc':61,'vwmaccus':62,'vwmaccsu':63}
vector=w.vector
wide=w.wide
def validate(c):
    w.validate(c)
    d=set(range(c['vd'],c['vd']+c['dest_registers']))
    sources=[(c['vs2'],c['group_registers'])]+([(c['vs1'],c['group_registers'])] if vector(c) else [])
    assert all(not d.intersection(range(reg,reg+regs)) for reg,regs in sources), 'wide addend is a source: two source EEWs are reserved'
    return True
overlap_agnostic=w.overlap_agnostic
check_reference=w.check_reference

def element(c,a,z,d):
    e=c['sew'];m=(1<<e)-1;a&=m;z&=m
    if c['mnemonic'] in ('vwmacc','vwmaccus'):a=w.signed(a,e)
    if c['mnemonic'] in ('vwmacc','vwmaccsu'):z=w.signed(z,e)
    return ((d+a*z)%(1<<(2*e))).to_bytes(e//4,'little')

def initial(c):
    import vadd as v
    raw=bytearray(v.initial(dict(c,family='baseline-wmac156',seed=146,mask='alternating' if c['mask']=='qemu-odd' else c['mask'])))
    b=c['vlen']//8;e=c['sew']//8;de=2*e;m=(1<<c['sew'])-1;dm=(1<<(2*c['sew']))-1
    ds=[7,dm,1<<c['sew'],(1<<(2*c['sew']-1))+3,0,dm-2,23]
    aa=[3,m,m,3,1<<(c['sew']-1),0,17,m//2]
    zz=[5,2,m,m,m,7,19,m//2]
    for i in range(c['dest_registers']*b//de):
      value=c.get('witness_d',int.from_bytes(bytes([0x11])*de,'little') if c['tag'].startswith('qemu-') else ds[i%len(ds)])&dm
      raw[c['vd']*b+i*de:c['vd']*b+(i+1)*de]=value.to_bytes(de,'little')
    for reg,values,key in [(c['vs2'],aa,'witness_a'),(c['vs1'],zz,'witness_z')]:
      if reg==c['vs1'] and not vector(c):continue
      for i in range(c['group_registers']*b//e):
        raw[reg*b+i*e:reg*b+(i+1)*e]=(c.get(key,values[i%len(values)])&m).to_bytes(e,'little')
    if c['mask']=='qemu-odd':raw[:b]=bytes([0xaa])*b
    return bytes(raw)

def lane(c,before,i):
    b=c['vlen']//8;e=c['sew']//8;de=2*e
    def get(reg,size):return int.from_bytes(before[reg*b+i*size:reg*b+(i+1)*size],'little')
    # RV32 scalar is truncated to source SEW before the operation's sign/zero extension.
    z=get(c['vs1'],e) if vector(c) else c['operand']&0xffffffff
    return element(c,get(c['vs2'],e),z,get(c['vd'],de))

def target(c):
    z=f'v{c["vs1"]}' if vector(c) else 's0'
    return f'{c["mnemonic"]}.{c["form"]} v{c["vd"]},{z},v{c["vs2"]}'+(',v0.t' if c['mask']!='none' else '')

def instruction(c):
    z=c['vs1'] if vector(c) else 8
    return FUNCT6[c['mnemonic']]<<26|int(c['mask']=='none')<<25|c['vs2']<<20|z<<15|(2 if vector(c) else 6)<<12|c['vd']<<7|0x57

def cases():
    template=[c for c in w.cases() if c['mnemonic']=='vwmulu' and not c['tag'].startswith('dest-high-')];rows=[]
    for op,forms in FORMS.items():
      for old in template:
        if old['form'] not in forms:continue
        c=dict(old,mnemonic=op,family='wmac156',seed=156)
        c['id']=old['id'].replace('vwmulu-',op+'-',1);c['unit']=old['unit'].replace('vwmulu-',op+'-',1)
        if c['vd']==16:c['vd']=8
        validate(c);rows.append(c)
      for base in [c for c in rows if c['mnemonic']==op and c['tag']=='length0']:
        e=base['sew'];m=(1<<e)-1;dm=(1<<(2*e))-1
        for label,a,z,d in [('distinct',3,5,7),('unsigned-signed',m,2,(1<<e)+7),('signed-unsigned',3,m,(1<<(2*e-1))+7),('both-negative',m,m,dm),('wrap',m,2,dm),('wide-addend',0,7,1<<e)]:
          c=dict(base,tag='witness-'+label,vl=base['vlmax'],witness_a=a,witness_z=z,witness_d=d,operand=z)
          c['id']=base['id'].removesuffix('length0')+c['tag'];rows.append(c)
    assert len(rows)==len({c['id'] for c in rows})
    return rows

def reserved_declarations():
    return [dict(form=op+'.'+form,kind=kind,execution='NOT_RUN',expected='reserved encoding') for op,forms in FORMS.items() for form in forms for kind in ['destination-EMUL16','destination-EEW128','misaligned-wide-group','low-part-narrow-source-overlap','fractional-narrow-source-overlap','masked-destination-v0','wide-addend-narrow-source-overlap-even-high-part']]+[dict(form='vwmaccus.vv',kind='unallocated-form',execution='NOT_RUN',expected='reserved encoding')]

def check_isa(c,raw,rc=0,timeout=False):
    import vadd as v
    if rc or timeout:raise ValueError('execution/timeout')
    pre,post,before,after=v.decode(c,raw);x=c['operand']&0xffffffff
    if pre!=v.csr_expected(c)+[x] or post!=v.csr_expected(c,True)+[x]:raise ValueError('CSR/scalar')
    if before!=initial(c):raise ValueError('prestate')
    b=c['vlen']//8;de=c['sew']//4;vd=c['vd']*b;end=vd+c['dest_registers']*b
    if after[:vd]!=before[:vd] or after[end:]!=before[end:]:raise ValueError('other register')
    overlap=overlap_agnostic(c)
    for i in range((end-vd)//de):
      old=before[vd+i*de:vd+(i+1)*de];actual=after[vd+i*de:vd+(i+1)*de]
      active=c['vstart']<=i<c['vl'] and (c['mask']=='none' or before[i//8]>>(i%8)&1)
      agnostic=c['vstart']<c['vl'] and i>=c['vstart'] and ((i>=c['vl'] and (c['ta'] or overlap)) or (i<c['vl'] and not active and (c['ma'] or overlap)))
      if active:
        if actual!=lane(c,before,i):raise ValueError('widened active lane '+str(i))
      elif actual!=old and not (agnostic and actual==b'\xff'*de):raise ValueError('preserved lane '+str(i))
    return True


def destination_chunk_cases():
    """Additive finite delta: destination chunk is half the narrow-source chunk."""
    rows=[]
    existing=cases()
    keys=['mnemonic','form','vlen','sew','lmul','vl','mask','ta','ma','vstart','vd','vs2','vs1','operand','witness_a','witness_z','witness_d']
    def key(c):return tuple(c.get(k) for k in keys)+(c['tag'].startswith('qemu-'),)
    seen={key(c) for c in existing}
    for base in existing:
      if base['tag']!='length0':continue
      chunk=512//(2*base['sew']);n=base['vlmax']
      for vl in [chunk-1,chunk,chunk+1]:
        if not 0<vl<=n:continue
        for mask in ['none','alternating']:
          tag=f'destchunk-length{vl}-{mask}'
          c=dict(base,tag=tag,vl=vl,mask=mask,unit=base['unit'].removesuffix('zero')+'destchunk-zero',id=base['id'].removesuffix('length0')+tag)
          validate(c)
          if key(c) not in seen:rows.append(c);seen.add(key(c))
      vl=min(n,chunk+2)
      for start in [chunk-1,chunk,chunk+1]:
        if not 0<start<vl:continue
        for mask in ['none','alternating']:
          tag=f'destchunk-start{start}-{mask}'
          c=dict(base,tag=tag,vl=vl,vstart=start,mask=mask,unit=base['unit'].removesuffix('zero')+'destchunk-start',id=base['id'].removesuffix('length0')+tag)
          validate(c)
          if key(c) not in seen:rows.append(c);seen.add(key(c))
    assert len(rows)==len({c['id'] for c in rows})
    return rows
