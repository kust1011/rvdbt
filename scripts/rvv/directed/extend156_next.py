#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Next distinct family: integer sign/zero extension, never fixed-point narrowing."""
FORMS={op:('vf2','vf4','vf8') for op in ('vzext','vsext')}

def factor(c):return int(c['form'][2:])
def source_bits(c):return c['sew']//factor(c)
def overlap(c):return bool(set(range(c['vd'],c['vd']+c['group_registers']))&set(range(c['vs2'],c['vs2']+c['source2_registers'])))
def validate(c):
    assert source_bits(c)>=8 and c['source2_emul_exp']>=-3
    d=set(range(c['vd'],c['vd']+c['group_registers']));s=set(range(c['vs2'],c['vs2']+c['source2_registers']))
    assert c['vd']%c['group_registers']==0 and c['vs2']%c['source2_registers']==0 and max(d|s)<32
    if d&s:assert c['source2_emul_exp']>=0 and max(d)==max(s)
    assert c['mask']=='none' or 0 not in d
    return True

def initial(c):
    import vadd as v
    raw=bytearray(v.initial(dict(c,family='baseline-extend156',seed=146)))
    b=c['vlen']//8;e=c['sew']//8;se=source_bits(c)//8;m=(1<<(8*se))-1
    for i in range(c['group_registers']*b//e):raw[c['vd']*b+i*e:c['vd']*b+(i+1)*e]=bytes([(0x63+i*7)%256])*e
    values=[m,m//2,0,1,1<<(8*se-1),(1<<(8*se-1))+1,17,0x11223344&m]
    for i in range(c['source2_registers']*b//se):raw[c['vs2']*b+i*se:c['vs2']*b+(i+1)*se]=values[i%len(values)].to_bytes(se,'little')
    return bytes(raw)

def lane(c,before,i):
    b=c['vlen']//8;se=source_bits(c)//8;a=int.from_bytes(before[c['vs2']*b+i*se:c['vs2']*b+(i+1)*se],'little')
    if c['mnemonic']=='vsext' and a>>(8*se-1):a-=1<<(8*se)
    return (a%(1<<c['sew'])).to_bytes(c['sew']//8,'little')
def target(c):return f'{c["mnemonic"]}.{c["form"]} v{c["vd"]},v{c["vs2"]}'+(',v0.t' if c['mask']!='none' else '')
def instruction(c):
    selector={8:2,4:4,2:6}[factor(c)]+int(c['mnemonic']=='vsext')
    return 18<<26|int(c['mask']=='none')<<25|c['vs2']<<20|selector<<15|2<<12|c['vd']<<7|0x57

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
      agnostic=c['vstart']<c['vl'] and i>=c['vstart'] and ((i>=c['vl'] and (c['ta'] or overlap(c))) or (i<c['vl'] and not active and (c['ma'] or overlap(c))))
      if active:
        if actual!=lane(c,before,i):raise ValueError('extended active lane')
      elif actual!=old and not (agnostic and actual==b'\xff'*e):raise ValueError('preserved lane')
    return True

def check_reference(c,raw,reference):
    import vadd as v
    before=v.decode(c,raw)[2];after=v.decode(c,raw)[3];expected=v.decode(c,reference)[3];b=c['vlen']//8;e=c['sew']//8
    for i in range(c['vstart'],c['vl']):
      if c['mask']=='none' or before[i//8]>>(i%8)&1:
        off=c['vd']*b+i*e
        if after[off:off+e]!=expected[off:off+e]:raise ValueError('independent reference extension')
    return True

def cases():
    import vadd as v
    rows=[]
    for op,forms in FORMS.items():
      for form in forms:
        shift=int(form[2:]).bit_length()-1
        for old in v.integer_cases():
          if old['mnemonic']!='vadd' or old['form']!='vv' or old['sew']//(1<<shift)<8 or old['lmul_exp']-shift<-3 or old['tag'] in ('dest-source1','dest-source2','same-sources'):continue
          c=dict(old,mnemonic=op,form=form,family='extend156',source2_emul_exp=old['lmul_exp']-shift,source2_registers=max(1,2**(old['lmul_exp']-shift)),source2_eew=old['sew']//(1<<shift),dest_eew=old['sew'],dest_emul_exp=old['lmul_exp'])
          if c['vd']==16:
            if c['source2_emul_exp']>=0:c['vs2']=16+c['group_registers']-c['source2_registers']
            else:c['vd']=8
          c['id']=old['id'].replace('vadd-',op+'-',1).replace('-vv-', '-'+form+'-',1);c['unit']=old['unit'].replace('vadd-',op+'-',1).replace('-vv-', '-'+form+'-',1)
          validate(c);rows.append(c)
        for base in [c for c in rows if c['mnemonic']==op and c['form']==form and c['tag']=='length0' and c['source2_emul_exp']>=0]:
          for tag,mask in [('dest-high-source','none'),('dest-high-source-mask','alternating')]:
            c=dict(base,tag=tag,vl=base['vlmax'],mask=mask,vs2=8+base['group_registers']-base['source2_registers']);c['id']=base['id'].removesuffix('length0')+tag;validate(c);rows.append(c)
    assert len(rows)==len({c['id'] for c in rows})
    return rows

def reserved_declarations():
    return [dict(form=op+'.'+f,kind=kind,execution='NOT_RUN',expected='reserved encoding') for op,forms in FORMS.items() for f in forms for kind in ['source-EEW-below8','source-EMUL-below-mf8','low-part-source-overlap','fractional-source-overlap','misaligned-group','masked-destination-v0']]
