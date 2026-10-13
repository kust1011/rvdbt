#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Integer widening add/subtract and multiply; separate next-family manifest."""
FORMS={op:('vv','vx','wv','wx') for op in ('vwaddu','vwadd','vwsubu','vwsub')}
FORMS.update({op:('vv','vx') for op in ('vwmulu','vwmul','vwmulsu')})
FUNCT6={'vwaddu':48,'vwadd':49,'vwsubu':50,'vwsub':51,'vwmulu':56,'vwmulsu':58,'vwmul':59}

def vector(c):return c['form'] in ('vv','wv')
def wide(c):return c['form'] in ('wv','wx')
def signed(x,e):return x-(1<<e) if x>>(e-1)&1 else x

def element(c,a,z):
    e=c['sew'];op=c['mnemonic'];a_bits=2*e if wide(c) else e
    a &= (1<<a_bits)-1;z &= (1<<e)-1
    if op in ('vwadd','vwsub','vwmul','vwmulsu'):a=signed(a,a_bits)
    if op in ('vwadd','vwsub','vwmul'):z=signed(z,e)
    r=a*z if op.startswith('vwmul') else a-z if op.startswith('vwsub') else a+z
    return (r%(1<<(2*e))).to_bytes(e//4,'little')

def initial(c):
    import vadd as v
    raw=bytearray(v.initial(dict(c,family='baseline-widen154',seed=146,mask='alternating' if c['mask']=='qemu-odd' else c['mask'])))
    b=c['vlen']//8;e=c['sew']//8;de=2*e
    for i in range(c['dest_registers']*b//de):
      raw[c['vd']*b+i*de:c['vd']*b+(i+1)*de]=bytes([0x11 if c['tag'].startswith('qemu-') else (0x63+i*7)%256])*de
    ae=de if wide(c) else e;am=(1<<(8*ae))-1;zm=(1<<c['sew'])-1
    aa=[am,am//2,0,1,1<<(8*ae-1),(1<<(8*ae-1))+1,17,0x11223344ffffffff&am]
    zz=[1,zm,zm,0,2,(1<<(c['sew']-1))+1,19,0x76543210&zm]
    for reg,size,count,values in [(c['vs2'],ae,c['source2_registers'],aa),(c['vs1'],e,c['group_registers'],zz)]:
      if reg==c['vs1'] and not vector(c):continue
      for i in range(count*b//size):raw[reg*b+i*size:reg*b+(i+1)*size]=values[i%len(values)].to_bytes(size,'little')
    if c['mask']=='qemu-odd':
      raw[:b]=bytes([0xaa])*b
    return bytes(raw)

def lane(c,before,i):
    b=c['vlen']//8;e=c['sew']//8;ae=2*e if wide(c) else e
    a=int.from_bytes(before[c['vs2']*b+i*ae:c['vs2']*b+(i+1)*ae],'little')
    z=int.from_bytes(before[c['vs1']*b+i*e:c['vs1']*b+(i+1)*e],'little') if vector(c) else c['operand']&0xffffffff
    # All narrow SEW <= XLEN, so truncate scalar before signed/unsigned extension.
    return element(c,a,z)

def target(c):
    z=f'v{c["vs1"]}' if vector(c) else 's0'
    return f'{c["mnemonic"]}.{c["form"]} v{c["vd"]},v{c["vs2"]},{z}'+(',v0.t' if c['mask']!='none' else '')

def instruction(c):
    z=c['vs1'] if vector(c) else 8
    return (FUNCT6[c['mnemonic']]+(4 if wide(c) else 0))<<26|int(c['mask']=='none')<<25|c['vs2']<<20|z<<15|(2 if vector(c) else 6)<<12|c['vd']<<7|0x57

def overlap_agnostic(c):
    d=set(range(c['vd'],c['vd']+c['dest_registers']))
    return (not wide(c) and bool(d&set(range(c['vs2'],c['vs2']+c['source2_registers'])))) or (vector(c) and bool(d&set(range(c['vs1'],c['vs1']+c['group_registers']))))

def validate(c):
    assert c['sew'] in (8,16,32) and c['lmul_exp']<=2
    d=set(range(c['vd'],c['vd']+c['dest_registers']))
    sources=[(c['vs2'],c['source2_registers'],2*c['sew'] if wide(c) else c['sew'],c['lmul_exp']+(1 if wide(c) else 0))]
    if vector(c):sources.append((c['vs1'],c['group_registers'],c['sew'],c['lmul_exp']))
    assert c['vd']%c['dest_registers']==0 and max(d)<32
    for reg,regs,eew,exp in sources:
      assert reg%regs==0 and reg+regs<=32
      s=set(range(reg,reg+regs))
      if d&s and eew!=2*c['sew']:assert exp>=0 and max(s)==max(d)
    if len(sources)==2 and sources[0][2]!=sources[1][2]:
      assert not set(range(sources[0][0],sources[0][0]+sources[0][1]))&set(range(sources[1][0],sources[1][0]+sources[1][1]))
    assert c['mask']=='none' or 0 not in d
    return True

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

def check_reference(c,raw,reference):
    import vadd as v
    before=v.decode(c,raw)[2];after=v.decode(c,raw)[3];expected=v.decode(c,reference)[3]
    b=c['vlen']//8;de=c['sew']//4
    for i in range(c['vstart'],c['vl']):
      if c['mask']=='none' or before[i//8]>>(i%8)&1:
        off=c['vd']*b+i*de
        if after[off:off+de]!=expected[off:off+de]:raise ValueError('independent reference widened lane')
    return True

def cases():
    import vadd as v
    template=[c for c in v.integer_cases() if c['mnemonic']=='vadd' and c['form'] in ('vv','vx') and c['sew']<=32 and c['lmul_exp']<=2]
    rows=[]
    for op,forms in FORMS.items():
      for form in forms:
        for old in template:
          if old['form']!=('vv' if form in ('vv','wv') else 'vx'):continue
          # Same-width destination aliases in the template are reserved for widening.
          if old['tag'] in ('dest-source2','dest-source1'):continue
          if form=='wv' and old['tag']=='same-sources':continue
          c=dict(old,mnemonic=op,form=form,family='widen154',seed=154)
          c['dest_registers']=max(1,2**(c['lmul_exp']+1));c['source2_registers']=c['dest_registers'] if wide(c) else c['group_registers']
          c['dest_eew']=2*c['sew'];c['source2_eew']=c['dest_eew'] if wide(c) else c['sew'];c['source1_eew']=c['sew']
          c['dest_emul_exp']=c['lmul_exp']+1;c['source2_emul_exp']=c['lmul_exp']+(1 if wide(c) else 0);c['source1_emul_exp']=c['lmul_exp']
          c['emul']='m'+str(2**c['dest_emul_exp']) if c['dest_emul_exp']>=0 else 'mf'+str(2**-c['dest_emul_exp'])
          if c['tag']=='end-group':c['vd']=32-c['dest_registers'];c['vs1']=8
          elif c['vd']==16:
            # Start cases retain overlap stress only where source EMUL permits it.
            if wide(c):pass # equal EEW source2 overlap is legal even fractional
            elif c['lmul_exp']>=0:c['vs2']=16+c['dest_registers']-c['group_registers']
            else:c['vd']=8
          c['id']=op+'-'+old['id'].removeprefix('vadd-').replace('-'+old['form']+'-','-'+form+'-',1)
          c['unit']=op+'-'+old['unit'].removeprefix('vadd-').replace('-'+old['form'],'-'+form,1)
          validate(c);rows.append(c)
        bases=[c for c in rows if c['mnemonic']==op and c['form']==form and c['tag']=='length0']
        for base in bases:
          def add(tag,**kw):
            c=dict(base,tag=tag,**kw);c['id']=base['id'].removesuffix('length0')+tag;validate(c);rows.append(c)
          for label,mask,vl in [('partial','none',max(0,base['vlmax']-1)),('even','alternating',base['vlmax']),('odd','qemu-odd',base['vlmax'])]:
            add('qemu-'+label,mask=mask,vl=vl,operand=0x55667788)
          if wide(base):add('dest-wide-source',vd=16,vl=base['vlmax'])
          if base['lmul_exp']>=0:
            high=8+base['dest_registers']-base['group_registers']
            if not wide(base):
              add('dest-high-source2',vs2=high,vl=base['vlmax'])
              add('dest-high-source2-mask',vs2=high,vl=max(1,base['vlmax']-1),mask='alternating')
            if vector(base):
              add('dest-high-source1',vs1=high,vl=base['vlmax'])
              if not wide(base):add('dest-high-both-sources',vs1=high,vs2=high,vl=base['vlmax'])
    assert len(rows)==len({c['id'] for c in rows})
    return rows

def reserved_declarations():
    return [dict(form=op+'.'+form,kind=kind,execution='NOT_RUN',expected='reserved encoding') for op,forms in FORMS.items() for form in forms for kind in ['destination-EMUL16','destination-EEW128','misaligned-wide-group','low-part-narrow-source-overlap','fractional-narrow-source-overlap','masked-destination-v0']]+[dict(form=op+'.wv',kind='different-EEW-source-source-overlap',execution='NOT_RUN',expected='reserved encoding') for op in ('vwaddu','vwadd','vwsubu','vwsub')]
