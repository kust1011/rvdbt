#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite eight-form scaling shift/fractional multiply manifest."""
FORMS={'vssra':('vv','vx','vi'),'vssrl':('vv','vx','vi'),'vsmul':('vv','vx')}

def cases():
    import vadd as v
    import shift148
    rows=[]
    shifted=shift148.cases()
    templates={op:[c for c in shifted if c['mnemonic']==base] for op,base in [('vssra','vsra'),('vssrl','vsrl')]}
    templates['vsmul']=[c for c in v.integer_cases() if c['mnemonic']=='vadd' and c['form'] in ('vv','vx')]
    for op,template in templates.items():
      for old in template:
       for rm in range(4):
        c=dict(old,mnemonic=op,family='scaling155-next',seed=155,vxrm_initial=rm,vxsat_initial=0,execution='NOT_RUN')
        c['id']=old['id'].replace(old['mnemonic']+'-',op+'-',1)+f'-rm{rm}'
        c['unit']=old['unit'].replace(old['mnemonic']+'-',op+'-',1)
        rows.append(c)
      bases=[c for c in rows if c['mnemonic']==op and c['tag']=='length0']
      for base in bases:
        e=base['sew'];n=base['vlmax'];bottom=1<<(e-1)
        def add(tag,**kw):
            c=dict(base,tag=tag,vl=1,mask='none',vd=8);c.update(kw)
            c['id']=base['id'].removesuffix('length0-rm'+str(base['vxrm_initial']))+tag+f'-rm{base["vxrm_initial"]}'
            c['unit']=base['unit'].removesuffix('zero')+('start' if c['vstart'] else 'zero');rows.append(c)
        pairs=[(1,1),(3,1),(5,1),(-1,1),(-3,1),(-5,1),(7,2),(11,2),(0,0),((1<<e)-1,0),((1<<e)-1,e-1),((1<<e)-1,e),((1<<e)-1,e+1)] if op!='vsmul' else [(bottom,bottom),(bottom,bottom-1),(bottom-1,bottom-1),(1,bottom//2),(3,bottom//2),(-1,bottom//2),(-3,bottom//2),(bottom,0),(bottom,-1)]
        for a,z in pairs:
            if base['form']=='vi' and not 0<=z<=31:continue
            add(f'pair{a},{z}',pair_override=[a,z],operand=z)
        add('sticky-preserved',pair_override=[1,1],operand=1,vxsat_initial=1,vl=n)
        if op=='vsmul':
          for sat in [0,1]:add('saturating-sat'+str(sat),witness='saturating',sat_lane=0,operand=bottom,vxsat_initial=sat)
          add('masked-saturation',vl=n,mask='off',witness='saturating',sat_lane=0,operand=bottom,ta=True,ma=True)
          add('zero-saturation',vl=0,witness='saturating',sat_lane=0,operand=bottom,ta=True,ma=True)
          if n>1:
            add('prestart-saturation',vl=n,vstart=1,witness='saturating',sat_lane=0,operand=bottom,ta=True,ma=True)
            add('tail-saturation',vl=n-1,witness='saturating',sat_lane=n-1,operand=bottom,ta=True,ma=True)
            add('masked-partial-saturation',vl=n-1,mask='alternating',witness='saturating',sat_lane=1,operand=bottom,ta=True,ma=True)
    assert len(rows)==len({c['id'] for c in rows})
    return rows
