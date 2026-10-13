#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite RVV1.0 vnclip[u].wv/wx/wi; ELEN64 bounds 2*SEW and EMUL."""
FORMS={'vnclip':('wv','wx','wi'),'vnclipu':('wv','wx','wi')}

def cases():
    import vadd as v
    import shift148
    rows=[]
    template=[c for c in shift148.cases() if c['mnemonic']=='vsrl' and c['sew']<=32 and c['lmul_exp']<=2 and c['tag'] not in ('same-sources','equal-operands')]
    for op in FORMS:
      for old in template:
       for rm in range(4):
        c=dict(old,mnemonic=op,family='narrowing155-next',seed=155,vxrm_initial=rm,vxsat_initial=0,execution='NOT_RUN',form={'vv':'wv','vx':'wx','vi':'wi'}[old['form']],source_eew=old['sew']*2,source_lmul_exp=old['lmul_exp']+1,source_group_registers=max(1,2**(old['lmul_exp']+1)))
        c['id']=old['id'].replace('vsrl-',op+'-',1).replace('-'+old['form']+'-','-'+c['form']+'-')+f'-rm{rm}'
        c['unit']=old['unit'].replace('vsrl-',op+'-',1).replace('-'+old['form']+'-','-'+c['form']+'-')
        rows.append(c)
      bases=[c for c in rows if c['mnemonic']==op and c['tag']=='length0']
      for base in bases:
        e=base['sew'];n=base['vlmax'];hi=(1<<e)-1 if op=='vnclipu' else (1<<(e-1))-1;lo=0 if op=='vnclipu' else -(1<<(e-1))
        def add(tag,**kw):
            c=dict(base,tag=tag,vl=1,mask='none',vd=8);c.update(kw)
            c['id']=base['id'].removesuffix('length0-rm'+str(base['vxrm_initial']))+tag+f'-rm{base["vxrm_initial"]}'
            c['unit']=base['unit'].removesuffix('zero')+('start' if c['vstart'] else 'zero');rows.append(c)
        pairs=[('upper-exact',hi,0),('upper-inside',hi-1,0),('upper-outside',hi+1,0),('lower-exact',lo,0),('lower-inside',lo+1,0),('round-upper',2*hi+1,1),('tie1',1,1),('tie3',3,1),('tie5',5,1),('zero-shift-wide',(1<<(2*e))-1,0),('max-shift',(1<<(2*e))-1,2*e-1),('shift-wrap',(1<<(2*e))-1,2*e),('shift-wrap1',(1<<(2*e))-1,2*e+1)]
        if op=='vnclip':pairs += [('lower-outside',lo-1,0),('tie-negative1',-1,1),('tie-negative3',-3,1),('tie-negative5',-5,1),('round-lower',2*lo-1,1)]
        for tag,a,z in pairs:
          if base['form']=='wi' and z>31:continue
          for sat in [0,1]:add(tag+'-sat'+str(sat),pair_override=[a,z],operand=z,vxsat_initial=sat)
        add('masked-saturation',vl=n,mask='off',witness='saturating',sat_lane=0,operand=0,ta=True,ma=True)
        add('zero-saturation',vl=0,witness='saturating',sat_lane=0,operand=0,ta=True,ma=True)
        if n>1:
          add('prestart-saturation',vl=n,vstart=1,witness='saturating',sat_lane=0,operand=0,ta=True,ma=True)
          add('tail-saturation',vl=n-1,witness='saturating',sat_lane=n-1,operand=0,ta=True,ma=True)
          add('masked-partial-saturation',vl=n-1,mask='alternating',witness='saturating',sat_lane=1,operand=0,ta=True,ma=True)
        # Additional legal low-part destination overlap with the wide source.
        add('narrow-low-overlap',vl=n,vd=16,operand=1,mask='alternating',ta=True,ma=True)
    assert len(rows)==len({c['id'] for c in rows})
    return rows
