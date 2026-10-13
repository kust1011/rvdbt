# SPDX-License-Identifier: MIT
"""Retained packet integration of exact Task155 predicates; no generator claim."""
import fixedpoint155, rounding153_next, saturation153

def install(v):
    families={'scaling155-next':fixedpoint155,'narrowing155-next':fixedpoint155,
              'rounding153-next':rounding153_next,'saturation153':saturation153,
              'saturation153-boundary':saturation153}
    for name in ('initial','check_isa','check_reference'):
        original=getattr(v,name)
        def wrapped(c,*args,_name=name,_original=original,**kwargs):
            module=families.get(c.get('family'))
            return getattr(module,_name)(c,*args,**kwargs) if module else _original(c,*args,**kwargs)
        setattr(v,name,wrapped)
    original=v.csr_expected
    def csr(c,post=False):
        values=original(c,post)
        if c.get('family') in families:
            rm=c.get('vxrm_initial',2);sat=c.get('vxsat_initial',1)
            if post and c.get('family')!='rounding153-next':sat=families[c['family']].saturation(c)
            values[4:7]=[rm,sat,rm*2+sat]
        return values
    v.csr_expected=csr
