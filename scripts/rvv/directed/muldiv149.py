#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Single-width OPMVV/OPMVX multiply/divide: independent ISA predicates."""
FORMS={op:('vv','vx') for op in ['vmul','vmulh','vmulhu','vmulhsu','vdiv','vdivu','vrem','vremu']}
FUNCT6={'vdivu':32,'vdiv':33,'vremu':34,'vrem':35,'vmulhu':36,'vmul':37,'vmulhsu':38,'vmulh':39}

def signed(x,e):return x-(1<<e) if x&(1<<(e-1)) else x
def quotient(a,z):
    q=abs(a)//abs(z)
    return -q if (a<0)!=(z<0) else q # integer truncation toward zero

def arithmetic(c,a,z):
    e=c['sew'];m=(1<<e)-1;a&=m;z&=m;op=c['mnemonic']
    sa=signed(a,e);sz=signed(z,e)
    if op=='vmul':r=a*z
    elif op=='vmulh':r=(sa*sz)>>e
    elif op=='vmulhu':r=(a*z)>>e
    elif op=='vmulhsu':r=(sa*z)>>e # vs2 signed, vs1/scalar unsigned
    elif op in ['vdiv','vrem']:
        q=-1 if z==0 else quotient(sa,sz)
        r=q if op=='vdiv' else sa if z==0 else sa-q*sz
    elif op in ['vdivu','vremu']:
        r=(m if z==0 else a//z) if op=='vdivu' else (a if z==0 else a%z)
    else:raise ValueError('unknown multiply/divide operation')
    return (r&m).to_bytes(e//8,'little')

def witnesses(e,form):
    sign=1<<(e-1);m=(1<<e)-1
    # Scalar is an RV32 XLEN operand, sign-extended for SEW64 even in unsigned ops.
    return [('zero-divisor',sign,0),('min-minus-one',sign,0xffffffff),
            ('negative-positive',m-6,3),('positive-negative',7,0xfffffffd),
            ('negative-negative',m-6,0xfffffffd),('high-both-negative',m,0xffffffff),
            ('high-mixed-vs2-negative',sign,3),('high-mixed-vs1-negative',3,0xffffffff),
            ('unsigned-extreme',m,2),('zero-numerator',0,3),
            ('scalar-sign-bit',sign+1,0x80000000),('scalar-max-positive',m,0x7fffffff)] if form=='vx' else [
            ('zero-divisor',sign,0),('min-minus-one',sign,m),
            ('negative-positive',m-6,3),('positive-negative',7,m-2),
            ('negative-negative',m-6,m-2),('high-both-negative',m,m),
            ('high-mixed-vs2-negative',sign,m),('high-mixed-vs1-negative',m,sign),
            ('unsigned-extreme',m,2),('zero-numerator',0,3),
            ('signed-extremes',sign,sign-1),('high-positive',sign-1,sign-1)]

def cases():
    import vadd as v
    template=[c for c in v.integer_cases() if c['mnemonic']=='vadd' and c['form']!='vi'];rows=[]
    for op in FORMS:
      oldrows=[]
      for old in template:
        c=dict(old,mnemonic=op,family='muldiv149',seed=149)
        c['id']=old['id'].replace('vadd-',op+'-',1);c['unit']=old['unit'].replace('vadd-',op+'-',1)
        rows.append(c);oldrows.append(c)
      for base in [c for c in oldrows if c['tag']=='length0']:
        for label,a,z in witnesses(base['sew'],base['form']):
          c=dict(base,tag='witness-'+label,vl=base['vlmax'],witness_a=a,witness_z=z,operand=z if base['form']=='vx' else base['operand'])
          c['id']=base['id'].removesuffix('length0')+c['tag'];rows.append(c)
        # Meaningful active witness interacting with overlap, mask, policy and vstart.
        if base['vlmax']>1:
          c=dict(base,tag='witness-start-overlap',vl=base['vlmax'],vstart=1,vd=16,mask='single-on',ta=True,ma=True,witness_a=(1<<base['sew'])-8,witness_z=3,operand=3)
          c['unit']=base['unit'].removesuffix('zero')+'start';c['id']=base['id'].removesuffix('length0')+c['tag'];rows.append(c)
    # Explicit 0/0 in EVERY divide geometry, including VLMAX2: a zero
    # numerator shortcut must not bypass the zero-divisor quotient rule.
    # Append, preserving all original ordinals; distinct shared-geometry units
    # allow additive execution without rerunning any existing case.
    bases=[c for c in rows if c['tag']=='length0' and c['mnemonic'] in ('vdiv','vdivu','vrem','vremu')]
    for base in bases:
        c=dict(base,tag='witness-zero-over-zero',vl=base['vlmax'],operand=0,witness_a=0,witness_z=0)
        c['id']=base['id'].removesuffix('length0')+c['tag']
        c['unit']=f'zerozero149-w{c["vlen"]}-e{c["sew"]}-{c["lmul"]}-zero'
        rows.append(c)
    assert len(rows)==len({c['id'] for c in rows})
    return rows

def initial(c):
    import vadd as v
    raw=bytearray(v.initial(dict(c,family='baseline149',seed=146)))
    b=c['vlen']//8;e=c['sew'];size=e//8;m=(1<<e)-1;s=1<<(e-1)
    pairs=[(m,m),(s,m),(m-6,3),(7,m-2),(m-6,m-2),(s,0),(s,m),(m,2),(s,s-1),(s-1,s-1),(0,3),(3,m)]
    for i in range(c['group_registers']*b//size):
      a,z=(c['witness_a'],c['witness_z']) if 'witness_a' in c else pairs[i%len(pairs)]
      for base,value in [(16,a),(24,z)]:raw[base*b+i*size:base*b+(i+1)*size]=(value&m).to_bytes(size,'little')
    return bytes(raw)
