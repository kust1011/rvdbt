#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Ordinary-width destructive RVV FMA, with one exact rational rounding.

Independent pinned Spike/Sail packets remain the reference answers. FP157
supplies capture, boxing, IEEE rounding and preservation predicates.
"""
from functools import lru_cache
import json
from pathlib import Path
QEMU_INPUTS=json.loads(Path(__file__).with_name("qemu_fma164.json").read_text())
import fp157 as fp

FORMS = {op: ('vv', 'vf') for op in
         ('vfmacc','vfnmacc','vfmsac','vfnmsac','vfmadd','vfnmadd','vfmsub','vfnmsub')}
FUNCT6 = dict(vfmadd=40,vfnmadd=41,vfmsub=42,vfnmsub=43,
              vfmacc=44,vfnmacc=45,vfmsac=46,vfnmsac=47)
# (destination is addend, negate product, negate addend), from RVV1.0.
ROLES = dict(vfmacc=(True,False,False),vfnmacc=(True,True,True),
             vfmsac=(True,False,True),vfnmsac=(True,True,False),
             vfmadd=(False,False,False),vfnmadd=(False,True,True),
             vfmsub=(False,False,True),vfnmsub=(False,True,False))

@lru_cache(maxsize=65536)
def fused(bits,a,b,c,frm):
    sa,ka,va,sna=fp.unpack(bits,a);sb,kb,vb,snb=fp.unpack(bits,b)
    sc,kc,vc,snc=fp.unpack(bits,c);k=fp.constants(bits);sp=sa^sb
    invalid_product = ((ka=='inf' and kb=='finite' and not vb) or
                       (kb=='inf' and ka=='finite' and not va))
    # 0*inf is invalid even with a quiet-NaN addend (RISC-V F rules).
    if 'nan' in (ka,kb,kc) or invalid_product:
        return k['canonical'],16 if sna or snb or snc or invalid_product else 0
    if ka=='inf' or kb=='inf':
        if kc=='inf' and sp!=sc:return k['canonical'],16
        return (sp << (bits-1)) | k['inf'],0
    if kc=='inf':return (sc << (bits-1)) | k['inf'],0
    value=va*vb+vc
    zero_sign=sp if not va*vb and not vc and sp==sc else int(frm==2)
    return fp.rounded(bits,value,frm,zero_sign)

def operands(c,before,i):
    b,e=c['vlen']//8,c['sew']//8
    def word(reg):return int.from_bytes(before[reg*b+i*e:reg*b+(i+1)*e],'little')
    d,s2=word(c['vd']),word(c['vs2'])
    s1=word(c['vs1']) if c['form']=='vv' else fp.scalar_operand(c)
    acc,negp,negc=ROLES[c['mnemonic']];sign=1 << (c['sew']-1)
    a,z=(s2,d) if acc else (d,s2)
    return a^(sign if negp else 0),s1,z^(sign if negc else 0)

def lane(c,before,i):return fused(c['sew'],*operands(c,before,i),c['frm'])

def nonfused(c,before,i):
    a,b,z=operands(c,before,i)
    product,pflags=fp.arithmetic(c['sew'],'vfmul',a,b,c['frm'])
    result,aflags=fp.arithmetic(c['sew'],'vfadd',product,z,c['frm'])
    return result,pflags|aflags

def target(c):
    rhs=f'v{c["vs1"]}' if c['form']=='vv' else 'fs0'
    return f'{c["mnemonic"]}.{c["form"]} v{c["vd"]},{rhs},v{c["vs2"]}'+(',v0.t' if c['mask']!='none' else '')

def instruction(c):
    return (FUNCT6[c['mnemonic']]<<26 | int(c['mask']=='none')<<25 |
            c['vs2']<<20 | (c['vs1'] if c['form']=='vv' else 8)<<15 |
            (1 if c['form']=='vv' else 5)<<12 | c['vd']<<7 | 0x57)

def triples(bits):
    k=fp.constants(bits);s=1 << (bits-1)
    return [(name,k[a],k[b],k[z]) for name,a,b,z in [
        ('exact','one','two','three'),('cancel','one','one','negone'),
        ('zero-same','negzero','one','negzero'),('zero-opposite','zero','one','negzero'),
        ('inf-product','inf','two','one'),('inf-addend','one','two','inf'),
        ('inf-cancel','inf','two','neginf'),('zero-inf','zero','inf','one'),
        ('zero-inf-qnan','zero','inf','qnan'),('inf-zero-qnan','inf','zero','qnan'),
        ('qnan-a','qnan','one','one'),('qnan-b','one','qnan','one'),
        ('qnan-c','one','one','qnan'),('snan-a','snan','one','one'),
        ('snan-b','one','snan','one'),('snan-c','one','one','snan'),
        ('subnormal-exact','minsub','one','minsub'),
        ('underflow','minsub','half','zero'),('normal-boundary','minnormal','nextone','minsub'),
        ('overflow','maxfinite','two','one'),('overflow-rescue','maxfinite','two','maxfinite'),
        ('halfway-even','one','one','halfulp'),('halfway-odd','one','nextone','halfulp'),
        ('inexact','nextone','nextone','one')]] + [
        ('fused-cancel',k['nextone'],k['one']-2,k['negone']),
        ('fused-round',k['nextone'],k['nextone'],k['negone']),
        ('fused-overflow-rescue',k['maxfinite'],k['two'],k['maxfinite']|s),
        ('fused-underflow-rescue',k['minsub'],k['half'],k['minsub']),
        ('negative-halfway',k['negone'],k['one'],k['halfulp']|s),
        ('negative-overflow',k['maxfinite']|s,k['two'],k['negone']),
        ('negative-underflow',k['minsub']|s,k['half'],k['negzero'])]

def physical(op,bits,a,b,z):
    acc,negp,negc=ROLES[op];s=1 << (bits-1)
    a^=s if negp else 0;z^=s if negc else 0
    return dict(fp_a=a if acc else z,fp_b=b,fp_d=z if acc else a)

def initial(c):
    import vadd as v
    raw=bytearray(v.initial(dict(c,family='fma164-baseline')))
    b,e=c['vlen']//8,c['sew']//8;ts=triples(c['sew']);k=fp.constants(c['sew'])
    # Defined physical initialization order makes same-width aliases real.
    # The ISA predicate always reads the captured old physical registers.
    for reg,key in ((c['vd'],'fp_d'),(c['vs2'],'fp_a'),(c['vs1'],'fp_b')):
        for i in range(c['group_registers']*b//e):
            _,a,z,d=ts[i%len(ts)];defaults=physical(c['mnemonic'],c['sew'],a,z,d)
            word=c.get(key,defaults[key])
            if c.get('exception_lane') is not None and i!=c['exception_lane']:
                word=k['one'] if key!='fp_d' else k['zero']
            if c.get('qemu_vectors'):
                values=c['qemu_vectors'][key];word=values[i%len(values)]
            raw[reg*b+i*e:reg*b+(i+1)*e]=word.to_bytes(e,'little')
    raw[:b]=(sum(1<<i for i in range(c['vlmax']) if i%2).to_bytes(b,'little')
             if c['mask']=='odd' else v.mask_bytes(c))
    return bytes(raw)

# Shared checks call the family-dispatched initial/lane functions in FP157.
check_isa=fp.check_isa
check_reference=fp.check_reference
active=fp.active

def cases():
    import vadd as v
    baseline=[c for c in v.integer_cases() if c['mnemonic']=='vadd' and
              c['form'] in ('vv','vx') and c['sew'] in (32,64) and
              not c['tag'].startswith('operand') and c['vstart']<c['vlmax']]
    result=[]
    for op,forms in FORMS.items():
        for form in forms:
            sources=[c for c in baseline if c['form']==('vv' if form=='vv' else 'vx')]
            for old in sources:
                prefix=f'{op}-{form}-rm0-'
                c=dict(old,family='fma164',mnemonic=op,form=form,frm=0,fflags_initial=0,
                       id=prefix+old['id'].removeprefix('vadd-'),unit=prefix+old['unit'].removeprefix('vadd-'))
                result.append(c)
            for base in [c for c in sources if c['tag']=='length0']:
                bits=base['sew'];k=fp.constants(bits)
                for frm in range(5):
                    prefix=f'{op}-{form}-rm{frm}-w{base["vlen"]}-e{bits}-{base["lmul"]}-semantic-'
                    def add(tag,**changes):
                        c=dict(base,family='fma164',mnemonic=op,form=form,frm=frm,
                               fflags_initial=0,tag=tag,vl=1)
                        c.update(changes);c['id']=prefix+tag;c['unit']=prefix+('start' if c['vstart'] else 'zero')
                        result.append(c)
                    for name,a,b,z in triples(bits):add('fp-'+name,**physical(op,bits,a,b,z))
                    # Unadapted distinct physical inputs distinguish every sign and old-vd role.
                    add('fp-destructive-role',fp_a=k['two'],fp_b=k['three'],fp_d=k['half'])
                    add('fp-flags-accrue',**physical(op,bits,k['snan'],k['one'],k['zero']),fflags_initial=9)
                    for name in ('snan-a','snan-c','zero-inf','overflow','underflow','inexact'):
                        _,a,b,z=next(t for t in triples(bits) if t[0]==name)
                        add('suppress-'+name,mask='off',**physical(op,bits,a,b,z))
                    add('fp-tail-exception',exception_lane=1,**physical(op,bits,k['snan'],k['one'],k['zero']))
                    if base['vlmax']>1:
                        add('fp-masked-exception',vl=2,mask='alternating',exception_lane=1,**physical(op,bits,k['snan'],k['one'],k['zero']))
                        add('fp-prestart-exception',vl=base['vlmax'],vstart=1,exception_lane=0,**physical(op,bits,k['snan'],k['one'],k['zero']))
                        add('fp-start-fused',vl=base['vlmax'],vstart=1,**physical(op,bits,k['nextone'],k['one']-2,k['negone']))
                    add('fp-no-body-flags',vl=1,vstart=1,fflags_initial=9,**physical(op,bits,k['snan'],k['snan'],k['snan']))
                    add('fp-zero-vl-flags',vl=0,fflags_initial=9,**physical(op,bits,k['snan'],k['snan'],k['snan']))
                    if form=='vf' and bits==32:
                        for name in ('snan','one','inf'):
                            add('fp-malformed-box-'+name,fp_a=k['one'],fp_b=k[name],fp_d=k['one'],bad_box=True)
                    for name,mask in [('partial','none'),('even','alternating'),('odd','odd')]:
                        vectors=QEMU_INPUTS[op+'_'+form][str(bits)]
                        add('qemu-'+name,vl=base['vlmax']-1 if mask=='none' else base['vlmax'],mask=mask,qemu_vectors=vectors,fp_b=vectors['fp_b'][0])
                    if frm==0:
                        add('all-alias',vd=16,vs1=16,vs2=16,vl=base['vlmax'])
    assert len(result)==len({c['id'] for c in result})
    assert all(c['vstart']<c['vlmax'] for c in result)
    return result

def reserved_declarations():
    return [dict(form=op+'.'+f,obligation=kind,execution='NOT_RUN',expected='reserved encoding')
            for op,fs in FORMS.items() for f in fs for kind in
            ('unsupported-EEW8-or16','frm5','frm6','frm7','masked-destination-v0','misaligned-group')]
