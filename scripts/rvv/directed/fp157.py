#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite binary32/64 arithmetic; exact rational ISA checks, no host FP golden.

Pinned Spike/Sail execute the independent oracle. This module checks IEEE
rounding, canonical NaNs, active exception union and all preserved state.
"""
from fractions import Fraction
from functools import lru_cache
import struct

FORMS = {'vfadd': ('vv', 'vf'), 'vfsub': ('vv', 'vf'),
         'vfmul': ('vv', 'vf'), 'vfdiv': ('vv', 'vf'),
         'vfrsub': ('vf',), 'vfrdiv': ('vf',)}
FUNCT6 = {'vfadd': 0, 'vfsub': 2, 'vfmul': 36, 'vfdiv': 32,
          'vfrsub': 39, 'vfrdiv': 33}

def layout(bits):
    return (23, 8, 127) if bits == 32 else (52, 11, 1023)

def constants(bits):
    f, e, bias = layout(bits)
    inf = ((1 << e) - 1) << f
    return dict(zero=0, negzero=1 << (bits-1), one=bias << f,
                negone=(1 << (bits-1)) | (bias << f), two=(bias+1) << f,
                three=((bias+1) << f) | (1 << (f-1)),
                half=(bias-1) << f, minsub=1, maxsub=(1 << f)-1,
                minnormal=1 << f, maxfinite=inf-1, inf=inf,
                neginf=(1 << (bits-1)) | inf, qnan=inf | (1 << (f-1)) | 7,
                snan=inf | 1, canonical=inf | (1 << (f-1)),
                halfulp=(bias-f-1) << f, nextone=(bias << f)+1)

def unpack(bits, word):
    f, e, bias = layout(bits)
    sign = word >> (bits-1)
    exponent = (word >> f) & ((1 << e)-1)
    mantissa = word & ((1 << f)-1)
    if exponent == (1 << e)-1:
        return sign, 'nan' if mantissa else 'inf', None, bool(mantissa and not mantissa & (1 << (f-1)))
    significand = mantissa + ((1 << f) if exponent else 0)
    power = (exponent-bias if exponent else 1-bias)-f
    value = Fraction(significand) * (Fraction(2)**power)
    return sign, 'finite', -value if sign else value, False

def rounded(bits, value, frm, zero_sign=0):
    """Round an exact rational once, with tininess detected after rounding."""
    f, e, bias = layout(bits)
    sign = int(value < 0) if value else zero_sign
    value = abs(value)
    if not value:
        return sign << (bits-1), 0
    exp = value.numerator.bit_length()-value.denominator.bit_length()
    if value < Fraction(2)**exp:
        exp -= 1
    minimum, maximum = 1-bias, bias
    def round_significand(q):
        n, r = divmod(q.numerator, q.denominator)
        if frm in (0, 4):
            increment = 2*r > q.denominator or (2*r == q.denominator and (frm == 4 or n & 1))
        elif frm == 1:
            increment = False
        elif frm == 2:
            increment = bool(r and sign)
        elif frm == 3:
            increment = bool(r and not sign)
        else:
            raise ValueError('reserved frm')
        return n+int(increment), bool(r)
    # IEEE after-rounding tininess tests the precision-rounded result with an
    # unbounded exponent range, before the subnormal exponent-range rounding.
    # A final min-normal encoding can therefore still accrue UF (e.g. RUP
    # min-normal / nextafter(1,+inf)). Do not infer tininess from output bits.
    unbounded_quantum = Fraction(2)**(exp-f)
    unlimited, _ = round_significand(value/unbounded_quantum)
    tiny = unlimited*unbounded_quantum < Fraction(2)**minimum
    quantum = Fraction(2)**(max(exp, minimum)-f)
    q = value/quantum
    n, inexact = round_significand(q)
    if n >= 1 << (f+1):
        n >>= 1
        exp = max(exp, minimum)+1
    k = constants(bits)
    if exp > maximum:
        infinity = frm in (0, 4) or (frm == 2 and sign) or (frm == 3 and not sign)
        return (sign << (bits-1)) | (k['inf'] if infinity else k['maxfinite']), 5
    if n < 1 << f:
        word = n
    else:
        word = ((max(exp, minimum)+bias) << f) | (n-(1 << f))
    flags = int(inexact) | (2 if inexact and tiny else 0)
    return (sign << (bits-1)) | word, flags

@lru_cache(maxsize=65536)
def arithmetic(bits, op, a, b, frm):
    sa, ka, va, sna = unpack(bits, a)
    sb, kb, vb, snb = unpack(bits, b)
    k = constants(bits)
    if ka == 'nan' or kb == 'nan':
        return k['canonical'], 16 if sna or snb else 0
    if op in ('vfrsub', 'vfrdiv'):
        return arithmetic(bits, {'vfrsub':'vfsub','vfrdiv':'vfdiv'}[op], b, a, frm)
    if op == 'vfsub':
        sb ^= 1
        if vb is not None:
            vb = -vb
    if op in ('vfadd', 'vfsub'):
        if ka == kb == 'inf' and sa != sb:
            return k['canonical'], 16
        if ka == 'inf' or kb == 'inf':
            return ((sa if ka == 'inf' else sb) << (bits-1)) | k['inf'], 0
        value = va+vb
        zero_sign = sa if not va and not vb and sa == sb else int(frm == 2)
        return rounded(bits, value, frm, zero_sign)
    sign = sa ^ sb
    if op == 'vfmul':
        if (ka == 'inf' and kb == 'finite' and not vb) or (kb == 'inf' and ka == 'finite' and not va):
            return k['canonical'], 16
        if ka == 'inf' or kb == 'inf':
            return (sign << (bits-1)) | k['inf'], 0
        return rounded(bits, va*vb, frm, sign)
    if op == 'vfdiv':
        if (ka == kb == 'inf') or (ka == kb == 'finite' and not va and not vb):
            return k['canonical'], 16
        if ka == 'inf':
            return (sign << (bits-1)) | k['inf'], 0
        if kb == 'inf':
            return sign << (bits-1), 0
        if not vb:
            return (sign << (bits-1)) | k['inf'], 8
        return rounded(bits, va/vb, frm, sign)
    raise ValueError(op)

def pairs(bits):
    k = constants(bits)
    return [(name, k[a], k[b]) for name, a, b in [
        ('exact','one','two'), ('cancel','one','negone'),
        ('zero-same','negzero','negzero'), ('zero-opposite','zero','negzero'),
        ('infinity','inf','one'), ('inf-opposite','inf','neginf'),
        ('zero-inf','zero','inf'), ('inf-inf','inf','inf'),
        ('divide-zero','one','zero'), ('zero-zero','zero','zero'),
        ('qnan','qnan','one'), ('snan','one','snan'),
        ('subnormal-exact','minsub','one'), ('subnormal-round','minsub','half'),
        ('normal-boundary','minnormal','nextone'), ('overflow','maxfinite','two'),
        ('halfway-even','one','halfulp'), ('halfway-odd','nextone','halfulp'),
        ('inexact','one','three')]]

def scalar(c):
    if c.get('family') == 'fpreduce174':
        import fpreduce174
        return fpreduce174.scalar(c)
    if c.get('family') == 'fpconvert172':
        import fpconvert172
        return fpconvert172.scalar(c)
    value = c.get('fp_b', constants(c['sew'])['three'])
    if c['sew'] == 32:
        value |= (0 if c.get('bad_box') else 0xffffffff) << 32
    return value

def scalar_operand(c):
    if c['sew'] == 32 and scalar(c) >> 32 != 0xffffffff:
        return constants(32)['canonical']
    return scalar(c) & ((1 << c['sew'])-1)

def initial(c):
    if c.get('family') == 'fpreduce174':
        import fpreduce174
        return fpreduce174.initial(c)
    if c.get('family') == 'fpconvert172':
        import fpconvert172
        return fpconvert172.initial(c)
    if c.get('family') == 'fpcompare170':
        import fpcompare170
        return fpcompare170.initial(c)
    if c.get('family') == 'fma164':
        import fma164
        return fma164.initial(c)
    import vadd as v
    raw = bytearray(v.initial(dict(c, family='fp157-baseline')))
    b, e = c['vlen']//8, c['sew']//8
    ps = pairs(c['sew'])
    if c.get('qemu_pad'):
        raw[c['vd']*b:(c['vd']+c['group_registers'])*b] = b'\x11'*(c['group_registers']*b)
    # Same-width aliases naturally consume captured old physical inputs.
    for reg, side in ((c['vs2'],1), (c['vs1'],2)):
        for i in range(c['group_registers']*b//e):
            word = c.get('fp_a' if side == 1 else 'fp_b', ps[i % len(ps)][side])
            if c.get('exception_lane') is not None and i != c['exception_lane']:
                word = constants(c['sew'])['one']
            raw[reg*b+i*e:reg*b+(i+1)*e] = word.to_bytes(e, 'little')
    raw[:b] = (sum(1 << i for i in range(c['vlmax']) if i % 2).to_bytes(b,'little')
               if c['mask']=='odd' else v.mask_bytes(c))
    return bytes(raw)

def target(c):
    if c.get('family') == 'fpreduce174':
        import fpreduce174
        return fpreduce174.target(c)
    if c.get('family') == 'fpconvert172':
        import fpconvert172
        return fpconvert172.target(c)
    if c.get('family') == 'fpcompare170':
        import fpcompare170
        return fpcompare170.target(c)
    if c.get('family') == 'fma164':
        import fma164
        return fma164.target(c)
    rhs = f'v{c["vs1"]}' if c['form'] == 'vv' else 'fs0'
    return f'{c["mnemonic"]}.{c["form"]} v{c["vd"]},v{c["vs2"]},{rhs}' + (',v0.t' if c['mask'] != 'none' else '')

def instruction(c):
    if c.get('family') == 'fpreduce174':
        import fpreduce174
        return fpreduce174.instruction(c)
    if c.get('family') == 'fpconvert172':
        import fpconvert172
        return fpconvert172.instruction(c)
    if c.get('family') == 'fpcompare170':
        import fpcompare170
        return fpcompare170.instruction(c)
    if c.get('family') == 'fma164':
        import fma164
        return fma164.instruction(c)
    return FUNCT6[c['mnemonic']] << 26 | int(c['mask']=='none') << 25 | c['vs2'] << 20 | (c['vs1'] if c['form']=='vv' else 8) << 15 | (1 if c['form']=='vv' else 5) << 12 | c['vd'] << 7 | 0x57

def active(c, before, i):
    return c['vstart'] <= i < c['vl'] and (c['mask']=='none' or before[i//8] >> (i%8) & 1)

def lane(c, before, i):
    if c.get('family') == 'fpreduce174':
        import fpreduce174
        return fpreduce174.lane(c, before, i)
    if c.get('family') == 'fpconvert172':
        import fpconvert172
        return fpconvert172.lane(c, before, i)
    if c.get('family') == 'fpcompare170':
        import fpcompare170
        return fpcompare170.lane(c, before, i)
    if c.get('family') == 'fma164':
        import fma164
        return fma164.lane(c, before, i)
    b, e = c['vlen']//8, c['sew']//8
    def word(reg):
        return int.from_bytes(before[reg*b+i*e:reg*b+(i+1)*e], 'little')
    a = word(c['vs2'])
    z = word(c['vs1']) if c['form']=='vv' else scalar_operand(c)
    return arithmetic(c['sew'], c['mnemonic'], a, z, c['frm'])

def expected_flags(c, before):
    flags = c['fflags_initial']
    for i in range(c['vstart'], c['vl']):
        if active(c, before, i):
            flags |= lane(c, before, i)[1]
    return flags

def csr_expected(c, post=False, before=None):
    import vadd as v
    rows = v.csr_expected(dict(c, family='fp157-baseline'), post)
    flags = expected_flags(c, before if before is not None else initial(c)) if post else c['fflags_initial']
    rows[7:] = [flags, c['frm'], (c['frm'] << 5) | flags]
    return rows

def check_isa(c, raw, rc=0, timeout=False):
    if c.get('family') == 'fpreduce174':
        import fpreduce174
        return fpreduce174.check_isa(c, raw, rc, timeout)
    if c.get('family') == 'fpconvert172':
        import fpconvert172
        return fpconvert172.check_isa(c, raw, rc, timeout)
    if c.get('family') == 'fpcompare170':
        import fpcompare170
        return fpcompare170.check_isa(c, raw, rc, timeout)
    import vadd as v
    if rc or timeout:
        raise ValueError('execution/timeout')
    pre, post, before, after = v.decode(c, raw)
    x = c['operand'] & 0xffffffff
    if pre != csr_expected(c)+[x] or post != csr_expected(c, True, before)+[x]:
        raise ValueError('FP CSR/fflags/frm/scalar')
    if raw[-16:] != struct.pack('<2Q', scalar(c), scalar(c)):
        raise ValueError('FP scalar bits/boxing/preservation')
    if before != initial(c):
        raise ValueError('FP prestate')
    b, e = c['vlen']//8, c['sew']//8
    start, end = c['vd']*b, (c['vd']+c['group_registers'])*b
    if after[:start] != before[:start] or after[end:] != before[end:]:
        raise ValueError('other register')
    for i in range((end-start)//e):
        old = before[start+i*e:start+(i+1)*e]
        actual = after[start+i*e:start+(i+1)*e]
        if active(c, before, i):
            if actual != lane(c, before, i)[0].to_bytes(e, 'little'):
                raise ValueError('FP active result')
        else:
            agnostic = c['vstart'] < c['vl'] and i >= c['vstart'] and ((i >= c['vl'] and c['ta']) or (i < c['vl'] and c['ma']))
            if actual != old and not (agnostic and actual == b'\xff'*e):
                raise ValueError('FP inactive/prestart/tail/no-body')
    return True

def check_reference(c, raw, reference):
    if c.get('family') == 'fpreduce174':
        import fpreduce174
        return fpreduce174.check_reference(c, raw, reference)
    if c.get('family') == 'fpconvert172':
        import fpconvert172
        return fpconvert172.check_reference(c, raw, reference)
    if c.get('family') == 'fpcompare170':
        import fpcompare170
        return fpcompare170.check_reference(c, raw, reference)
    import vadd as v
    pre, post, before, after = v.decode(c, raw)
    _, refpost, _, refafter = v.decode(c, reference)
    if post[7:10] != refpost[7:10]:
        raise ValueError('independent reference FP flags/frm')
    b, e = c['vlen']//8, c['sew']//8
    for i in range(c['vstart'], c['vl']):
        if active(c, before, i):
            off = c['vd']*b+i*e
            if after[off:off+e] != refafter[off:off+e]:
                raise ValueError('independent reference FP active result')
    return True

def cases():
    import vadd as v
    baseline = [c for c in v.integer_cases() if c['mnemonic']=='vadd' and c['form'] in ('vv','vx') and c['sew'] in (32,64) and not c['tag'].startswith('operand')]
    result = []
    for op, forms in FORMS.items():
        for form in forms:
            sources = [c for c in baseline if c['form'] == ('vv' if form=='vv' else 'vx')]
            for old in sources:
                c = dict(old, family='fp157', mnemonic=op, form=form, frm=0, fflags_initial=0)
                prefix = f'{op}-{form}-rm0-'
                c['id'] = prefix+old['id'].removeprefix('vadd-')
                c['unit'] = prefix+old['unit'].removeprefix('vadd-')
                result.append(c)
            for base in [c for c in sources if c['tag']=='length0']:
                for frm in range(5):
                    def add(tag, **changes):
                        c = dict(base, family='fp157', mnemonic=op, form=form, frm=frm, fflags_initial=0)
                        c.update(changes)
                        c['tag'] = tag
                        prefix = f'{op}-{form}-rm{frm}-w{c["vlen"]}-e{c["sew"]}-{c["lmul"]}-'
                        c['id'] = prefix+tag
                        c['unit'] = prefix+('start' if c['vstart'] else 'zero')
                        result.append(c)
                    for name, a, z in pairs(base['sew']):
                        add('fp-'+name, vl=1, fp_a=a, fp_b=z)
                    k = constants(base['sew'])
                    add('fp-flags-accrue', vl=1, fp_a=k['snan'], fp_b=k['one'], fflags_initial=9)
                    # sNaN only in suppressed vector lane; scalar remains finite.
                    add('fp-masked-exception', vl=min(2,base['vlmax']), mask='alternating', fp_a=k['snan'], fp_b=k['one'], exception_lane=1)
                    add('fp-tail-exception', vl=1, fp_a=k['snan'], fp_b=k['one'], exception_lane=1)
                    if base['vlmax'] > 1:
                        add('fp-prestart-exception', vl=base['vlmax'], vstart=1, fp_a=k['snan'], fp_b=k['one'], exception_lane=0)
                    add('fp-no-body-flags', vl=0, vstart=1, fp_a=k['snan'], fp_b=k['snan'], fflags_initial=9)
                    add('fp-zero-vl-flags', vl=0, fp_a=k['snan'], fp_b=k['snan'], fflags_initial=9)
                    if form=='vf' and base['sew']==32:
                        add('fp-malformed-box', vl=1, fp_a=k['one'], fp_b=k['snan'], bad_box=True)
                    # QEMU-inspired partial/parity/pad scenarios, current 1.0 policy.
                    for name, mask in [('partial','none'),('even','alternating'),('odd','odd')]:
                        add('qemu-'+name, vl=max(0,base['vlmax']-1) if mask=='none' else base['vlmax'], mask=mask, qemu_pad=True)
    # Append disjoint units: old pilot ordinals/declarations remain unchanged.
    # Negative directed rounding needs its own witnesses; positive-only ties
    # cannot distinguish RTZ from RDN. Suppress each exception pattern with
    # all lanes masked off so another active lane cannot hide a leaked flag.
    for op, forms in FORMS.items():
        for form in forms:
            for base in [c for c in baseline if c['tag']=='length0' and c['form']==('vv' if form=='vv' else 'vx')]:
                bits=base['sew'];k=constants(bits);sign=1 << (bits-1)
                edge_pairs=[('negative-halfway',k['negone'],k['halfulp']),
                            ('negative-inexact',k['negone'],k['three']),
                            ('negative-overflow',k['maxfinite']|sign,k['two']),
                            ('negative-underflow-mul',k['minsub']|sign,k['half']),
                            ('negative-underflow-div',k['minsub']|sign,k['two'])]
                suppressed=[(name,a,z) for name,a,z in pairs(bits) if name in ('snan','overflow','divide-zero','zero-inf','subnormal-round','normal-boundary','inexact')]
                for frm in range(5):
                    for name,a,z in edge_pairs+suppressed:
                        masked=(name,a,z) in suppressed
                        tag=('suppress-' if masked else 'edge-')+name
                        prefix=f'{op}-{form}-edge-rm{frm}-w{base["vlen"]}-e{bits}-{base["lmul"]}-'
                        c=dict(base,family='fp157',mnemonic=op,form=form,frm=frm,fflags_initial=0,
                               tag=tag,vl=1,mask='off' if masked else 'none',fp_a=a,fp_b=z,
                               id=prefix+tag,unit=prefix+'zero')
                        result.append(c)
    assert len(result) == len({c['id'] for c in result})
    return result

def reserved_declarations():
    return [dict(form=op+'.'+f, obligation=kind, execution='NOT_RUN', expected='reserved encoding')
            for op, fs in FORMS.items() for f in fs
            for kind in ('unsupported-EEW8-or16','frm5','frm6','frm7','masked-destination-v0','misaligned-group')]
