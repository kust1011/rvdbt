# SPDX-License-Identifier: MIT
"""Independent source-EEW classification delta; no execution or DUT goldens.

20240411 ISA manual, V 1.0, Vector Operands: a register supplying
two different source EEWs is reserved, including mask sources (EEW=1).
The old public-review pin omits this clause. Reserved is NOT a universal
requirement to trap and cannot receive mandatory ordinary-completion credit.
"""
from fractions import Fraction


def source_conflicts(operands):
    """Operands are (base register, register count, effective element bits).

    Fractional operands still occupy one architectural register for this
    constraint. Scalar vector sources have count=1; GPR/FPR sources are omitted.
    """
    seen = {}
    conflicts = []
    for base, count, eew in operands:
        if not 0 <= base < 32 or count < 1 or base + count > 32 or eew < 1:
            raise ValueError('invalid source description')
        for reg in range(base, base + count):
            old = seen.setdefault(reg, eew)
            if old != eew:
                conflicts.append(dict(reg=reg, first_eew=old, second_eew=eew))
    return conflicts


def sources(c):
    """Describe sources only; existing shape/destination predicates still apply."""
    family = c['family']
    operands = [] if c['mask'] == 'none' else [(0, 1, 1)]
    if family in ('memory165', 'indexed166'):
        if c['store']:
            operands += [(c['vd'] + f * c['group_registers'],
                          c['group_registers'], c['eew']) for f in range(c['nf'])]
        if family == 'indexed166':
            operands.append((c['vs2'], c['index_registers'], c['index_eew']))
    elif family == 'permute162' and c['mnemonic'] == 'vcompress':
        operands += [(c['vs2'], c['group_registers'], c['sew']),
                     (c['vs1'], 1, 1)]
    else:
        raise ValueError('outside bounded classification delta')
    return operands


def ordinary_credit(c, baseline='published-20240411'):
    if baseline == 'public-review-3570f998':
        return True  # No added source constraint; existing predicates still apply.
    if baseline != 'published-20240411':
        raise ValueError('unknown specification baseline')
    return not source_conflicts(sources(c))


def mandatory_vtypes():
    """ELEN64 minimum required SEW/LMUL pairs, independent of DUT helpers."""
    return {(sew, lm) for sew in (8, 16, 32, 64)
            for lm in (Fraction(1, 8), Fraction(1, 4), Fraction(1, 2),
                       Fraction(1), Fraction(2), Fraction(4), Fraction(8))
            if sew <= 64 and (lm >= 1 or sew <= lm * 64)}
