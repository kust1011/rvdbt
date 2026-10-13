#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded full-geometry controls using the frozen FP157 predicates and raw."""
import argparse
import collections
import hashlib
import importlib
import json
from pathlib import Path
import sys


def run(root, scripts, out):
    sys.path.insert(0, str(scripts.resolve()))
    f = importlib.import_module('fp157')
    v = importlib.import_module('vadd')
    out.mkdir(parents=True, exist_ok=False)
    rows = json.loads((root / 'manifest.json').read_text())['cases']
    geometries = sorted({(c['vlen'], c['sew'], c['lmul']) for c in rows})
    rank = {g: i for i, g in enumerate(geometries)}
    selected = []
    by_unit = collections.defaultdict(list)
    for c in rows:
        by_unit[c['unit']].append(c)
        geom = c['vlen'], c['sew'], c['lmul']
        desired_rm = rank[geom] % 5
        if (c['frm'] == 0 and c['tag'] in ('length1', 'policy11', 'start-equal-full')) or (c['frm'] == desired_rm and c['tag'] == 'edge-negative-inexact'):
            selected.append(c)
    expected = {(g, name, form, tag) for g in geometries
                for name, form in sorted({(c['mnemonic'], c['form']) for c in rows})
                for tag in ('length1', 'policy11', 'start-equal-full', 'edge-negative-inexact')}
    observed = {((c['vlen'], c['sew'], c['lmul']), c['mnemonic'], c['form'], c['tag']) for c in selected}
    assert observed == expected and len(selected) == len(expected)
    records, allowed, originals = [], [], []
    grouped = collections.defaultdict(list)
    for c in selected:
        grouped[c['unit']].append(c)
    for unit, cases in grouped.items():
        reference = v.storage.verify(root / 'runs' / unit / 'Reference' / 'packets.bin')
        raw = v.storage.verify(root / 'runs' / unit / 'B' / 'packets.bin')
        indices = {c['id']: i for i, c in enumerate(by_unit[unit])}
        for c in cases:
            size = v.packet_size(c)
            offset = indices[c['id']] * size
            packet = raw[offset:offset + size]
            ref = reference[offset:offset + size]
            f.check_isa(c, packet)
            f.check_reference(c, packet, ref)
            before = v.decode(c, packet)[2]
            b, e = c['vlen'] // 8, c['sew'] // 8
            semantic = 'reserved-start-profile' if c['vstart'] >= c['vlmax'] else 'ordinary'
            originals.append(dict(case=c['id'], unit=unit, offset=offset, bytes=size,
                                  packet_sha256=hashlib.sha256(packet).hexdigest(),
                                  geometry=[c['vlen'], c['sew'], c['lmul']], frm=c['frm'],
                                  semantic_class=semantic))
            def reject(label, pos, predicate='ISA'):
                bad = bytearray(packet)
                bad[pos] ^= 1
                assert bad != packet
                try:
                    if predicate == 'ISA':
                        f.check_isa(c, bad)
                    else:
                        f.check_reference(c, bad, ref)
                except ValueError as ex:
                    records.append(dict(case=c['id'], control=label, predicate=predicate,
                                        byte=pos, xor=1, rejected=True, error=str(ex),
                                        semantic_class=semantic))
                else:
                    raise ValueError('accepted effective mutation: ' + c['id'] + ' ' + label)
            for base in (8, 52):
                for j in range(11):
                    reject('CSR-scalar-' + str(base) + '-' + str(j), base + 4 * j)
            reject('scalar-FP-pre', size - 16)
            reject('scalar-FP-post', size - 8)
            reject('captured-source', 96 + c['vs2'] * b)
            reject('other-register', 96 + 32 * b + 31 * b)
            active = [i for i in range(c['vstart'], c['vl']) if f.active(c, before, i)]
            if active:
                pos = 96 + 32 * b + c['vd'] * b + active[0] * e
                reject('active-result', pos)
                reject('independent-active', pos, 'reference')
                reject('independent-fflags', 52 + 7 * 4, 'reference')
            inactive = [i for i in range(c['group_registers'] * b // e) if not f.active(c, before, i)]
            preserved = [i for i in inactive if i < c['vstart'] or c['vstart'] >= c['vl'] or
                         (i >= c['vl'] and not c['ta']) or (i < c['vl'] and not c['ma'])]
            if preserved:
                reject('inactive-preservation', 96 + 32 * b + c['vd'] * b + preserved[0] * e)
            if c['tag'] == 'policy11' and c['vstart'] < c['vl']:
                bad = bytearray(packet)
                for i in inactive:
                    if i >= c['vstart']:
                        pos = 96 + 32 * b + c['vd'] * b + i * e
                        old = before[c['vd'] * b + i * e:c['vd'] * b + (i + 1) * e]
                        ones = b'\xff' * e
                        bad[pos:pos + e] = old if packet[pos:pos + e] == ones else ones
                assert bad != packet, 'agnostic control must change bytes'
                f.check_isa(c, bad)
                f.check_reference(c, bad, ref)
                allowed.append(dict(case=c['id'], control='allowed-agnostic-old-or-ones', accepted=True))
    for name, value in [('records.json', records), ('allowed.json', allowed), ('selected.json', originals)]:
        v.save(out / name, value)
    summary = dict(actual_packets=len(selected), rejected=len(records), allowed=len(allowed),
                   rejected_by_class=dict(collections.Counter(r['semantic_class'] for r in records)),
                   geometries=len(geometries), rounding_modes=sorted({c['frm'] for c in selected}),
                   selection='length1/policy11/start-equal-full at frm0 plus edge-negative-inexact at frm=sorted-geometry-index modulo5, per form and geometry',
                   guest_reruns=0, predicates={name: hashlib.sha256((scripts / name).read_bytes()).hexdigest()
                                               for name in ('fp157.py', 'vadd.py')})
    v.save(out / 'summary.json', summary)
    print(json.dumps(summary))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('root', type=Path)
    p.add_argument('scripts', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    run(a.root, a.scripts, a.output)
