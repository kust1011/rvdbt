# SPDX-License-Identifier: MIT
"""Reclassify bounded existing declarations; never rewrites historical receipts."""
import collections
import hashlib
import json
from pathlib import Path
import sys
import legality193 as l
import memory165
import permute162


def audit(capture):
    rows = []
    assert len(capture['records']) == 172, 'bounded selection must be complete'
    for r in capture['records']:
        c = r['case']
        # This is the actual old admission predicate, not a copied substitute.
        (memory165 if c['family'] == 'memory165' else permute162).validate(c)
        conflicts = l.source_conflicts(l.sources(c))
        ordinary = not conflicts
        assert r['accepted'] == ordinary, 'actual final181 selector disagrees with classification'
        rows.append(dict(entry=r['entry'], case=c['id'], form=c['mnemonic'],
                         old_validate='accepted',
                         public_review='no-added-source-EEW-constraint',
                         published_v1_0='ordinary' if ordinary else 'reserved-source-EEW',
                         final181_accepted=r['accepted'], conflicts=conflicts,
                         required_trap=False, new_ordinary_credit=False))
    return dict(rows=rows, counts=dict(collections.Counter(r['form'] for r in rows)),
                total=len(rows), reserved_excluded=sum(not r['final181_accepted'] for r in rows),
                legal_included=sum(r['final181_accepted'] for r in rows),
                new_guest_calls=0, new_ISA_pass_credit=0,
                historical_receipts_changed=0, inputs=capture['inputs'])


if __name__ == '__main__':
    raw = Path(sys.argv[1]).read_bytes()
    receipt = json.loads(Path(sys.argv[1]).with_name('CAPTURE_FIXED.json').read_text())
    assert hashlib.sha256(raw).hexdigest() == receipt['declarations_sha256']
    Path(sys.argv[2]).write_text(json.dumps(audit(json.loads(raw)),
                                          indent=2)+'\n')
