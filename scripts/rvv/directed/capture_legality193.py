# SPDX-License-Identifier: MIT
"""Read only retained manifests; no matrix generation or guest execution."""
import gzip
import hashlib
import json
from pathlib import Path
import sys


def capture(plan, out):
    records = []
    inputs = []
    # Both pilot and remainder: their accepted indices are disjoint.
    entries = [e for e in plan['entries'] if e['id'] in
               ('b162-023', 'b165-025', 'b165-026')]
    assert len(entries) == 3
    for entry in entries:
        p = Path(entry['original']) / 'manifest.json'
        raw = p.read_bytes() if p.exists() else gzip.decompress(Path(str(p)+'.gz').read_bytes())
        assert hashlib.sha256(raw).hexdigest() == entry['manifest_sha256']
        manifest = json.loads(raw)
        selected = set(entry['accepted_indices'])
        for index, c in enumerate(manifest['cases']):
            wanted = c['vlen'] == 128 and (
                c['family'] == 'memory165' and c['tag'] == 'v0-masked' or
                c['family'] == 'permute162' and c['mnemonic'] == 'vcompress'
                and c['tag'] == 'source-mask-alias')
            if wanted:
                records.append(dict(entry=entry['id'], case=c,
                                    accepted=index in selected, manifest_index=index))
                # A matched legal neighbour tests that exclusion is selective.
                tag = 'mask-even' if c['family'] == 'memory165' else 'mask-source-v0'
                neighbour_id = c['id'].removesuffix(c['tag']) + tag
                neighbours = [(j, n) for j, n in enumerate(manifest['cases'])
                              if n['id'] == neighbour_id]
                assert len(neighbours) == 1
                j, neighbour = neighbours[0]
                records.append(dict(entry=entry['id'], case=neighbour,
                                    accepted=j in selected, manifest_index=j))
        inputs.append(dict(entry=entry['id'], path=str(p),
                           manifest_sha256=entry['manifest_sha256']))
    ids = [r['case']['id'] for r in records]
    assert len(ids) == len(set(ids))
    assert len(ids) == 172, '86 reserved declarations and 86 matched legal neighbours'
    out.write_text(json.dumps(dict(records=records, inputs=inputs), indent=2)+'\n')


if __name__ == '__main__':
    capture(json.loads(gzip.decompress(Path(sys.argv[1]).read_bytes())), Path(sys.argv[2]))
