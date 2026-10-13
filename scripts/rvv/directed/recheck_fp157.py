#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Derive corrected receipts from immutable FP raw, preserving original failures."""
import collections
import hashlib
import json
from pathlib import Path
import shutil
import sys
import vadd as v

def recheck(original,out):
    original=original.resolve();out.mkdir(parents=True,exist_ok=False)
    root=out/'corpus';root.mkdir()
    manifest=json.loads((original/'manifest.json').read_text())
    if manifest['family']!='fp157':raise ValueError('only explicit FP checker correction')
    units=collections.defaultdict(list)
    for c in manifest['cases']:units[c['unit']].append(c)
    regenerated=v.manifest_cases('fp157')
    for i,c in enumerate(regenerated):c['ordinal']=i
    regenerated=[c for c in regenerated if c['unit'] in manifest['pilot_units']]
    if regenerated!=manifest['cases']:raise ValueError('changed case declaration')
    before={name:hashlib.sha256((original/name).read_bytes()).hexdigest() for name in ['manifest.json','results.json','summary.json','build-commands.json']}
    for name in ['manifest.json','build-commands.json','identities-before.json','identities-after.json','runner-identity.json','user.ld','sail.ld']:
        shutil.copy2(original/name,root/name)
    (root/'runs').symlink_to(original/'runs',target_is_directory=True)
    for unit in units:(root/unit).symlink_to(original/unit,target_is_directory=True)
    results=[]
    for unit,cs in units.items():
        size=v.packet_size(cs[0]);refdir=original/'runs'/unit/'Reference'
        reference=v.storage.verify(refdir/'packets.bin');rr=json.loads((refdir/'execution.json').read_text())
        # Only valid independent packets can serve as references.
        if len(reference)!=size*len(cs):raise ValueError('reference extent')
        for i,c in enumerate(cs):v.check_isa(c,reference[i*size:(i+1)*size],rr['returncode'],rr['timeout'])
        for arm in ['Reference','B','M1','M2','BOTH']:
            d=original/'runs'/unit/arm;raw=v.storage.verify(d/'packets.bin');rec=json.loads((d/'execution.json').read_text())
            if len(raw)!=size*len(cs):raise ValueError('packet extent')
            for i,c in enumerate(cs):
                packet=raw[i*size:(i+1)*size]
                v.check_isa(c,packet,rec['returncode'],rec['timeout'])
                if arm!='Reference':v.check_reference(c,packet,reference[i*size:(i+1)*size])
                results.append(dict(case=c['id'],arm=arm,status='PASS',error=None,isa_status='PASS',reference_status='ORACLE_PACKET' if arm=='Reference' else 'PASS',raw=str(d/'packets.bin'),offset=i*size,size=size))
    v.save(root/'results.json',results)
    summary=json.loads((original/'summary.json').read_text());old_counts=summary['counts'];summary['counts']={'PASS':len(results)};summary['arms']={a:{'PASS':len(manifest['cases'])} for a in ['Reference','B','M1','M2','BOTH']}
    summary['receipt_origin']='corrected checker replay of unchanged raw; no new guest commands'
    v.save(root/'summary.json',summary)
    after={name:hashlib.sha256((original/name).read_bytes()).hexdigest() for name in before}
    if before!=after:raise ValueError('original receipts changed')
    v.save(out/'RECHECK_LINEAGE.json',dict(original=str(original),original_receipt_hashes=before,original_counts=old_counts,revised_counts=summary['counts'],reason='after-rounding tininess must use precision rounding with unbounded exponent, not final encoding',checker_sha256=v.sha(Path(__file__).with_name('fp157.py')),unchanged_manifest=True,new_guest_commands=0,original_raw_and_scripts_mutations=0))
    print(summary['counts'])

if __name__=='__main__':recheck(Path(sys.argv[1]),Path(sys.argv[2]))
