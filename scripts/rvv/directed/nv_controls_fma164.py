#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check NV repair/omission on original failed pairs; no guest/PASS credit."""
import collections,gzip,hashlib,json,sys
from pathlib import Path
import fp157 as fp
import vadd as v

def run(root,out):
    out.mkdir(parents=True,exist_ok=False);cases=json.loads((root/'manifest.json').read_text())['cases'];ids={c['id']:c for c in cases};byunit=collections.defaultdict(list)
    for c in cases:byunit[c['unit']].append(c)
    failures=[r for r in json.loads((root/'results.json').read_text()) if r['status']=='FAIL'];grouped=collections.defaultdict(list)
    for r in failures:grouped[ids[r['case']]['unit']].append(r)
    records=[]
    for unit,rs in grouped.items():
        indices={c['id']:i for i,c in enumerate(byunit[unit])};streams={a:v.storage.verify(root/'runs'/unit/a/'packets.bin') for a in ('Reference','B','M1','M2','BOTH')}
        for r in rs:
            c=ids[r['case']];size=v.packet_size(c);off=indices[c['id']]*size;raw=streams[r['arm']][off:off+size];ref=streams['Reference'][off:off+size]
            expected=v.decode(c,ref)[1][7];actual=v.decode(c,raw)[1][7];assert expected^actual==16
            repaired=bytearray(raw);repaired[80]^=16;repaired[88]^=16
            assert repaired!=raw;fp.check_isa(c,repaired);fp.check_reference(c,repaired,ref)
            omitted=bytearray(ref);omitted[80]^=16;omitted[88]^=16
            assert omitted!=ref
            for predicate in ('ISA','reference'):
                try:fp.check_isa(c,omitted) if predicate=='ISA' else fp.check_reference(c,omitted,ref)
                except ValueError:pass
                else:raise ValueError('effective omitted NV accepted')
            records.append(dict(case=c['id'],arm=r['arm'],raw_sha256=hashlib.sha256(raw).hexdigest(),reference_sha256=hashlib.sha256(ref).hexdigest(),NV_only_repair_sha256=hashlib.sha256(repaired).hexdigest(),reference_NV_omitted_sha256=hashlib.sha256(omitted).hexdigest(),repair_validates_all_other_ISA_state=True,omission_rejected_by_both=True,ordinary_PASS_credit=0))
    with gzip.open(out/'records.json.gz','wt') as stream:json.dump(records,stream,separators=(',',':'))
    v.save(out/'summary.json',dict(original_failed_packets=len(records),NV_only_effective_repairs=len(records),effective_NV_omission_rejections=len(records)*2,guest_commands=0,ordinary_PASS_credit=0))
    print(json.dumps(json.loads((out/'summary.json').read_text())))
if __name__=='__main__':run(*map(Path,sys.argv[1:]))
