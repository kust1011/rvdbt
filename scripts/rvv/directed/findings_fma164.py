#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retain exact original FMA failures and reference comparison evidence."""
import collections,gzip,hashlib,json,sys
from pathlib import Path
import fma164 as f
import fp157 as fp
import vadd as v

def run(root,out):
    out.mkdir(parents=True,exist_ok=False)
    cases=json.loads((root/'manifest.json').read_text())['cases'];ids={c['id']:c for c in cases};byunit=collections.defaultdict(list)
    for c in cases:byunit[c['unit']].append(c)
    results=json.loads((root/'results.json').read_text());failed=[r for r in results if r['status']!='PASS'];groups=collections.defaultdict(list)
    for r in failed:groups[ids[r['case']]['unit']].append(r)
    witnesses=[];reference_mismatches=[];selected={}
    for unit,rs in groups.items():
        indices={c['id']:i for i,c in enumerate(byunit[unit])};streams={arm:v.storage.verify(root/'runs'/unit/arm/'packets.bin') for arm in ('Reference','B','M1','M2','BOTH')}
        for r in rs:
            c=ids[r['case']];size=v.packet_size(c);offset=indices[c['id']]*size;raw=streams[r['arm']][offset:offset+size];ref=streams['Reference'][offset:offset+size]
            pre,post,before,after=v.decode(c,raw);rpre,rpost,rbefore,rafter=v.decode(c,ref)
            fp.check_isa(c,ref);assert pre==rpre and before==rbefore
            try:fp.check_reference(c,raw,ref)
            except ValueError as ex:reference_mismatches.append(dict(case=c['id'],arm=r['arm'],error=str(ex)))
            else:raise ValueError('original ISA failure has no independent mismatch')
            active=[i for i in range(c['vstart'],c['vl']) if fp.active(c,before,i)];b,e=c['vlen']//8,c['sew']//8
            differing=[];observed_lane_results=[]
            for i in active:
                pos=c['vd']*b+i*e;word=int.from_bytes(after[pos:pos+e],'little');rw=int.from_bytes(rafter[pos:pos+e],'little')
                if word!=rw:differing.append(i)
                if len(observed_lane_results)<8:
                    observed_lane_results.append(dict(lane=i,effective_operands=[hex(w) for w in f.operands(c,before,i)],isa_result_flags=list(f.lane(c,before,i)),dut_result=hex(word),reference_result=hex(rw)))
            witnesses.append(dict(case=c['id'],arm=r['arm'],tag=c['tag'],geometry=[c['vlen'],c['sew'],c['lmul']],frm=c['frm'],expected_flags=fp.expected_flags(c,before),dut_flags=post[7],reference_flags=rpost[7],dut_fcsr=post[9],reference_fcsr=rpost[9],active_lanes=active,result_mismatch_lanes=differing,lanes=observed_lane_results,raw=r['raw'],offset=offset,bytes=size,packet_sha256=hashlib.sha256(raw).hexdigest(),reference_sha256=hashlib.sha256(ref).hexdigest()))
            key=c['mnemonic'],c['form'],c['sew'],c['tag']
            if c['frm']==0 and r['arm']=='B' and key not in selected:
                selected[key]=c
                d=out/'witness-packets'/c['id'];d.mkdir(parents=True)
                (d/'CASE.json').write_text(json.dumps(c,indent=2)+'\n')
                for arm,stream in streams.items():(d/(arm+'.bin')).write_bytes(stream[offset:offset+size])
    for name,value in [('original-failures',failed),('witnesses',witnesses),('independent-mismatches',reference_mismatches)]:
        with gzip.open(out/(name+'.json.gz'),'wt') as stream:json.dump(value,stream,separators=(',',':'))
    per=collections.Counter((ids[r['case']]['mnemonic']+'.'+ids[r['case']]['form'],r['arm'],ids[r['case']]['tag']) for r in failed)
    v.save(out/'summary.json',dict(original_failures=len(failed),reference_mismatches=len(reference_mismatches),reference_failures=sum(r['arm']=='Reference' for r in failed),result_mismatches=sum(bool(r['result_mismatch_lanes']) for r in witnesses),missing_NV=sum(r['expected_flags']^r['dut_flags']==16 for r in witnesses),per_form=[dict(form=k[0],arm=k[1],tag=k[2],failures=n) for k,n in sorted(per.items())],raw_location='xbd:'+str(root),production_changes=0))
    print(json.dumps(json.loads((out/'summary.json').read_text())))
if __name__=='__main__':run(*map(Path,sys.argv[1:]))
