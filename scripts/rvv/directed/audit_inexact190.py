#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline retained receipt audit; no guest execution and no golden repinning."""
import collections,gzip,json,os,struct,sys
from pathlib import Path
import audit
import inexact190 as q
import fpreduce174 as f
import vadd as v
import storage149 as storage

def audit_inputs(out):
    rows=json.loads((out/'MANIFEST.json').read_text())
    if rows!=q.cases():raise ValueError('manifest differs from declared generator')
    root=out/'corpus';manifest=json.loads((root/'manifest.json').read_text())
    if manifest['cases']!=rows:raise ValueError('corpus manifest mismatch')
    with gzip.open(out/'EXPECTED.json.gz','rt') as s:expected=json.load(s)
    for c,e in zip(rows,expected):
        r,steps=q.sequential(c,f.initial(c))
        legal=[dict(result=list(r),tree=w) for r,w in sorted(q.witnesses(c,f.initial(c)).items())]
        if e!=dict(case=c['id'],selected=list(r),steps=steps,legal_minimum_format_witnesses=legal):raise ValueError('pre-execution rational expectation changed')
    if len(expected)!=len(rows):raise ValueError('expectation extent')
    results=json.loads((out/'RESULTS.json').read_text())
    want={(c['id'],a) for c in rows for a in ['Reference','B','M1','M2','BOTH']}
    if len(results)!=len(want) or {(r['case'],r['arm']) for r in results}!=want:raise ValueError('missing/duplicate results')
    for b in json.loads((root/'build-commands.json').read_text()):
        if b['returncode'] or v.sha(Path(b['command'][-1]))!=b['elf_sha256']:raise ValueError('ELF build identity')
    units=collections.defaultdict(list)
    for c in rows:units[c['unit']].append(c)
    targets=[];streams={};data_checks=0
    for unit,cs in units.items():
        if storage.text(root/unit/'test.S')!=v.assembly(cs):raise ValueError('assembly setup changed')
        sections,symbols=audit.elf_sections_symbols(root/unit/'test.elf');base,code=sections['.text'];dbase,data=sections['.data']
        for c in cs:
            pc=symbols['target_'+str(c['ordinal'])];word=int.from_bytes(code[pc-base:pc-base+4],'little')
            if word!=f.instruction(c):raise ValueError('target encoding mismatch')
            off=symbols['initial_'+str(c['ordinal'])]-dbase;before=f.initial(c)
            if data[off:off+len(before)]!=before:raise ValueError('ELF initial data mismatch')
            off=symbols['fp_scalar_'+str(c['ordinal'])]-dbase
            if data[off:off+8]!=f.scalar(c).to_bytes(8,'little'):raise ValueError('ELF scalar FP mismatch')
            data_checks+=1;targets.append(dict(case=c['id'],pc=pc,raw=word))
        for arm in ['Reference','B','M1','M2','BOTH']:
            d=root/'runs'/unit/arm;rec=json.loads((d/'execution.json').read_text());raw=storage.verify(d/'stdout');err=storage.verify(d/'stderr')
            if storage.digest(raw)!=rec['stdout_sha256'] or storage.digest(err)!=rec['stderr_sha256']:raise ValueError('stream identity')
            if len(raw)!=len(cs)*v.packet_size(cs[0]):raise ValueError('stream extent')
            cmd=json.loads((d/'command.json').read_text());elf=root/unit/'test.elf'
            if arm=='Reference':wanted=[str(Path('/home/vick/rvv-directed-task145/deps/spike')),f'--isa=rv32gcv_zvl{cs[0]["vlen"]}b',str(Path('/home/vick/rvv-directed-task145/deps/pk')),str(elf)]
            else:
                fs=root/'work'/unit/arm/'fs';flags=json.loads((out/'FLAGS.json').read_text())[arm]
                opts=[f'--vlen={cs[0]["vlen"]}' if x.startswith('--vlen=') else x for x in flags]
                wanted=[str(q.BASE/'build/bin/elfrun'),*opts,'--dump-tbmap='+str(d/'tbmap'),'--fsroot='+str(fs),'--cache='+str(fs.parent/'cache'),'--','/t.elf']
            if cmd!=wanted:raise ValueError('command/arm identity')
            streams[unit,arm]=(raw,rec)
    observed=[];controls=0;counts=collections.Counter();sample_alternatives=[];refs={}
    for r in sorted(results,key=lambda r:(r['arm']!='Reference',r['case'],r['arm'])):
        c=next(c for c in rows if c['id']==r['case']);raw,rec=streams[c['unit'],r['arm']];size=v.packet_size(c);i=units[c['unit']].index(c)
        if r['offset']!=i*size or r['size']!=size or r['raw']!=str(root/'runs'/c['unit']/r['arm']/'stdout'):raise ValueError('result binding')
        packet=raw[i*size:(i+1)*size];legal=q.witnesses(c,f.initial(c))
        allowed=(lambda c,b:legal) if r['arm']=='Reference' else q.selected_allowed
        q.check(c,packet,rec['returncode'],rec['timeout'],allowed)
        pre,post,before,after=v.decode(c,packet);off=c['vd']*(c['vlen']//8);e=c['dst_eew']//8
        actual=(int.from_bytes(after[off:off+e],'little'),post[7])
        if r['status']!='PASS':raise ValueError('receipt status')
        recorded=q.sequential(c,before)[0] if not c['vl'] else actual
        if r['actual']!=list(recorded):raise ValueError('receipt result differs from packet')
        if r['arm']=='Reference':refs[c['id']]=actual
        row=dict(case=c['id'],arm=r['arm'],observed_destination=list(actual),status='PASS',witness=legal.get(actual) if c['vl'] else 'VL0: preserve whole prestate',reference_agreement=None if r['arm']=='Reference' else actual==refs[c['id']])
        observed.append(row);counts[r['arm']]+=1
        if r['arm']=='B':
            for label,pos in [('destination',off),('other-register',15*(c['vlen']//8))]:
                bad=bytearray(packet);bad[96+32*(c['vlen']//8)+pos]^=1
                try:q.check(c,bad)
                except ValueError:controls+=1
                else:raise ValueError('corruption accepted: '+label)
            # Coherently alter both flag views, so fcsr consistency alone cannot reject.
            bad=bytearray(packet);fl=post[7]^1;struct.pack_into('<I',bad,80,fl);struct.pack_into('<I',bad,88,(c['frm']<<5)|fl)
            try:q.check(c,bad)
            except ValueError:controls+=1
            else:raise ValueError('corruption accepted: flags')
        if r['arm']=='Reference' and len(legal)>1:
            sample_alternatives.append(dict(case=c['id'],observed=list(actual),other_certified=[list(x) for x in legal if x!=actual]))
    before=json.loads((out/'IDENTITIES_BEFORE.json').read_text());after=json.loads((out/'IDENTITIES_AFTER.json').read_text())
    if before!=after or list(before.values())!=[q.PIN,q.LIB,q.SPIKE,q.PK]:raise ValueError('executable pin')
    resources=[json.loads(x) for x in (out/'RESOURCES.jsonl').read_text().splitlines()]
    if any(x['nice']!=10 or min(x['disk_free_bytes'],x['available_bytes'])<10*1024**3 for x in resources):raise ValueError('resource gate')
    v.save(out/'AUDIT.json',dict(status='PASS',checked_packets=len(observed),counts=dict(counts),ELF_targets=len(targets),ELF_input_data=data_checks,retained_corruptions_rejected=controls,reference_disagreement=sum(x['reference_agreement'] is False for x in observed),cases_with_certified_alternatives=len(sample_alternatives),resource_samples=len(resources),min_available_GiB=min(x['available_bytes'] for x in resources)/1024**3,min_disk_free_GiB=min(x['disk_free_bytes'] for x in resources)/1024**3,resource_limit='own guest sequential1, build executor2, inherited nice10, no affinity set; sampled reserve gates, not continuous shared occupancy proof'))
    for name,data in [('AUDITED_RESULTS',observed),('TARGETS',targets),('ALTERNATIVES',sample_alternatives)]:
        with gzip.open(out/(name+'.json.gz'),'wt') as stream:json.dump(data,stream,indent=2)
    print((out/'AUDIT.json').read_text())
if __name__=='__main__':audit_inputs(Path(sys.argv[1]))
