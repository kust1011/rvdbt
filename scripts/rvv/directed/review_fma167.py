#!/usr/bin/env python3
"""Construct an explicit new-DUT/reused-reference view for the frozen auditor."""
import collections, hashlib, json, os, shutil, subprocess, sys, time
from pathlib import Path
import vadd as v

def review(original, replay, output, parallel):
    assert (replay/'COMPLETE').read_text()=='PASS\n'
    output.mkdir(parents=True,exist_ok=False);root=output/'corpus';root.mkdir()
    for name in ('manifest.json','build-commands.json','user.ld','sail.ld'):
        shutil.copy2(original/name,root/name)
    manifest=json.loads((root/'manifest.json').read_text());units=dict.fromkeys(c['unit'] for c in manifest['cases'])
    for unit in units:
        (root/unit).symlink_to(original/unit,target_is_directory=True)
        d=root/'runs'/unit;d.mkdir(parents=True)
        (d/'Reference').symlink_to(original/'runs'/unit/'Reference',target_is_directory=True)
        for arm in ('B','M1','M2','BOTH'):(d/arm).symlink_to(replay/'runs'/unit/arm,target_is_directory=True)
    results=json.loads((replay/'results.json').read_text())
    refs=[r for r in json.loads((original/'results.json').read_text()) if r['arm']=='Reference']
    assert len(refs)==len(manifest['cases']) and all(r['status']=='PASS' for r in refs)
    v.save(root/'results.json',results+refs)
    for name in ('identities-before.json','identities-after.json'):
        shutil.copy2(replay/name,root/name)
    v.save(output/'VIEW_LINEAGE.json',dict(original=str(original),new_DUT=str(replay),reference_receipts_reused=len(refs),new_DUT_checks=len(results),new_reference_executions=0,original_manifest_sha256=v.sha(original/'manifest.json'),original_results_sha256=v.sha(original/'results.json'),new_results_sha256=v.sha(replay/'results.json'),checker_sha256=v.sha(Path(v.__file__)),auditor_sha256=v.sha(Path(__file__).with_name('audit.py'))))
    def run(name,args):
        with (output/(name+'.log')).open('w') as stream:rc=subprocess.run(args,stdout=stream,stderr=subprocess.STDOUT).returncode
        (output/(name+'.rc')).write_text(str(rc)+'\n');assert rc==0,(name,rc)
    run('audit',[sys.executable,str(parallel),str(root),str(output/'audit-parallel'),'--audit-script',str(Path(__file__).with_name('audit.py')),'--jobs','4'])
    run('controls',[sys.executable,str(Path(__file__).with_name('controls_fma164.py')),str(root),str(output/'controls')])
    compact=output/'evidence';compact.mkdir()
    audit=output/'audit-parallel'/'audit'
    for src,name in [(audit/'audit.json','AUDIT.json'),(audit/'observed-checks.csv.gz','observed-checks.csv.gz'),(output/'VIEW_LINEAGE.json','VIEW_LINEAGE.json'),(output/'controls'/'summary.json','CONTROLS.json'),(output/'audit-parallel'/'workers.json','AUDIT_WORKERS.json'),(output/'audit-parallel'/'parallel.json','PARALLEL.json'),(replay/'summary.json','DUT_SUMMARY.json')]:shutil.copy2(src,compact/name)
    ids={c['id']:c for c in manifest['cases']};forms=collections.Counter()
    for r in results+refs:forms[(ids[r['case']]['mnemonic']+'.'+ids[r['case']]['form'],r['arm'],r['status'])]+=1
    import csv
    with (compact/'PER_FORM.csv').open('w') as stream:
        w=csv.writer(stream);w.writerow(['form','arm','status','checks'])
        for key,n in sorted(forms.items()):w.writerow([*key,n])
    v.save(compact/'EVIDENCE_SHA256.json',{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in compact.iterdir() if p.is_file()})
    (output/'COMPLETE').write_text('PASS\n')

if __name__=='__main__':review(*map(Path,sys.argv[1:]))
