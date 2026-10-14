#!/usr/bin/env python3
"""Fresh full180 trace0 and focused179 trace1 replay, with original177 auditors.

Uses the retained trace179 implementation, changing only build/output/admission
and successful scratch retention. No new guest sources or reference execution.
"""
import concurrent.futures
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

B=Path('/home/vick/rvv-task197')
sys.path.insert(0,str(B/'tools'))
import admission181 as admission
import storage149 as storage
sys.path.insert(0,'/home/vick/rvv-directed-task177/tools')
os.environ['RVV_TASK179_OUTPUT']=str(B/'sequence')
os.environ['RVV_COMPRESS']='1'
import trace197 as t
v=t.v;s=t.s
OLD=Path('/home/vick/rvv-directed-task177')
PIN='908df235e36fe49f8a64793a8e4a401987f9b2c56da10179470b7bc7bd5ffbc4'
LIBPIN='79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af'
READ=lambda p:json.loads(Path(p).read_text())
SHA=lambda p:hashlib.sha256(storage.verify(p)).hexdigest()


def setup():
    assert t.identities()=={str(t.C/'build/bin/elfrun'):PIN,str(t.C/'build/lib/libdbtjitshared.so'):LIBPIN}
    import cache_entries177
    cache_entries177.install();s.install('integer')
    # Same streamed capture as181, shared guest and predicate admission.
    v.execute=storage.execute;v.storage=storage


def prepare():
    jobs=[];roots=[]
    accepted=json.loads(gzip.decompress((B/'accepted180-manifests.json.gz').read_bytes()))
    receipts=json.loads(gzip.decompress((B/'accepted180-receipts.json.gz').read_bytes()))
    byunit={(r['root'],r['unit']):r for r in receipts if r['arm']=='Reference'}
    for part in ('integer','fp','cache','cache64'):
        for phase in ('pilot','remaining'):
            old=OLD/part/phase;root=t.B/'trace0'/part/phase
            m=READ(old/'manifest.json');assert m['cases']==accepted['trace0/'+part+'/'+phase]['cases']
            if not root.exists():
                root.mkdir(parents=True);v.save(root/'manifest.json',dict(m,reuse=str(old),candidate=str(t.C),trace=0))
                v.save(root/'build-commands.json',READ(old/'build-commands.json'))
                v.save(root/'identities-before.json',t.identities())
            roots.append(root)
            for unit in sorted({c['unit'] for c in m['cases']}):
                (root/unit).mkdir(exist_ok=True);(root/'runs'/unit).mkdir(parents=True,exist_ok=True)
                rr=byunit[('trace0/'+part+'/'+phase,unit)]
                assert SHA(old/unit/'test.elf')==rr['guest_sha256']
                assert SHA(old/'runs'/unit/'Reference/packets.bin')==rr['reference_sha256']
                for p in (old/unit).iterdir():
                    if p.name.startswith(('test.elf','test.S','sail.elf')) and not (root/unit/p.name).exists():(root/unit/p.name).symlink_to(p)
                if not (root/'runs'/unit/'Reference').exists():(root/'runs'/unit/'Reference').symlink_to(old/'runs'/unit/'Reference',target_is_directory=True)
                rows=[c for c in m['cases'] if c['unit']==unit]
                jobs.extend((part,0,root,old,unit,rows,arm) for arm in s.ARMS[1:])
    assert sum(len(j[5]) for j in jobs)==9672 and len(jobs)==2640
    for part in t.selections:
        root=t.B/'trace1'/part
        if not root.exists():root,js=t.prepare(part,1)
        else:
            m=READ(root/'manifest.json');old=OLD/part/'pilot'
            js=[(part,1,root,old,u,[c for c in m['cases'] if c['unit']==u],a) for u in sorted({c['unit'] for c in m['cases']}) for a in s.ARMS[1:]]
        roots.append(root);jobs.extend(js)
    return roots,jobs


def job(j):
    part,trace,root,old,unit,cs,arm=j;d=root/'runs'/unit/arm
    if (B/'STOP_NEW_GUESTS.json').exists():raise RuntimeError('retained stop requires diagnosis')
    try:
        if (d/'REUSE.json').exists():
            rec=READ(d/'execution.json');rr=READ(d/'REUSE.json')
            assert rr['new_execution'] and rr['original_ELF_sha256']==SHA(old/unit/'test.elf')
            assert rr['original_reference_sha256']==SHA(old/'runs'/unit/'Reference/packets.bin')
            assert rec['returncode']==0 and not rec['timeout']
            raw=storage.verify(d/'packets.bin');ref=storage.verify(old/'runs'/unit/'Reference/packets.bin');size=v.packet_size(cs[0])
            assert hashlib.sha256(raw).hexdigest()==rec['stdout_sha256'] and len(raw)==len(ref)==len(cs)*size
            with admission.predicate_slot():
                for i,c in enumerate(cs):s.check_reference(c,raw[i*size:(i+1)*size],ref[i*size:(i+1)*size])
            return len(cs)
        assert not d.exists(),('partial capture retained; diagnose without repeating a successful execution',str(d))
        with admission.predicate_slot():
            # The original function includes full ISA/reference predicates.
            count=t.execute_job(j)
        work=root/'work'/unit/arm
        if work.exists():shutil.rmtree(work)
        return count
    except BaseException as ex:
        v.save(B/'STOP_NEW_GUESTS.json',dict(family='sequence',part=part,trace=trace,unit=unit,arm=arm,error=repr(ex)))
        raise


def run():
    setup();roots,jobs=prepare()
    # One complete arm is a bounded pilot, then the remaining frozen calls.
    counts=[job(jobs[0])]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for n,count in enumerate(pool.map(job,jobs[1:]),1):
            counts.append(count)
            if n%100==0:print('SEQUENCE',n+1,len(jobs),sum(counts),flush=True)
    for root in roots:v.save(root/'identities-after.json',t.identities())
    assert sum(counts)==9888
    v.save(t.B/'REPLAY.json',dict(status='PASS',new_DUT_checks=sum(counts),new_DUT_commands=len(jobs),trace0_DUT_checks=9672,trace1_focused_DUT_checks=216,reference_executions=0,ELF_rebuilds=0,build=t.identities(),roots=list(map(str,roots))))
    (t.B/'COMPLETE').write_text('PASS\n')


def audit():
    setup();assert (t.B/'COMPLETE').exists()
    for trace in (0,1):
        for group,parts in (('main',('integer','fp','cache')),('cache64',('cache64',))):
            roots=[t.B/f'trace{trace}'/p/q for p in parts for q in ('pilot','remaining')] if trace==0 else [t.B/'trace1'/p for p in parts]
            for mode in ('audit','controls'):
                dest=t.B/f'{mode}-trace{trace}-{group}'
                if mode=='controls':dest=dest.with_suffix('.json')
                complete=Path(str(dest)+'.COMPLETE')
                if complete.exists():continue
                assert not dest.exists(),('retain incomplete audit',str(dest))
                cmd=['python3',str(OLD/'tools/review_sequences177_v2.py'),mode,'--roots',*map(str,roots),'--out',str(dest)]+(['--cache64'] if group=='cache64' else [])
                with admission.predicate_slot():r=subprocess.run(cmd,env=t.env(),capture_output=True)
                (t.B/f'{mode}-trace{trace}-{group}.stdout').write_bytes(r.stdout)
                (t.B/f'{mode}-trace{trace}-{group}.stderr').write_bytes(r.stderr)
                assert r.returncode==0,(cmd,r.stderr.decode())
                complete.write_text('PASS\n');print(mode,trace,group,'PASS',flush=True)
    (t.B/'AUDIT_COMPLETE').write_text('PASS\n')


if __name__=='__main__':globals()[sys.argv[1]]()
