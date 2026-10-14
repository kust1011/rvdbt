#!/usr/bin/env python3
"""Fixed192 replay using authenticated Task181/179 runners and frozen inputs.

Run locally with Python3; raw and full adapted runner snapshots stay outside git.
No compiler, reference simulator, source build, or golden generation is invoked.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import time

REMOTE = '/home/vick/rvv-task197'
OLD = '/home/vick/rvv-task181'
ENGINE = '/home/vick/rvv-long-task192/build/bin/elfrun'
PIN = '908df235e36fe49f8a64793a8e4a401987f9b2c56da10179470b7bc7bd5ffbc4'
OLDPIN = '8a468967852b8f16225b359fce99c0d22ab286d6314cb90a79934a7376207281'
LIBPIN = '79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af'
RESERVE = 10 * 1024**3


def sha(p):
    h = hashlib.sha256()
    with Path(p).open('rb') as f:
        for chunk in iter(lambda: f.read(1024**2), b''):
            h.update(chunk)
    return h.hexdigest()


def remote(code):
    for attempt in range(3):
        r = subprocess.run(['ssh', '-o', 'ControlPath=none','-o','ConnectTimeout=10',args.host, 'nice -n 10 python3 -'],
                           input=code, text=True, capture_output=True)
        if not r.returncode:return r.stdout
        if attempt<2:time.sleep(2)
    raise RuntimeError(r.stderr + r.stdout)


def save(p, data):
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    Path(p).write_text(json.dumps(data, indent=2) + '\n')


def prepare(refresh=False):
    # Persist budget before any new guest or runner staging.
    code = '''import json,shutil,subprocess
from pathlib import Path
B=Path('/home/vick/rvv-task181');P=json.load(open(B/'DIRECTED_PLAN.json'))
print(json.dumps(dict(free=shutil.disk_usage(B).free,entries=len(P['entries']),
 directed_commands=sum(len(e['units'])*4 for e in P['entries']),
 cases_per_arm=sum(e['accepted_cases'] for e in P['entries']),
 uptime=subprocess.check_output(['uptime'],text=True).strip())))
'''
    budget = json.loads(remote(code))
    budget.update(local_free=__import__('shutil').disk_usage(args.raw).free,
                  reserve_bytes=RESERVE, historical_directed_archive_bytes=1268670066,
                  conservative_new_retained_bytes=6*1024**3,
                  scratch_allowance_bytes=512*1024**2,
                  method='gzip stream capture; hardlink stdout/packets; verified per-entry tar.gz offload; successful scratch only removed',
                  originals_and_failures='read-only retained; no historical DUT credit')
    if not refresh:
        assert budget['free'] >= RESERVE + budget['conservative_new_retained_bytes'] + budget['scratch_allowance_bytes'], budget
        save(args.raw/'BUDGET.json', budget)
    sources = remote("""import json,hashlib
from pathlib import Path
B=Path('/home/vick/rvv-task181/tools')
print(json.dumps({p.name:dict(text=p.read_text(),sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in B.glob('*.py')}))
""")
    originals = json.loads(sources)
    accepted_pins=Path(__file__).resolve().parents[2]/'docs/rvv-validation/final-task197/original-runner-pins.json'
    if accepted_pins.exists():
        assert {n:r['sha256'] for n,r in originals.items()}==json.loads(accepted_pins.read_text()), 'accepted181 raw runner snapshot changed'
    tools = args.raw/'tools'; tools.mkdir(exist_ok=True)
    if refresh:
        import shutil
        shutil.copytree(tools,args.raw/('tools-before-refresh-'+str(time.time_ns())))
    for name, row in originals.items():
        save(args.raw/'original-runner-pins.json', {n:r['sha256'] for n,r in originals.items()})
        text = row['text'].replace(OLD, REMOTE).replace('rvdbt-host512-task179-build/build', 'rvv-long-task192/build').replace(OLDPIN, PIN)
        if name == 'admission181.py':
            text = text.replace("'rvv-task178','rvv-task181'", "'rvv-task178','rvv-task181','rvv-task197'")
            text = text.replace('for n in range(2):','for n in range(8):')
        if name == 'replay.py':
            text = text.replace("jobs=8 if a.action!='audit' else 2", 'jobs=8')
            text = text.replace("max_workers=2 if a.action=='audit' else 8", 'max_workers=8')
            text = text.replace("if len(selected)<2:selected=list(groups)[:2]", "if len(selected)<2:selected=list(groups)[:2]\nselected=selected[:1] if a.action=='pilot' else selected")
            text = text.replace('assert not root.exists();root.mkdir()', "assert not (root/'COMPLETE').exists();root.mkdir(exist_ok=True)")
            text = text.replace("if recover_existing:\n", "same_stage=a.action not in ('audit','reuse') and (root/'runs'/unit/arm/'execution.json').exists()\n  if same_stage:\n   d=root/'runs'/unit/arm;rec=read(d/'execution.json');cmd=read(d/'command.json');raw=storage.verify(d/'packets.bin')\n  elif recover_existing:\n")
            text = text.replace('and not recover_existing and all', 'and not recover_existing and not same_stage and all')
            text = text.replace("try:return worker_impl(unit)", """try:
  done=[root/(unit+'-'+arm+'-checks.json.gz') for arm in flags]
  if all(p.exists() for p in done):
   rows=[r for p in done for r in json.loads(gzip.decompress(p.read_bytes()))]
   assert all(r['status']=='PASS' for r in rows)
   assert len(rows)==4*sum(c['id'] in accepted for _,c in groups[unit])
   for r in rows:
    d=Path(r['raw']).parent
    assert sha(d/'command.json')==r['command_sha256'] and sha(d/'execution.json')==r['execution_sha256']
   return rows
  return worker_impl(unit)""")
        if name == 'focused.py':
            text = text.replace('assert not root.exists();root.mkdir(parents=True)', "assert not (root/'COMPLETE').exists();root.mkdir(parents=True,exist_ok=True)")
            text = text.replace("if audit:rec=read(new/'execution.json');raw=storage.verify(new/'packets.bin')", "retained=(new/'execution.json').exists()\n  if audit or retained:rec=read(new/'execution.json');raw=storage.verify(new/'packets.bin')")
            text = text.replace('if not audit and not error:', 'if not audit and not retained and not error:')
        if name == 'external.py':
            text = text.replace("assert not R.exists(), 'never overwrite or repeat an execution root'\nR.mkdir()", "assert not (R/'COMPLETE').exists()\nR.mkdir(exist_ok=True)")
            text = text.replace('d.mkdir()', 'd.mkdir(exist_ok=True)').replace("(d/'raw').mkdir()", "(d/'raw').mkdir(exist_ok=True)")
            text = text.replace("os.symlink('/home/vick/ara-current122/observers', d/'observers')", "\n        if not (d/'observers').exists():os.symlink('/home/vick/ara-current122/observers', d/'observers')")
            text = text.replace("    work=d/'work';", "    if (d/'result.json').exists():\n        r=act.read(d/'result.json');assert r['call']==c and r['build']==pins and r['status'] in ('PASS','SCOPED_PASS')\n        assert __import__('hashlib').sha256(storage.verify(d/'stdout')).hexdigest()==r['stdout_sha256']\n        assert __import__('hashlib').sha256(storage.verify(d/'stderr')).hexdigest()==r['stderr_sha256']\n        return suite,r['status']\n    work=d/'work';")
            text = text.replace('max_workers=2', 'max_workers=8')
            text = text.replace("    work=d/'work'; (work/'fs').mkdir(parents=True); (work/'cache').mkdir()", """    work=d/'work'
    if (d/'execution.json').exists():
        rec=act.read(d/'execution.json');cmd=act.read(d/'command.json')
        assert cmd[0]==str(STAGE/'bin/elfrun')
        out=storage.verify(d/'stdout');err=storage.verify(d/'stderr')
        assert __import__('hashlib').sha256(out).hexdigest()==rec['stdout_sha256']
        assert __import__('hashlib').sha256(err).hexdigest()==rec['stderr_sha256']
        with admission.predicate_slot():return classify_retained(suite,c,d,work,rec,out,err,rec['returncode'])
    (work/'fs').mkdir(parents=True); (work/'cache').mkdir()""")
        (tools/name).write_text(text)
    # Task181 plan retains every selector, source, checker, flag and reference pin.
    remote(f"""import json,hashlib,shutil
from pathlib import Path
B=Path({REMOTE!r});B.mkdir(exist_ok=True);(B/'tools').mkdir(exist_ok=True)
engine=Path({ENGINE!r});assert hashlib.sha256(engine.read_bytes()).hexdigest()=={PIN!r}
assert hashlib.sha256((engine.parent.parent/'lib/libdbtjitshared.so').read_bytes()).hexdigest()=={LIBPIN!r}
old=Path('/home/vick/rvv-task181/DIRECTED_PLAN.json')
assert hashlib.sha256(old.read_bytes()).hexdigest()=='6a57de0fb7c149ea865a62a27055db1a438610336fa6bb34b9c185e91e6ad929'
P=json.load(open(old));P['build']={PIN!r}
assert not any(e['reuse_same179'] for e in P['entries'])
for name in ('PREDICATE_DATA_PINS.json',):shutil.copy2('/home/vick/rvv-task181/'+name,B/name)
(B/'DIRECTED_PLAN.json').write_text(json.dumps(P,indent=2)+'\\n')
""")
    subprocess.run(['scp', *map(str, tools.glob('*.py')), str(Path(__file__).resolve()),
                    args.host+':'+REMOTE+'/tools/'], check=True)
    subprocess.run(['scp','-o','ControlPath=none',str(Path(__file__).parent/'supervise197.py'),args.host+':'+REMOTE+'/tools/'],check=True)
    subprocess.run(['scp', str(args.raw/'BUDGET.json'), str(args.raw/'original-runner-pins.json'), args.host+':'+REMOTE+'/'], check=True)
    print(json.dumps(budget), flush=True)


def stage_sequence():
    source=Path(__file__).parent/'directed/trace179.py'
    text=source.read_text().replace('/home/vick/rvdbt-host512-task179-build','/home/vick/rvv-long-task192')
    target=args.raw/'tools/trace197.py';target.write_text(text)
    repo=Path(__file__).resolve().parents[2]
    files=[target,Path(__file__).parent/'sequence197.py']
    subprocess.run(['scp',*map(str,files),args.host+':'+REMOTE+'/tools/'],check=True)
    for filename,dest in [('MANIFESTS.json.gz','accepted180-manifests.json.gz'),('EXECUTION_RECEIPTS.json.gz','accepted180-receipts.json.gz')]:
        src=repo/'docs/rvv-validation/directed-task180'/filename
        subprocess.run(['scp',str(src),args.host+':'+REMOTE+'/'+dest],check=True)
        remote(f"import hashlib\nassert hashlib.sha256(open({REMOTE+'/'+dest!r},'rb').read()).hexdigest()=={sha(src)!r}")
    save(args.raw/'sequence-source-pins.json',dict(trace179=sha(source),adapted_trace197=sha(target),sequence197=sha(files[1])))


def execute(command, label):
    log = args.raw/(label+'.log')
    if log.exists():log.rename(args.raw/(label+'.prior-'+str(time.time_ns())+'.log'))
    token=label+'-'+str(time.time_ns())
    launched=json.loads(remote(f"""import json,os,subprocess
from pathlib import Path
B=Path({REMOTE!r});(B/'controllers').mkdir(exist_ok=True)
for d in (B/'controllers').iterdir():
 if not d.is_dir() or not (d/'START.json').exists() or (d/'EXIT.json').exists():continue
 r=json.load(open(d/'START.json'));p=Path('/proc')/str(r['pid'])/'cmdline'
 if r['command']=={command!r} and p.exists() and d.name.encode() in p.read_bytes():
  print(json.dumps(dict(token=d.name,pid=r['pid'],reuse_active_supervisor=True)));raise SystemExit(0)
env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',RVV_TASK181_OWNER='181',RVV_TASK181_ROOT=str(B))
with (B/'controllers'/({token!r}+'.launcher.log')).open('wb') as f:
 p=subprocess.Popen(['nohup','python3',str(B/'tools/supervise197.py'),{token!r},*{command!r}],cwd=B,env=env,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
print(json.dumps(dict(token={token!r},pid=p.pid,reuse_active_supervisor=False)))
"""));token=launched['token']
    save(args.raw/(token+'.launch.json'),dict(label=label,remote_receipt=REMOTE+'/controllers/'+token,command=command))
    failures=0
    while True:
        try:
            state=json.loads(remote(f"""import json
from pathlib import Path
d=Path({REMOTE!r})/'controllers'/{token!r}
print(json.dumps(dict(exit=json.load(open(d/'EXIT.json')) if (d/'EXIT.json').exists() else None,log=(d/'output.log').read_text() if (d/'output.log').exists() else '')))
"""))
            failures=0;log.write_text(state['log'])
            if state['exit'] is not None:rc=state['exit']['returncode'];break
        except RuntimeError:
            failures+=1
            if failures>=12:raise RuntimeError('detached job retained; transport unavailable; inspect remote receipt before any retry')
        time.sleep(5)
    print(label, 'rc', rc, flush=True)
    return rc


def archive_entry(entry):
    """Existing181 transfer protocol: verify gzip CRC and storage hashes first."""
    target=args.raw/(entry+'.tar.gz'); meta=target.with_suffix('.receipt.json')
    if not target.exists():
        part=Path(str(target)+'.partial')
        cmd=['tar','-C',REMOTE+'/directed/'+entry,'-czf','-','pilot/runs','remaining/runs']
        if part.exists():part.rename(Path(str(part)+'.retained-'+str(time.time_ns())))
        for attempt in range(3):
            with part.open('wb') as f:
                r=subprocess.run(['ssh','-o','ControlPath=none',args.host,'nice -n 10 '+shlex.join(cmd)],stdout=f)
            if not r.returncode:break
            part.rename(Path(str(part)+'.failed-'+str(time.time_ns())))
            time.sleep(2)
        else:raise RuntimeError('archive transport; original streams and failed captures retained')
        hashes={}; links={}; metadata=[]
        with tarfile.open(part,'r:gz') as tf:
            for m in tf:
                assert not Path(m.name).is_absolute() and '..' not in Path(m.name).parts
                if m.islnk():links[m.name]=m.linkname
                elif m.isfile():
                    data=tf.extractfile(m).read();hashes[m.name]=hashlib.sha256(data).hexdigest()
                    if m.name.endswith('.storage.json'):metadata.append((m.name,json.loads(data)))
        for n,l in links.items():hashes[n]=hashes[l]
        for n,m in metadata:assert hashes[str(Path(n).parent/m['stored_file'])]==m['compressed_sha256']
        with gzip.open(part,'rb') as f:
            for _ in iter(lambda:f.read(1024**2),b''):pass
        part.rename(target)
        save(meta,dict(entry=entry,archive=str(target),bytes=target.stat().st_size,sha256=sha(target),storage_receipts=len(metadata),file_sha256=hashes))
    receipt=json.loads(meta.read_text());assert sha(target)==receipt['sha256']
    receipt.update(archive_sha256=receipt['sha256'],archive_bytes=receipt['bytes'],moved_stages=['pilot','remaining'])
    save(meta,receipt)
    packet=Path(str(meta)+'.gz');packet.write_bytes(gzip.compress(meta.read_bytes(),mtime=0));checksum=sha(packet)
    remote(f"from pathlib import Path\n(Path({REMOTE!r})/'transfer-metadata').mkdir(exist_ok=True)")
    for attempt in range(3):
        destination=REMOTE+'/transfer-metadata/'+entry+'-'+str(time.time_ns())+'.json.gz'
        r=subprocess.run(['scp','-o','ControlPath=none','-o','ConnectTimeout=10',str(packet),args.host+':'+destination])
        if not r.returncode:break
        time.sleep(2)
    else:raise RuntimeError('compressed metadata upload failed; originals and archive retained')
    # Existing181 receiver checks the upload hash, final build, closed audit,
    # stage completion and idempotent receipt before moving only new streams.
    remote(f"""import runpy,sys
sys.path.insert(0,{REMOTE+'/tools'!r});sys.argv=['commit_transfer.py',{destination!r},{checksum!r}]
runpy.run_path({REMOTE+'/tools/commit_transfer.py'!r},run_name='__main__')
""")


def run():
    plan=json.loads(remote(f"print(open({REMOTE+'/DIRECTED_PLAN.json'!r}).read())"))
    stopped=set()
    for e in plan['entries']:
        if e['batch'] in stopped:continue
        if json.loads(remote(f"from pathlib import Path\nimport json\nprint(json.dumps((Path({REMOTE!r})/'directed'/{e['id']!r}/'TRANSFER.json').exists()))")):continue
        for stage in ('pilot','remaining','audit'):
            state=json.loads(remote(f"from pathlib import Path\nimport json\nd=Path({REMOTE!r})/'directed'/{e['id']!r};print(json.dumps(dict(done=(d/{stage!r}/'COMPLETE').exists(),moved=(d/'TRANSFER.json').exists())))"))
            if state['done'] or state['moved']:continue
            if execute(['python3','tools/replay.py',stage,e['id']],e['id']+'-'+stage):
                stopped.add(e['batch']); signal()
                return 1  # Requires diagnosis before scheduling independent work.
        archive_entry(e['id'])
    return 0


def signal():
    for channel in ('rvv-review197198','rvv-final197'):
        subprocess.run(['tmux','wait-for','-S',channel],check=False)


def finish_supplements():
    while True:
        state=json.loads(remote(f"""from pathlib import Path
import json
B=Path({REMOTE!r})
print(json.dumps(dict(external=(B/'external/COMPLETE').exists(),external_audit=(B/'external/audit/COMPLETE').exists(),sequence=(B/'sequence/COMPLETE').exists(),sequence_audit=(B/'sequence/AUDIT_COMPLETE').exists(),stop=(B/'STOP_NEW_GUESTS.json').exists())))
"""))
        if state['external'] and not state['external_audit']:
            if execute(['python3','tools/audit_external.py'],'external-audit'):signal();return 1
        if state['sequence'] and not state['sequence_audit']:
            if execute(['python3','tools/sequence197.py','audit'],'sequence-audit'):signal();return 1
        if state['external_audit'] and state['sequence_audit']:return 0
        if state['stop']:signal();return 1
        time.sleep(20)


def compact_metadata():
    """Losslessly move closed per-unit receipts, avoiding small-file disk overhead."""
    while True:
        state=json.loads(remote(f"""from pathlib import Path
import json
B=Path({REMOTE!r});P=json.load(open(B/'DIRECTED_PLAN.json'))
print(json.dumps(dict(final=(B/'FINAL_COMPLETE').exists(),entries=[e['id'] for e in P['entries'] if (B/'directed'/e['id']/'TRANSFER.json').exists() and not (B/'directed'/e['id']/'METADATA_TRANSFER.json').exists()])))
"""))
        for entry in state['entries']:
            target=args.raw/(entry+'.metadata.tar.gz');meta=Path(str(target)+'.receipt.json')
            if not target.exists():
                part=Path(str(target)+'.partial')
                if part.exists():part.rename(Path(str(part)+'.retained-'+str(time.time_ns())))
                cmd=['tar','-C',REMOTE+'/directed/'+entry,'-czf','-','--exclude=TRANSFER.json','.']
                for attempt in range(3):
                    with part.open('wb') as f:r=subprocess.run(['ssh','-o','ControlPath=none',args.host,'nice -n 10 '+shlex.join(cmd)],stdout=f)
                    if not r.returncode:break
                    part.rename(Path(str(part)+'.failed-'+str(time.time_ns())))
                    time.sleep(2)
                else:raise RuntimeError('metadata transport failed; originals and partial archives retained')
                hashes={}
                with tarfile.open(part,'r:gz') as tf:
                    for m in tf:
                        assert not Path(m.name).is_absolute() and '..' not in Path(m.name).parts
                        if m.isfile():hashes[m.name]=hashlib.sha256(tf.extractfile(m).read()).hexdigest()
                        else:assert m.isdir(),m.name
                with gzip.open(part,'rb') as f:
                    for _ in iter(lambda:f.read(1024**2),b''):pass
                part.rename(target);save(meta,dict(entry=entry,archive=str(target),bytes=target.stat().st_size,sha256=sha(target),file_sha256=hashes))
            r=json.loads(meta.read_text());assert sha(target)==r['sha256']
            compact={k:r[k] for k in ('entry','archive','bytes','sha256')}
            compact.update(local_full_ledger=str(meta),ledger_sha256=sha(meta))
            remote(f"""import json
from pathlib import Path
d=Path({REMOTE!r})/'directed'/{entry!r}
assert (d/'audit/COMPLETE').exists() and (d/'TRANSFER.json').exists()
assert json.load(open(d/'audit/summary.json'))['failed']==0
(d/'METADATA_TRANSFER.json').write_text({json.dumps(compact)!r}+'\\n')
for stage in ('pilot','remaining','audit'):
 for pattern in ('*-checks.json.gz','*-REUSE.json'):
  for p in (d/stage).glob(pattern):p.unlink()
""")
            print('METADATA_COMPACTED',entry,r['bytes'],flush=True)
        if state['final']:return 0
        time.sleep(20)


def verify_retention():
    entries=json.loads(gzip.decompress((args.raw/'compact-final/ENTRY_RECEIPTS.json.gz').read_bytes()))
    assert len(entries)==102 and all(e['fully_audited'] and e['transfer'] and e['metadata_transfer'] for e in entries)
    rows=[]
    for e in entries:
        records={}
        for kind in ('transfer','metadata_transfer'):
            r=e[kind];path=Path(r['archive'])
            assert path.stat().st_size==r['bytes'] and sha(path)==r['sha256'],path
            if kind=='metadata_transfer':assert sha(r['local_full_ledger'])==r['ledger_sha256']
            records[kind]=dict(archive=str(path),bytes=r['bytes'],sha256=r['sha256'])
        rows.append(dict(entry=e['entry'],**records))
    result=dict(status='PASS',entries=len(rows),stream_archives=len(rows),metadata_archives=len(rows),
                stream_archive_bytes=sum(r['transfer']['bytes'] for r in rows),
                metadata_archive_bytes=sum(r['metadata_transfer']['bytes'] for r in rows),
                verification='Every retained successful archive size/SHA256 rechecked after replay; gzip CRC, member hashes and stream storage joins verified before each move',entries_detail=rows)
    save(args.raw/'RETENTION_VERIFIED197.json',result)
    print(json.dumps({k:v for k,v in result.items() if k!='entries_detail'}),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('prepare','refresh-tools','run','stage-sequence','finish-supplements','external-resume','compact-metadata','verify-retention'))
    p.add_argument('--host',default='xbd')
    p.add_argument('--raw',type=Path,default=Path('/home/user/research/materials/task197-fixed192-raw'))
    args=p.parse_args();args.raw.mkdir(exist_ok=True,parents=True)
    if args.action=='prepare':prepare()
    elif args.action=='refresh-tools':prepare(refresh=True)
    elif args.action=='external-resume':sys.exit(execute(['python3','tools/external.py',REMOTE+'/external'],'external-resume'))
    elif args.action=='compact-metadata':sys.exit(compact_metadata())
    elif args.action=='verify-retention':verify_retention()
    elif args.action=='stage-sequence':stage_sequence()
    elif args.action=='finish-supplements':sys.exit(finish_supplements())
    else:sys.exit(run())
