import gzip,hashlib,json,subprocess,sys,time
from pathlib import Path
R=Path('/home/vick/rvdbt-host512-task138'); launch=Path('/home/vick/task138-launch')
while not (R/'EXECUTION_COUNTS.json').is_file():
 if (R/'STOPPED.json').is_file():raise RuntimeError('STOPPED queue requires diagnosis')
 time.sleep(10)
assert not any(json.loads((R/'UNATTEMPTED.json').read_text()).values())
assert json.loads((R/'EXECUTION_COUNTS.json').read_text())=={'chips':{'PASS':11744},'act':{'PASS':7668},'ara':{'PASS':1888,'SCOPED_PASS':16}}
for name in ('launcher.stdout','launcher.stderr','load.before.txt'):(R/name).write_bytes((launch/name).read_bytes())
for name in ('replay_retained_task138.py','collect_retained_task138.py','config138.py'):(R/name).write_bytes((Path('/home/vick')/name).read_bytes())
(R/'finalize138.py').write_bytes(Path(__file__).read_bytes())
with (R/'configuration-after.stdout').open('w') as o,(R/'configuration-after.stderr').open('w') as e:
 rc=subprocess.call(['python3','/home/vick/config138.py','AFTER'],stdout=o,stderr=e)
assert rc==0
with (R/'audit.stdout').open('w') as o,(R/'audit.stderr').open('w') as e:
 rc=subprocess.call(['python3','/home/vick/collect_retained_task138.py',str(R)],stdout=o,stderr=e)
(R/'audit.rc').write_text(str(rc)+'\n');assert rc==0
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
# Independently authenticate all retained CHIPS original sources without compiling.
source=json.loads(Path('/home/vick/rvdbt-host512-task129/CHIPS_SOURCE_AUDIT.json').read_text())
assert all(sha(p)==h for p,h in source['hashes'].items())
(R/'CHIPS_SOURCE_AUDIT.json').write_text(json.dumps(dict(source,current_hash_check='PASS; fresh Task138 source read'),indent=2)+'\n')
# Recheck input/predicate/answer hashes after all execution and observer audit.
inputs=json.loads((R/'INPUT_AUDIT.json').read_text());tools=json.loads((R/'TOOLS.json').read_text())
assert all(sha(p)==h for p,h in (inputs|tools).items())
(R/'INPUT_AFTER_AUDIT.json').write_text(json.dumps(dict(status='PASS',input_files=len(inputs),tools=len(tools)),indent=2)+'\n')
(R/'load.final.txt').write_text(subprocess.check_output(['uptime'],text=True))
# Same retention policy as Task129: all direct receipts, streams and TB dumps;
# full work/cache and unmodified observer dependencies remain remote.
paths=[p for p in R.rglob('*') if p.is_file() and 'work' not in p.relative_to(R).parts and 'observers' not in p.relative_to(R).parts and p.name!='RAW_MANIFEST.json.gz']
manifest={str(p.relative_to(R)):dict(sha256=sha(p),bytes=p.stat().st_size) for p in paths}
(R/'RAW_MANIFEST.json.gz').write_bytes(gzip.compress(json.dumps(manifest,separators=(',',':')).encode(),mtime=0))
listfile=Path('/home/vick/task138-archive-files.txt');listfile.write_text('\n'.join(manifest)+'\nRAW_MANIFEST.json.gz\n')
archive=Path('/home/vick/task138-host512-receipts.tar.gz')
subprocess.run(['tar','-czf',str(archive),'-C',str(R),'-T',str(listfile)],check=True)
(launch/'ARCHIVE.json').write_text(json.dumps(dict(archive=str(archive),sha256=sha(archive),bytes=archive.stat().st_size,files=len(manifest),scope='All direct raw receipt files including TB dumps; full work/cache and unchanged original observers remain remote'),indent=2)+'\n')
print('FINALIZED',len(manifest),sha(archive),flush=True)
