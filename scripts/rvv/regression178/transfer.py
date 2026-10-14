"""Move only closed successful NEW streams to verified local compressed capacity."""
import argparse,gzip,hashlib,json,os,shlex,subprocess,tarfile,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--host',default='xbd');p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
B='/home/vick/rvv-task178'
def remote(code):return subprocess.check_output(['ssh',a.host,'python3 -'],input=code.encode())
while True:
 state=json.loads(remote("from pathlib import Path\nimport json,shutil\nB=Path('/home/vick/rvv-task178');P=json.load(open(B/'DIRECTED_PLAN.json'));print(json.dumps(dict(free=shutil.disk_usage(B).free,complete=(B/'FINAL_COMPLETE').exists(),entries=[e['id'] for e in P['entries'] if not e['reuse_same174'] and (B/'directed'/e['id']/'audit/COMPLETE').exists() and not (B/'directed'/e['id']/'TRANSFER.json').exists()])))\n"))
 if state['complete']:break
 if state['free']>=22*1024**3 or not state['entries']:time.sleep(10);continue
 entry=state['entries'][0];target=a.output/(entry+'.tar.gz');part=target.with_suffix('.gz.partial');assert not target.exists() and not part.exists()
 command='tar -C '+shlex.quote(B+'/directed/'+entry)+' -czf - pilot/runs remaining/runs'
 with part.open('wb') as f:subprocess.run(['ssh',a.host,command],stdout=f,check=True)
 # Verify transport/archive integrity and every compressed/logical storage join.
 hashes={};metadata=[];members=[];links={}
 with tarfile.open(part,'r:gz') as tf:
  for m in tf:
   n=Path(m.name);assert not n.is_absolute() and '..' not in n.parts
   members.append(dict(path=m.name,bytes=m.size,type=m.type.decode(errors='replace'),link=m.linkname))
   if m.islnk():links[m.name]=m.linkname
   elif m.isfile():
    stream=tf.extractfile(m);h=hashlib.sha256();data=[]
    for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk);data.append(chunk) if m.name.endswith('.storage.json') else None
    hashes[m.name]=h.hexdigest()
    if data:metadata.append((m.name,json.loads(b''.join(data))))
 for name,link in links.items():
  assert link in hashes,(name,link);hashes[name]=hashes[link]
 for name,m in metadata:
  stored=str(Path(name).parent/m['stored_file']);assert hashes[stored]==m['compressed_sha256'],name
 # Drain the entire outer gzip stream so its CRC and extent are checked.
 with gzip.open(part,'rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):pass
 # The final SHA identifies the sole retained archive.
 h=hashlib.sha256()
 with part.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 part.rename(target)
 receipt=dict(entry=entry,archive=str(target.resolve()),archive_bytes=target.stat().st_size,archive_sha256=h.hexdigest(),members=members,file_sha256=hashes,storage_receipts_verified=len(metadata),original_inputs_moved=0,raw_failure_files_moved=0,reason='closed successful Task178 DUT streams moved to local capacity after archive/CRC/storage-hash verification; original inputs, goldens, failures and all summaries remain on xbd')
 meta=target.with_suffix('.transfer.json');meta.write_text(json.dumps(receipt,indent=2)+'\n')
 code="from pathlib import Path\nimport json,shutil,sys\nB=Path('/home/vick/rvv-task178');r=json.loads(sys.stdin.read());d=B/'directed'/r['entry'];assert (d/'audit/COMPLETE').exists();assert json.load(open(d/'audit/summary.json'))['failed']==0;assert not (d/'TRANSFER.json').exists();(d/'TRANSFER.json').write_text(json.dumps(r,indent=2)+'\\n');\nfor stage in ('pilot','remaining'):shutil.rmtree(d/stage/'runs')\nwith (B/'TRANSFERS.jsonl').open('a') as f:f.write(json.dumps(r,separators=(',',':'))+'\\n')\n"
 # A separate code file avoids combining code and receipt in stdin.
 taskfile='/tmp/rvv-task178-transfer-record.py'
 subprocess.run(['ssh',a.host,'python3 -c '+shlex.quote('from pathlib import Path;Path('+repr(taskfile)+').write_text('+repr(code)+')')],check=True)
 subprocess.run(['ssh',a.host,'python3 '+taskfile],input=json.dumps(receipt).encode(),check=True)
 print('TRANSFER',entry,target.stat().st_size,h.hexdigest(),flush=True)
