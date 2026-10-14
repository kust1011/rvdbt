"""Move only closed successful NEW streams to verified local compressed capacity."""
import argparse,gzip,hashlib,json,os,shlex,subprocess,tarfile,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--host',default='xbd');p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
B='/home/vick/rvv-task181'
SSH=['ssh','-o','ControlPath=none','-o','ControlMaster=no']
SCP=['scp','-o','ControlPath=none','-o','ControlMaster=no']
TOOL_SHA=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
def remote(code):
 for attempt in range(3):
  r=subprocess.run([*SSH,a.host,'nice -n 10 python3 -'],input=code.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  if r.returncode==0:return r.stdout
  print('STATE_TRANSPORT_ATTEMPT',attempt+1,r.returncode,r.stderr.decode(errors='replace')[-300:],flush=True);time.sleep(2)
 raise RuntimeError('state transport failed; no raw removal')
def archive_sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()
def commit_metadata(meta,r):
 packet=Path(str(meta)+'.gz')
 if not packet.exists():packet.write_bytes(gzip.compress(meta.read_bytes(),mtime=0))
 checksum=archive_sha(packet)
 for attempt in range(3):
  destination=B+'/transfer-metadata/'+r['entry']+'.receipt-'+r['archive_sha256'][:12]+'.upload-'+str(time.time_ns())+'.json.gz'
  upload=subprocess.run([*SCP,str(packet),a.host+':'+destination],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  if upload.returncode==0:break
  print('METADATA_UPLOAD_ATTEMPT',r['entry'],attempt+1,upload.returncode,destination,upload.stderr.decode(errors='replace')[-500:],flush=True);time.sleep(2)
 else:raise RuntimeError('metadata upload failed; original raw and verified archive retained')
 command='cd '+shlex.quote(B)+' && nice -n 10 env PYTHONDONTWRITEBYTECODE=1 python3 tools/commit_transfer.py '+shlex.join([destination,checksum])
 for attempt in range(3):
  result=subprocess.run([*SSH,a.host,command],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  if result.returncode==0:return
  print('METADATA_ATTEMPT',r['entry'],attempt+1,result.returncode,result.stderr.decode(errors='replace')[-500:],flush=True)
  time.sleep(2)
 raise RuntimeError('metadata commit failed; verified archive and original raw retained for idempotent recovery')
while True:
 state=json.loads(remote("from pathlib import Path\nimport json,shutil\nB=Path('/home/vick/rvv-task181');P=json.load(open(B/'DIRECTED_PLAN.json'));print(json.dumps(dict(free=shutil.disk_usage(B).free,complete=(B/'FINAL_COMPLETE').exists(),recovered_entries=[e['id'] for e in P['entries'] if (B/'directed'/e['id']/'recover/COMPLETE').exists()],entries=[e['id'] for e in P['entries'] if not e['reuse_same179'] and (B/'directed'/e['id']/'audit/COMPLETE').exists() and not (B/'directed'/e['id']/'TRANSFER.json').exists()])))\n"))
 if state['complete']:break
 if state['free']>=22*1024**3 or not state['entries']:time.sleep(10);continue
 entry=state['entries'][0];target=a.output/(entry+'.tar.gz');part=target.with_suffix('.gz.partial');meta=target.with_suffix('.transfer.json')
 if target.exists():
  assert meta.exists() and not part.exists()
  r=json.loads(meta.read_text());assert target.stat().st_size==r['archive_bytes'] and archive_sha(target)==r['archive_sha256']
  commit_metadata(meta,r);print('RECOVERED_TRANSFER',entry,r['archive_sha256'],flush=True);continue
 assert not part.exists()
 moved_stages=['pilot','recover'] if entry in state.get('recovered_entries',[]) else ['pilot','remaining']
 args=['tar','-C',B+'/directed/'+entry,'-czf','-',*[stage+'/runs' for stage in moved_stages]]
 code="import fcntl,subprocess,admission181 as a\nlock=open('/tmp/rvv-task181-offline.lock','a');fcntl.flock(lock,fcntl.LOCK_EX)\nwith a.predicate_slot():subprocess.run("+repr(args)+",check=True)\n"
 command='cd '+shlex.quote(B+'/tools')+' && nice -n 10 env PYTHONDONTWRITEBYTECODE=1 python3 -c '+shlex.quote(code)
 for attempt in range(3):
  with part.open('wb') as f:result=subprocess.run([*SSH,a.host,command],stdout=f,stderr=subprocess.PIPE)
  if result.returncode==0:break
  failed=Path(str(part)+'.capture-failed-'+str(time.time_ns()));part.rename(failed)
  print('CAPTURE_TRANSPORT_ATTEMPT',entry,attempt+1,result.returncode,str(failed),result.stderr.decode(errors='replace')[-500:],flush=True);time.sleep(2)
 else:raise RuntimeError('archive transport failed; incomplete captures and original raw retained')
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
 receipt=dict(moved_stages=moved_stages,failed_attempt_raw_moved=False,transfer_tool_sha256=TOOL_SHA,remote_command=command,entry=entry,archive=str(target.resolve()),archive_bytes=target.stat().st_size,archive_sha256=h.hexdigest(),members=members,file_sha256=hashes,storage_receipts_verified=len(metadata),original_inputs_moved=0,raw_failure_files_moved=0,reason='closed successful Task181 DUT streams moved to local capacity after archive/CRC/storage-hash verification; original inputs, goldens, failures and all summaries remain on xbd')
 meta=target.with_suffix('.transfer.json');meta.write_text(json.dumps(receipt,indent=2)+'\n')
 commit_metadata(meta,receipt)
 print('TRANSFER',entry,target.stat().st_size,h.hexdigest(),flush=True)
