"""Idempotently commit a verified new archive receipt sent as compressed metadata."""
import fcntl,gzip,hashlib,json,shutil,sys
from pathlib import Path
import admission181 as admission
B=Path('/home/vick/rvv-task181');p=Path(sys.argv[1]);expected=sys.argv[2]
assert p.parent==B/'transfer-metadata'
lock=open('/tmp/rvv-task181-offline.lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
with admission.predicate_slot():
 data=p.read_bytes();assert hashlib.sha256(data).hexdigest()==expected
 r=json.loads(gzip.decompress(data));plan=json.load(open(B/'DIRECTED_PLAN.json'));assert r['entry'] in {e['id'] for e in plan['entries']}
 assert plan['build']=='8a468967852b8f16225b359fce99c0d22ab286d6314cb90a79934a7376207281'
 d=B/'directed'/r['entry'];assert (d/'audit/COMPLETE').exists();assert json.load(open(d/'audit/summary.json'))['failed']==0
 f=d/'TRANSFER.json'
 if f.exists():assert json.load(open(f))==r
 else:f.write_text(json.dumps(r,indent=2)+'\n')
 for stage in r.get('moved_stages',['pilot','remaining']):
  assert stage in ('pilot','remaining','recover') and (d/stage/'COMPLETE').exists(),stage
  root=d/stage/'runs'
  if root.exists():shutil.rmtree(root)
 ledger=B/'TRANSFERS.jsonl';seen=set()
 if ledger.exists():
  for line in ledger.open():seen.add(json.loads(line)['entry'])
 if r['entry'] not in seen:
  with ledger.open('a') as out:out.write(json.dumps(r,separators=(',',':'))+'\n')
 print(json.dumps(dict(entry=r['entry'],archive_sha256=r['archive_sha256'],committed=True)))
