import json,os,hashlib,fcntl
from pathlib import Path
import vadd as v
import sequences177 as s
b=Path('/home/vick/rvv-directed-task179');o=Path('/home/vick/rvv-directed-task177')
os.environ['RVV_COMPRESS']='1'
with open('/home/vick/rvv-directed-task179.own-semaphore','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 c=json.load(open(o/'diagnostic-absolute-trace1/command.json'));d=b/'original174-trace0'
 c=[a for a in c if not a.startswith(('--dump-','--rvv-pc-census-out='))]
 cache=b/'original174-trace0-cache';cache.mkdir()
 c=[a.replace('--trace=1','--trace=0') if a.startswith('--trace=') else '--cache='+str(cache) if a.startswith('--cache=') else a for a in c]
 r=v.execute(c,d,dict(os.environ,LD_LIBRARY_PATH='/home/vick/rvdbt-host512-task174-build/build/lib:/home/vick/boost_vendor/lib'),60)
 cs=[x for x in json.load(open(o/'integer/pilot/manifest.json'))['cases'] if x['unit']=='integer-w1024-e32-m1-liveout-zero']
 raw=v.storage.verify(d/'stdout');ref=v.storage.verify(o/'integer/pilot/runs/integer-w1024-e32-m1-liveout-zero/Reference/packets.bin');size=v.packet_size(cs[0])
 assert not r['returncode'] and len(raw)==len(ref)==size*len(cs)
 for j,x in enumerate(cs):s.check_reference(x,raw[j*size:(j+1)*size],ref[j*size:(j+1)*size])
 v.save(d/'RESULT.json',dict(status='PASS',checks=len(cs),guest_sha256=v.sha(o/'diagnostic-fs/t.elf'),packet_sha256=hashlib.sha256(raw).hexdigest(),same_guest_as_original_trace1=True,original_build=v.sha(c[0]),only_functional_flag_difference='--trace=0',reference_executions=0))
