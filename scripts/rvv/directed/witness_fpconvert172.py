#!/usr/bin/env python3
"""Run isolated original case on original/fixed immutable builds; no form credit."""
import json,os,sys
from pathlib import Path
import fpconvert172 as f
import vadd as v

def witness(base):
 out=base/'adjudication';c=json.loads((out/'ORIGINAL_CASE.json').read_text());proof=json.loads((out/'ORIGINAL_FAILURES.json').read_text())['proof'][0];receipt=proof['original_receipt'];oldraw=v.storage.verify(receipt['raw'])[receipt['offset']:receipt['offset']+receipt['size']];ref=v.storage.verify(base/'narrow-pilot/corpus/runs'/c['unit']/'Reference/packets.bin')[receipt['offset']:receipt['offset']+receipt['size']];flags=json.loads((base/'FLAGS.json').read_text());records=[]
 for name,pin in [('167','da4dec6bfc5e28c0574dd659d0c84762e6b1b9e3b07cd7571cce0f73b835bb96'),('172','80fc0a102921a43f0cb590c85c21671244304003c3e94620e900ebfcb42656ff')]:
  engine=Path('/home/vick/rvdbt-host512-task'+name+'-build/build/bin/elfrun');assert v.sha(engine)==pin
  for arm,options in flags.items():
   d=out/('build'+name+'-'+arm);fs=d/'fs';cache=d/'cache';fs.mkdir(parents=True);cache.mkdir();(fs/'t.elf').write_bytes((out/'original.elf').read_bytes());run=d/'run';env=dict(os.environ,LD_LIBRARY_PATH=str(engine.parent.parent/'lib')+':/home/vick/boost_vendor/lib');cmd=[engine,*[('--vlen=128' if x.startswith('--vlen=') else x) for x in options],f'--dump-tbmap={run}/tbmap',f'--fsroot={fs}',f'--cache={cache}','--','/t.elf'];r=v.execute(cmd,run,env);raw=v.storage.verify(run/'stdout');v.storage.write(run/'packets.bin',raw,alias=run/'stdout');assert not r['returncode'] and not r['timeout']
   if name=='167':
    assert raw==oldraw
    try:f.check_isa(c,raw)
    except ValueError:status='ORIGINAL_FAIL_REPRODUCED'
    else:raise AssertionError('old defect not reproduced')
   else:f.check_isa(c,raw);f.check_reference(c,raw,ref);status='FIXED_PASS'
   pre,post,before,after=v.decode(c,raw);records.append(dict(build=name,arm=arm,status=status,flags=post[7],packet_sha256=v.storage.digest(raw),engine_sha256=pin,isolated_target='single original target with original VL/vstart/rounding/state',original_case=c['id'],instruction=hex(f.instruction(c))))
 v.save(out/'WITNESS_BEFORE_AFTER.json',dict(records=records,diagnostic_commands=8,ordinary_case_credit=0,reference_reuse='one validated exact original Spike packet; reference not re-executed'))
 print(records,flush=True)
if __name__=='__main__':witness(Path(sys.argv[1]))
