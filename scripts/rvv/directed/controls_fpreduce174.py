#!/usr/bin/env python3
"""One complete control pass on actual packets; no guest replays."""
import collections,json,struct,sys
from pathlib import Path
import fpreduce174 as f
import vadd as v

def controls(root,out):
 out.mkdir(parents=True,exist_ok=False);rows=json.loads((root/'manifest.json').read_text())['cases'];groups=collections.defaultdict(list)
 for c in rows:groups[c['unit']].append(c)
 counts=collections.Counter();allowed=collections.Counter();packets=0
 def reject(c,raw,name):
  try:f.check_isa(c,raw)
  except ValueError:counts[name]+=1;return
  raise AssertionError(('ineffective control',c['id'],name))
 def flag(raw,x):
  bad=bytearray(raw);struct.pack_into('<I',bad,80,x);struct.pack_into('<I',bad,88,(struct.unpack_from('<I',raw,88)[0]&~31)|x);return bad
 for unit,cs in groups.items():
  size=v.packet_size(cs[0]);cache={a:v.storage.verify(root/'runs'/unit/a/'packets.bin') for a in ('Reference','B','M1','M2','BOTH')}
  for i,c in enumerate(cs):
   if not (c['tag'].startswith(('strict-order','semantic-snan','no-active-snan','alias','state-vl0-none','sticky-31','ordered-opposite-inf'))):continue
   for arm,rawall in cache.items():
    raw=rawall[i*size:(i+1)*size];f.check_isa(c,raw);packets+=1
    b=c['vlen']//8;e=c['dst_eew']//8;off=96+32*b+c['vd']*b
    bad=bytearray(raw);bad[off]^=1;reject(c,bad,'wrong-result-or-VL0-write')
    # Flip DZ, which these reductions never newly raise. Sticky mutation is
    # coherent in fflags/fcsr, so rejection cannot come from inconsistent CSRs.
    fl=struct.unpack_from('<I',raw,80)[0];reject(c,flag(raw,fl^8),'exact-or-sticky-flags')
    bad=bytearray(raw);bad[96+32*b+((c['vd']+1)%32)*b]^=1;reject(c,bad,'other-register')
    bad=bytearray(raw);bad[-1]^=1;reject(c,bad,'scalar-FP-preservation')
    bad=bytearray(raw);bad[off+e]^=1
    if c['vl'] and c['ta']:
     good=bytearray(raw);old=raw[96+c['vd']*b+e:96+c['vd']*b+2*e];actual=raw[off+e:off+2*e]
     good[off+e:off+2*e]=old if actual==b'\xff'*e else b'\xff'*e
     if good!=raw:f.check_isa(c,good);allowed['changed-legal-tail']+=1
    else:reject(c,bad,'tail-or-VL0-preservation')
    if c['tag'].startswith('strict-order'):
     seed,xs=f.operands(c,f.initial(c));ys=[f.promote(c,x)[0] for x in xs]
     word,fl=f.fold(c['mnemonic'],c['dst_eew'],c['frm'],seed,tuple(reversed(ys)))
     fl|=c['fflags_initial']
     if (word,fl) not in f.allowed(c,f.initial(c)):
      bad=flag(raw,fl);bad[off:off+e]=word.to_bytes(e,'little');reject(c,bad,'coherent-wrong-order')
 v.save(out/'CONTROLS.json',dict(status='PASS',selected_actual_packets=packets,effective_rejections=sum(counts.values()),rejections=dict(counts),effective_changed_allowances=sum(allowed.values()),allowances=dict(allowed),checker_sha256=v.sha(Path(f.__file__)),guest_replays=0))
 print(packets,sum(counts.values()),dict(counts),flush=True)
if __name__=='__main__':controls(Path(sys.argv[1]),Path(sys.argv[2]))
