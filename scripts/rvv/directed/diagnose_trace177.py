#!/usr/bin/env python3
"""Preserve and locate the unaccepted generic trace-cache host fault."""
import json,os,re,resource,subprocess,sys
from pathlib import Path
import vadd as v
b=Path('/home/vick/rvv-directed-task177');d=b/'diagnostic-gdb'
review_only='--review-existing' in sys.argv
if not review_only:d.mkdir(exist_ok=False)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
cmd=json.loads((b/'diagnostic-absolute-trace1/command.json').read_text())
cmd=[a for a in cmd if not a.startswith(('--dump-','--rvv-pc-census-out='))]
gdb=['gdb','--batch','-ex','set pagination off','-ex','handle SIGALRM nostop noprint pass',
     '-ex','run',
     '-ex','info registers rip r13 rsp',
     '-ex','printf "GUEST_IP=%#x\\n",*(unsigned*)($r13+0xb8)',
     '-ex','x/18i $pc-32','-ex','bt','-ex','kill','--args',*cmd]
env=dict(os.environ,LD_LIBRARY_PATH='/home/vick/rvdbt-host512-task174-build/build/lib:/home/vick/boost_vendor/lib')
if not review_only:
    v.save(d/'command.json',gdb)
    r=subprocess.run(gdb,capture_output=True,env=env,timeout=30)
    (d/'stdout').write_bytes(r.stdout);(d/'stderr').write_bytes(r.stderr)
    v.save(d/'controller.json',dict(returncode=r.returncode))
text=(d/'stdout').read_text();m=re.search(r'GUEST_IP=(0x[0-9a-f]+)',text)
state=re.search(r'r13\s+(0x[0-9a-f]+)',text)
assert 'received signal SIGSEGV' in text and state,text
v.save(d/'RESULT.json',dict(status='REPRODUCED_UNACCEPTED_HOST_FAULT',guest_ip=m[1] if m else None,state_register_r13=state[1],first_target_pc='0x102c8',before_first_sequence_target='NOT_PROVEN',accepted_packet_credit=0,root_cause='NOT_PROVEN',production_fix='NOT_DONE',review_only=review_only,scope='generic trace-cache mode; default trace=0 finite matrix is separate'))
print(text[-4000:])
