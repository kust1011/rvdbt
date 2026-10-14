#!/usr/bin/env python3
"""Detached execution receipt; SSH transport loss never causes a guest retry."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

B=Path('/home/vick/rvv-task197')
label=sys.argv[1];command=sys.argv[2:]
assert os.getpriority(os.PRIO_PROCESS,0)==10
d=B/'controllers'/label;d.mkdir(parents=True,exist_ok=False)
(d/'START.json').write_text(json.dumps(dict(pid=os.getpid(),command=command,time=time.time(),nice=10)))
with (d/'output.log').open('wb') as f:
    rc=subprocess.run(command,cwd=B,stdout=f,stderr=subprocess.STDOUT).returncode
(d/'EXIT.json').write_text(json.dumps(dict(returncode=rc,time=time.time())))
