#!/usr/bin/env python3
"""Single repository entrypoint for Task178's frozen common-build regression."""
import argparse,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('action',choices=['prepare','run','external','external-audit','focused','summarize','status'])
p.add_argument('--host',default='xbd');p.add_argument('--focused-suite',choices=['guard165','guard166','faults','fof-startmask','vill'])
a=p.parse_args()
root='/home/vick/rvv-task178'
commands={'prepare':['python3','tools/prepare.py'],'run':['python3','tools/run.py'],'external':['python3','tools/external.py',root+'/external'],'external-audit':['python3','tools/audit_external.py'],'summarize':['python3','tools/summarize.py'],'status':['python3','tools/status.py']}
if a.action=='focused':
 if not a.focused_suite:p.error('--focused-suite is required')
 commands['focused']=['python3','tools/focused.py',a.focused_suite]
import shlex
command='cd '+shlex.quote(root)+' && nice -n 10 env PYTHONDONTWRITEBYTECODE=1 '+shlex.join(commands[a.action])
raise SystemExit(subprocess.run(['ssh',a.host,command]).returncode)
