#!/usr/bin/env python3
"""Retain actual QCG entry/trace/escape state for original or repaired witness."""
import json,subprocess,os,sys,fcntl,shlex
from pathlib import Path
b=Path(os.environ.get('RVV_TASK179_OUTPUT','/home/vick/rvv-directed-task179'))
fixed='--fixed' in sys.argv
if fixed:b=b/'fixed-gdb'
stackstep='--stackstep' in sys.argv
if stackstep:b=b/'stackstep-gdb'
b.mkdir(exist_ok=True)
(b/'cache').mkdir(exist_ok=True)
lock=open('/home/vick/rvv-directed-task179.own-semaphore','a');fcntl.flock(lock,fcntl.LOCK_EX)
assert os.getpriority(os.PRIO_PROCESS,0)==10
c=json.load(open('/home/vick/rvv-directed-task177/diagnostic-absolute-trace1/command.json'))
c=[a for a in c if not a.startswith(('--dump-','--rvv-pc-census-out='))]
c=[('--cache='+str(b/'cache')) if a.startswith('--cache=') else a for a in c]
g='''set pagination off
set breakpoint pending on
handle SIGALRM nostop noprint pass
break trampoline_to_jit
commands
silent
printf "ENTRY state=%p vmem=%p code=%p rsp=%p\\n",$rdi,$rsi,$rdx,$rsp
x/10gx $rsp
set $state=$rdi
set $tcode=$rdx
printf "ENTRY_GUEST_IP=%#x\\n",*(unsigned*)($state+0xb8)
x/35i $rdx
continue
end
break qcgstub_trace_cache
commands
silent
printf "TRACE state=%p target=%#lx entry=%#lx rsp=%p ret=%p\\n",$r13,$r14,$r15,$rsp,*(void**)$rsp
x/12gx $rsp
x/8i *(void**)$rsp
continue
end
break qcgstub_escape_link
commands
silent
printf "ESCAPE state=%p rsp=%p\\n",$r13,$rsp
x/12gx $rsp
continue
end
run
info registers
p $_siginfo
info proc mappings
x/16i qcgstub_escape_link
x/32gx $rsp-64
x/30i $pc-40
bt
kill
'''
if stackstep:
 g=g.replace('run\ninfo registers', 'break *qcgstub_escape_link+17\ncommands\nsilent\nprintf "PRE_RET target=%p state=%p rsp=%p\\n",*(void**)$rsp,$r13,$rsp\ninfo registers rip r13 r14 r15 rbp rsp\nx/4gx $rsp\nbt\ncontinue\nend\nrun\ninfo registers')
if fixed:
 c[0]='/home/vick/rvdbt-host512-task179-build/build/bin/elfrun'
 g=g.replace('x/35i $rdx\ncontinue','x/35i $rdx\ndisable 1\ncontinue').replace('x/8i *(void**)$rsp\ncontinue','x/8i *(void**)$rsp\ndisable 2\ncontinue').replace('x/12gx $rsp\ncontinue','x/12gx $rsp\ndisable 3\ncontinue')
 g=g[:g.index('run\ninfo registers')]+'run '+shlex.join(c[1:])+f' > {b}/packets.bin 2> {b}/guest.stderr\n'
(b/'gdb.cmd').write_text(g)
env=dict(os.environ,LD_LIBRARY_PATH=('/home/vick/rvdbt-host512-task179-build/build/lib' if fixed else '/home/vick/rvdbt-host512-task174-build/build/lib')+':/home/vick/boost_vendor/lib')
r=subprocess.run(['gdb','--batch','-x',str(b/'gdb.cmd'),'--args',*c],env=env,capture_output=True,timeout=45)
(b/'gdb.stdout').write_bytes(r.stdout);(b/'gdb.stderr').write_bytes(r.stderr);(b/'command.json').write_text(json.dumps(c,indent=2))
print(r.stdout.decode()[-14000:]);print(r.stderr.decode())
