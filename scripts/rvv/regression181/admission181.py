"""Task181 shared admission and sampled resource evidence."""
import fcntl, json, os, shutil, subprocess, threading, time
from pathlib import Path
BASE = Path(os.environ.get('RVV_TASK181_ROOT','/home/vick/rvv-task181'))
LOCK = threading.Lock()
def census():
    rows=[]
    for p in Path('/proc').iterdir():
        if not p.name.isdigit(): continue
        try:
            args=(p/'cmdline').read_bytes().split(b'\0'); exe=Path(args[0].decode()).name
            name=Path(args[1].decode()).name if len(args)>1 else ''
            cmd=b' '.join(args).decode(errors='replace'); st=(p/'stat').read_text().rsplit(')',1)[1].split()
            cwd=str((p/'cwd').resolve())
        except (OSError,ValueError,IndexError): continue
        audit_replay=name=='replay.py' and len(args)>2 and args[2]==b'audit'
        kind='guest' if exe in ('elfrun','spike','sail_riscv_sim') else 'build' if exe.startswith(('clang','ld.lld')) else 'offline' if exe in ('python','python3') and (audit_replay or any(x in name for x in ('audit','controls','reject_','crosscheck','finalize'))) else None
        role='worker'
        if audit_replay:
            try:role='controller' if (p/'task'/p.name/'children').read_text().strip() else 'worker'
            except OSError:pass
        if kind:
            try:tagged=b'RVV_TASK181_OWNER=181' in (p/'environ').read_bytes()
            except OSError:tagged=False
            rows.append(dict(role=role,pid=int(p.name),kind=kind,own=tagged or any(x in cmd or x in cwd for x in ('rvv-task178','rvv-task181')),nice=int(st[16]),command=cmd))
    return rows
original=subprocess.Popen
def admitted(*args,**kwargs):
    cmd=args[0] if args else kwargs['args']; exe=Path(str(cmd[0])).name
    kind='guest' if exe in ('elfrun','spike','sail_riscv_sim') else 'build' if exe.startswith(('clang','ld.lld')) else None
    if not kind:return original(*args,**kwargs)
    while True:
        with LOCK,open('/tmp/rvv-shared-admission.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX); rows=census()
            if sum(r['kind']==kind for r in rows)<(16 if kind=='guest' else 4) and sum(r['kind']==kind and r['own'] for r in rows)<(8 if kind=='guest' else 4) and shutil.disk_usage(BASE).free>=11*1024**3:
                return original(*args,**kwargs)
        time.sleep(.5)
subprocess.Popen=admitted
def monitor():
    while not (BASE/'FINAL_COMPLETE').exists():
        with (BASE/'RESOURCES.jsonl').open('a') as f:f.write(json.dumps(dict(time=time.time(),free=shutil.disk_usage(BASE).free,processes=census()))+'\n')
        time.sleep(5)

# Cross-controller predicate slots: online checks and retained-stream audits
# share the same two slots, including across forked directed workers.
from contextlib import contextmanager
_last_offline_check=0
@contextmanager
def predicate_slot():
    global _last_offline_check
    while True:
        for n in range(2):
            f=open('/tmp/rvv-task181-predicate-%d.lock'%n,'a')
            try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:f.close();continue
            try:
                if time.monotonic()-_last_offline_check>=1:
                    while sum(r['kind']=='offline' and not r['own'] and r.get('role')!='controller' for r in census())>2:time.sleep(.5)
                    _last_offline_check=time.monotonic()
                yield
            finally:fcntl.flock(f,fcntl.LOCK_UN);f.close()
            return
        time.sleep(.05)
