#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Opt-in lossless retention; logical paths also read legacy plain artifacts."""
import gzip,hashlib,json,os,shutil,threading
from pathlib import Path
RESERVE=10*1024**3

def enabled():return os.environ.get('RVV_COMPRESS')=='1'
def reserve(path,estimate=64*1024**2):
    path=Path(path)
    while not path.exists():path=path.parent
    if enabled() and shutil.disk_usage(path).free < RESERVE+estimate:
        raise RuntimeError('storage reserve: require 10GiB plus next batch estimate')
def digest(raw):return hashlib.sha256(raw).hexdigest()
def physical(path):
    p=Path(path)
    return p if p.exists() else Path(str(p)+'.gz')
def read(path):
    p=physical(path)
    return gzip.decompress(p.read_bytes()) if p!=Path(path) else p.read_bytes()
def text(path):return read(path).decode()
def receipt(path,logical_hash,size):
    p=Path(path);gz=Path(str(p)+'.gz')
    meta=dict(logical_path=p.name,logical_sha256=logical_hash,logical_bytes=size,codec='gzip',stored_file=gz.name,compressed_sha256=digest(gz.read_bytes()),stored_bytes=gz.stat().st_size)
    Path(str(p)+'.storage.json').write_text(json.dumps(meta,sort_keys=True)+'\n')
def verify(path):
    p=Path(path);raw=read(p);meta=Path(str(p)+'.storage.json')
    if meta.exists():
        m=json.loads(meta.read_text())
        if digest(raw)!=m['logical_sha256'] or len(raw)!=m['logical_bytes'] or digest(Path(str(p)+'.gz').read_bytes())!=m['compressed_sha256']:raise ValueError('compressed/logical artifact identity mismatch')
    return raw

def write(path,raw,alias=None):
    p=Path(path)
    if not enabled():p.write_bytes(raw);return
    reserve(p.parent,len(raw)+1024**2)
    gz=Path(str(p)+'.gz')
    if alias is not None and physical(alias).suffix=='.gz' and read(alias)==raw:
        os.link(physical(alias),gz)
    else:
        with gzip.GzipFile(filename=str(gz),mode='wb',mtime=0) as f:f.write(raw)
    receipt(p,digest(raw),len(raw))
    if verify(p)!=raw:raise ValueError('lossless retention failed')
def compress(path):
    p=Path(path)
    if enabled() and p.exists():
        raw=p.read_bytes();write(p,raw);p.unlink() # only NEW opted-in artifacts

def link_compressed(source,target):
    # A plaintext source may be materialized while a worker is executing.
    # Retained aliases must point explicitly to the permanent compressed file.
    gz=Path(str(source)+'.gz');alias=Path(str(target)+'.gz')
    if not gz.exists():raise FileNotFoundError(gz)
    os.symlink(os.path.relpath(gz,alias.parent),alias)

def materialize(path):
    p=Path(path)
    if not p.exists():p.write_bytes(verify(p));return True
    return False

def capture(pipe,path,errors):
    try:
        h=hashlib.sha256();n=0
        with gzip.GzipFile(filename=str(path)+'.gz',mode='wb',mtime=0) as f:
            while True:
                data=pipe.read(1024*1024)
                if not data:break
                reserve(path.parent,len(data)+1024**2);f.write(data);h.update(data);n+=len(data)
        receipt(path,h.hexdigest(),n)
    except BaseException as ex:errors.append(ex)
    finally:pipe.close()

def execute(cmd,d,env,timeout):
    import subprocess,signal,time
    reserve(d.parent)
    d.mkdir(parents=True,exist_ok=False)
    (d/'command.json').write_text(json.dumps(list(map(str,cmd)),indent=2)+'\n');start=time.monotonic()
    p=subprocess.Popen(list(map(str,cmd)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,stdin=subprocess.DEVNULL,start_new_session=True)
    errors=[];threads=[threading.Thread(target=capture,args=(pipe,d/name,errors)) for pipe,name in [(p.stdout,'stdout'),(p.stderr,'stderr')]]
    for t in threads:t.start()
    try:rc=p.wait(timeout=timeout);expired=False
    except subprocess.TimeoutExpired:
        expired=True
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        rc=p.wait()
    for t in threads:t.join()
    if errors:raise errors[0]
    rec=dict(returncode=rc,timeout=expired,seconds=time.monotonic()-start,stdout_sha256=digest(verify(d/'stdout')),stderr_sha256=digest(verify(d/'stderr')),storage='lossless-gzip-v1')
    (d/'execution.json').write_text(json.dumps(rec,indent=2)+'\n');return rec

def retain_tree(root):
    if enabled():
        for p in Path(root).rglob('*'):
            if p.is_file() and not p.name.endswith(('.gz','.storage.json')):compress(p)
