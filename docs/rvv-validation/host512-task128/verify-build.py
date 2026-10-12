import json,hashlib,subprocess
from pathlib import Path
r=Path('/home/vick/rvdbt-host512-task128');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
head=json.loads((r/'head-inputs.json').read_text());different=[p for p,h in head.items() if sha(r/'source'/p)!=h];assert not different
cache=(r/'build/CMakeCache.txt').read_text();assert 'RVV_HOST_CHUNK_BITS:STRING=512' in cache and 'CMAKE_BUILD_TYPE:STRING=Release' in cache
commands=json.loads((r/'build/compile_commands.json').read_text());prod=[c for c in commands if any(t in c['command'] for t in ('/dbtstatic.dir/','/dbtjitshared.dir/','/elfrun.dir/')) and c['file'].endswith('.cpp')];assert prod
for c in prod:assert all(f in c['command'] for f in ('-DRVV_HOST_CHUNK_BITS=512','-mavx512f','-mavx512bw','-O3','-DNDEBUG'))
(r/'SOURCE_EQUALITY.pre.json').write_text(json.dumps(dict(source_commit='a6c50facfac092c10fdfee2e8a8b4f34e86a22f8',inputs=len(head),differences=different,hashes=head),indent=2)+'\n')
(r/'FLAGS_AUDIT.json').write_text(json.dumps(dict(host_bits=512,build_type='Release',production_cpp_commands=len(prod),all_have_host512_avx512f_bw_O3_NDEBUG=True,compiler_commands=prod),indent=2)+'\n')
(r/'BUILD_IDENTITY.pre.json').write_text(json.dumps({str(p.relative_to(r)):sha(p) for p in sorted((r/'build/bin').iterdir()) if p.is_file()}|{'build/lib/libdbtjitshared.so':sha(r/'build/lib/libdbtjitshared.so')},indent=2)+'\n')
for p in ('build/bin/elfrun','build/lib/libdbtjitshared.so'):
 x=subprocess.run(['ldd','-r',str(r/p)],capture_output=True,text=True);(r/(Path(p).name+'.ldd')).write_text(x.stdout+x.stderr)
 assert x.returncode==0
print('SOURCE_FLAGS_PASS',len(head),len(prod))
