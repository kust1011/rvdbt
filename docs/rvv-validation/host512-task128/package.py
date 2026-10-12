import pathlib,json,hashlib,tarfile,shutil
r=pathlib.Path('/home/vick/rvdbt-host512-task128');d=r/'build-evidence';d.mkdir(exist_ok=True)
for name in ('CMakeCache.txt','compile_commands.json'):shutil.copy2(r/'build'/name,d/name)
for target in ('dbtstatic','dbtjitshared','elfrun'):
 for f in ('flags.make','link.txt'):
  p=r/'build/dbt/CMakeFiles'/f'{target}.dir'/f
  if p.exists():shutil.copy2(p,d/(target+'-'+f))
files=[]
for p in r.rglob('*'):
 if not p.is_file() or p.is_symlink():continue
 rel=p.relative_to(r)
 if rel.parts[0] in ('source','build','source-evidence','linkage-fixture') or 'work' in rel.parts or 'cache' in rel.parts or 'fs' in rel.parts or rel.name in ('overlay.tar.gz','receipts.tar.gz','RAW_MANIFEST.json') or '__pycache__' in rel.parts:continue
 if rel.parts[0]=='exit-only' and rel.parts[1] in ('source','build'):continue
 files.append(p)
manifest={str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}
(r/'RAW_MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n')
with tarfile.open(r/'receipts.tar.gz','w:gz') as t:
 for p in sorted(files)+[r/'RAW_MANIFEST.json']:t.add(p,arcname=str(p.relative_to(r)),recursive=False)
print('PACKAGED',len(manifest),(r/'receipts.tar.gz').stat().st_size,hashlib.sha256((r/'receipts.tar.gz').read_bytes()).hexdigest())
