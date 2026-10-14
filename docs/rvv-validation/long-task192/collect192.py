"""Package only Task192's own evidence; no old artifact-tree traversal."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile
import sys

root = Path(sys.argv[1])
assert os.getpriority(os.PRIO_PROCESS, 0) == 10
assert shutil.disk_usage(root).free >= 10*1024**3
admin = root/'administrative'
admin.mkdir(exist_ok=False)
for p in ('CMakeCache.txt', 'compile_commands.json',
          'dbt/CMakeFiles/dbtstatic.dir/flags.make',
          'dbt/CMakeFiles/elfrun.dir/link.txt',
          'dbt/CMakeFiles/qra_vpr_test.dir/link.txt'):
    source = root/'build'/p
    shutil.copy2(source, admin/p.replace('/', '__'))
for name in ('qra.cpp', 'qra_vpr_test.cpp'):
    shutil.copy2(root/'source/dbt/qmc/qcg'/name, admin/name)
tools = Path('/home/vick/rvdbt-exception-task186/task191-tools')
reused = {}
for name in ('vadd.py', 'sequences177.py', 'fp157.py', 'storage149.py', 'config.py'):
    source = tools/name
    shutil.copy2(source, admin/name)
    reused[name] = hashlib.sha256(source.read_bytes()).hexdigest()
pins = {}
for name in ('elfrun', 'qra_vpr_test'):
    p = root/'build/bin'/name
    pins[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
for name in ('libdbtstatic.a', 'libdbtjitshared.so'):
    p = root/'build/lib'/name
    pins[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
old = Path('/home/vick/rvdbt-exception-task186/build/bin/elfrun')
assert hashlib.sha256(old.read_bytes()).hexdigest() == '37a25624345214d97e3691cfd9f951166abfe92419ce2bbeca9c786b68227c14'
(root/'MANIFEST.json').write_text(json.dumps(dict(
    binaries=pins, reused_tools=reused, source191=json.loads((root/'SOURCE191.json').read_text()),
    fixed_sources={n: hashlib.sha256((admin/n).read_bytes()).hexdigest()
                   for n in ('qra.cpp', 'qra_vpr_test.cpp')},
    build_workers=2, correctness_workers=2, nice=10,
    affinity='inherited; no affinity changes', free_bytes=shutil.disk_usage(root).free,
    retained_failures='pilot/runs/long192-fp-w4096-e32-m4/{B,M1,M2,BOTH}',
    controller_transport='Two ssh commands returned255 after remote completion; retained build.json rc0, BUILD PASS and remaining/summary.json PASS plus run-resources authenticate completed stages; no guest replay for transport status.'
), indent=2)+'\n')
archive = root/'raw-receipts.tar.gz'
with tarfile.open(archive, 'w:gz', dereference=True) as tar:
    for p in sorted(root.iterdir()):
        if p.name not in ('source', 'build', archive.name):
            tar.add(p, arcname='task192/'+p.name,
                    filter=lambda info: None if '__pycache__' in info.name else info)
receipt = dict(bytes=archive.stat().st_size,
               sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
               free_after=shutil.disk_usage(root).free)
assert receipt['free_after'] >= 10*1024**3
(root/'RETENTION.json').write_text(json.dumps(receipt, indent=2)+'\n')
print(receipt)
