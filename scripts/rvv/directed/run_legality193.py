# SPDX-License-Identifier: MIT
"""One serial source probe and one read-only declaration capture on xbd."""
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import time

out = Path(sys.argv[1])
source = Path(sys.argv[2])
expected = json.loads((out/'EXPECTED_SOURCE.json').read_text())
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def gate(label):
    available = int(next(s.split()[1] for s in Path('/proc/meminfo').read_text().splitlines()
                         if s.startswith('MemAvailable:'))) * 1024
    r = dict(label=label, nice=os.getpriority(os.PRIO_PROCESS, 0),
             available_bytes=available, disk_free_bytes=shutil.disk_usage(out).free,
             own_executing_guests=0, own_executing_source_probes=1,
             affinity='none assigned')
    with (out/'RESOURCES.jsonl').open('a') as f:
        f.write(json.dumps(r)+'\n')
    assert r['nice'] == 10 and min(available, r['disk_free_bytes']) >= 10*1024**3


assert all(sha(source/p) == h for p, h in expected.items())
commands = [
    ['/usr/bin/clang++-22', '-std=gnu++20', '-O2', '-DNDEBUG',
     '-DRVV_HOST_CHUNK_BITS=512', '-mavx512f', '-mavx512bw',
     '-ffp-contract=off', '-DRVDBT_FROUND_IMPL=2', '-I'+str(source),
     '-isystem', str(source/'dbt/third_party/asmjit/src'),
     str(out/'legality193_predicates.cpp'), '-o', str(out/'probe')],
    [str(out/'probe')],
    ['python3', str(out/'capture_legality193.py'),
     str(out/'DIRECTED_PLAN.json.gz'), str(out/'DECLARATIONS.json')],
]
results = []
for i, cmd in enumerate(commands):
    gate(str(i))
    start = time.monotonic()
    with (out/f'{i}.stdout').open('wb') as stdout, (out/f'{i}.stderr').open('wb') as stderr:
        rc = subprocess.call(cmd, stdout=stdout, stderr=stderr, timeout=60)
    row = dict(command=cmd, rc=rc, seconds=time.monotonic()-start,
               stdout_sha256=sha(out/f'{i}.stdout'), stderr_sha256=sha(out/f'{i}.stderr'))
    results.append(row)
    (out/'EXECUTION.json').write_text(json.dumps(results, indent=2)+'\n')
    gate(str(i)+'-after')
    print(i, rc, flush=True)
    assert rc == 0
assert all(sha(source/p) == h for p, h in expected.items())
(out/'IDENTITIES.json').write_text(json.dumps(dict(source=expected,
    probe_sha256=sha(out/'probe'), probe_source_sha256=sha(out/'legality193_predicates.cpp'),
    production_rebuild=False, guest_calls=0), indent=2)+'\n')
