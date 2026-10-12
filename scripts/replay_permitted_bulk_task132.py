"""Nine unchanged ACT normal calls for affected ordinary/whole memory families.
Imports the retained original DUT predicate; never executes a reference engine.
"""
import importlib.util
import resource
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location('original121', '/home/vick/act-current121/run121.py')
act = importlib.util.module_from_spec(spec)
spec.loader.exec_module(act)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
act.STAGE = root / 'build'
act.R = root / 'external'
act.R.mkdir()
act.PINS = {str(p): act.sha(p) for p in
            (act.STAGE / 'bin/elfrun', act.STAGE / 'lib/libdbtjitshared.so')}
original = Path('/home/vick/act-current121/QUEUE.json')
queue = act.read(original)
cases = {'Vls8-vle8.v', 'Vls16-vle16.v', 'Vls32-vle32.v', 'Vls64-vle64.v',
         'Vls32-vse32.v', 'Vls64-vse64.v', 'Vls8-vl1re8.v', 'Vls8-vl1re64.v', 'Vls8-vs1r.v'}
entries = [e for e in queue['entries'] if e['case'] in cases]
calls = [c for c in queue['calls'] if c['case'] in cases and c['arm'] == 'B']
assert len(entries) == len(calls) == 9
inputs = {}
for entry in entries:
    for field in ('source', 'elf', 'checker', 'expected', 'capture'):
        p = Path(entry[field])
        assert act.sha(p) == entry[field + '_sha256']
        inputs[str(p)] = act.sha(p)
for p in (original, Path(spec.origin), Path('/home/vick/rvv-task109/execute109.py'), Path(__file__)):
    inputs[str(p)] = act.sha(p)
act.save(act.R / 'INPUTS.json', inputs)
act.save(act.R / 'QUEUE.json', {'entries': entries, 'calls': calls,
                              'predicate': queue['original_DUT_predicate']})
results = []
for cell in calls:
    results.append({'case': cell['case'], 'status': act.run(cell)})
assert all(act.sha(Path(p)) == h for p, h in inputs.items())
act.save(act.R / 'RESULTS.json', results)
print(results, flush=True)
