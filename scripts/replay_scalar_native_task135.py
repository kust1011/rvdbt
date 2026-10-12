"""Four unchanged external scalar-loop family calls with their original predicates.
Imports the retained original DUT predicate; never executes a reference engine.
"""
import importlib.util
import resource
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
import json
assert (root / 'build.rc').read_text() == '0'
build_pins = json.loads((root / 'BUILD_IDENTITY.json').read_text())
spec = importlib.util.spec_from_file_location('original121', '/home/vick/act-current121/run121.py')
act = importlib.util.module_from_spec(spec)
spec.loader.exec_module(act)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
act.STAGE = root / 'build'
act.R = root / 'external'
act.R.mkdir()
act.PINS = {str(p): act.sha(p) for p in
            (act.STAGE / 'bin/elfrun', act.STAGE / 'lib/libdbtjitshared.so')}
assert all(build_pins[str(p)] == act.sha(p) for p in (act.STAGE / 'bin/elfrun', act.STAGE / 'lib/libdbtjitshared.so'))
original = Path('/home/vick/act-current121/QUEUE.json')
queue = act.read(original)
cases = {'Vls32-vlseg2e32.v', 'Vls32-vlse32.v', 'Vls32-vluxei32.v', 'Vls32-vlm.v'}
entries = [e for e in queue['entries'] if e['case'] in cases]
calls = [c for c in queue['calls'] if c['case'] in cases and c['arm'] == 'B']
assert len(entries) == len(calls) == 4
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
