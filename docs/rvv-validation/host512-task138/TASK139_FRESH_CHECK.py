"""Task139 fresh-directory verification harness; saved exact executed check."""
import contextlib
import gzip
import hashlib
import io
import json
from pathlib import Path
import runpy
import sys

sys.dont_write_bytecode = True
repo = Path('repo').resolve()
checks = Path('checks').resolve(); checks.mkdir(exist_ok=False)
inspection = Path('inspection').resolve()
# No author-path, subprocess, network or guest/reference fallback is possible.
def guard(event, args):
    if event == 'open' and isinstance(args[0], (str, bytes)):
        name = str(args[0])
        if name.startswith('/home/'):
            raise RuntimeError('forbidden author-path access: '+name)
    if event in ('subprocess.Popen', 'os.system', 'socket.connect'):
        raise RuntimeError('forbidden live operation: '+event)
sys.addaudithook(guard)
sys.path.insert(0, str(repo/'scripts'))
from rvv_host512_corpus import read
from rvv_scope_report import main
base = ['--host512-raw', str(inspection/'current/raw'),
        '--host512-evidence', str(inspection/'current'),
        '--chips-package', str(inspection/'chips'),
        '--act-db2-package', str(inspection/'act'),
        '--ara-package', str(inspection/'ara')]
results = dict(forbidden_author_path_access=True, forbidden_live_operations=True,
               new_guest_reference_fault_performance_executions=0, commands=[],
               reader_sha256={name:hashlib.sha256((repo/'scripts'/name).read_bytes()).hexdigest()
                   for name in ('rvv_scope_report.py','rvv_host512_corpus.py','rvv_ara_replay.py')},
               package_manifest_sha256={name:hashlib.sha256((inspection/name/'FILES.json').read_bytes()).hexdigest()
                   for name in ('chips','act','ara','current')})
def invoke(label, args, rejection=None):
    sys.argv = ['rvv_scope_report.py', *args]
    stdout = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout): main()
    except (ValueError, FileNotFoundError) as e:
        if rejection is None: raise
        results['commands'].append(dict(label=label, argv=sys.argv, status='REJECTED', reason=str(e)))
        assert not (checks/label).exists(), 'rejected call wrote selection'
    else:
        assert rejection is None, 'bad receipt accepted'
        results['commands'].append(dict(label=label, argv=sys.argv, status='PASS'))
    (checks/(label+'.stdout')).write_text(stdout.getvalue())
    (checks/'RESULT.json').write_text(json.dumps(results, indent=2)+'\n')
nav = repo/'docs/rvv-validation/host512-task138/combined/navigation.json.gz'
invoke('audit', ['--host512-corpus', str(repo/'docs/rvv-validation'),
                 '--host512-task138-build', *base, '--output', str(checks/'audit')])
summary = read(checks/'audit/SUMMARY.json')
assert summary['task138']==21316 and summary['checked_union']==595
sources = read(checks/'audit/PORTABLE_SOURCES.json.gz')
assert len(sources['records'])==21316
results['summary'] = dict(calls=21316, forms=595, source_dependencies=sources['checked_payload_files'],
                          original_current_predicate_counts=sources['original_current_predicate_counts'])
invoke('regenerated-vadd', ['--host512-corpus',str(checks/'audit/navigation.json.gz'),*base,
                          '--form','vadd.vv','--suite','chips','--arm','B','--output',str(checks/'regenerated-vadd')])
for form in ('vadd.vv','vle32.v','vfadd.vv','vmand.mm','vsetvli'):
    label='select-'+form
    invoke(label, ['--host512-corpus',str(nav),*base,'--form',form,'--arm','B','--output',str(checks/label)])
    selected=read(checks/label/'record.json')
    assert selected['records'] and selected['current_raw_verification']=='CHECKED'
    assert all(r['task']==138 for r in selected['records'])
    assert selected['original_ACT_reference_blockers'], 'original blockers disappeared'
    assert all('UNKNOWN' in str(r['observed_runtime']) for r in selected['records'] if r['suite'] in ('chips','act')), 'unknown tuple inferred'
    results.setdefault('selections',{})[form]=dict(records=len(selected['records']),
        suites=sorted({r['suite'] for r in selected['records']}),
        original_current_predicate_counts=selected['portable_sources']['original_current_predicate_counts'])
record=next(r for r in read(checks/'select-vadd.vv/record.json')['records'] if r['suite']=='chips')
stream=Path(record['local_receipt'])/'stdout'; original=stream.read_bytes()
args=['--host512-corpus',str(nav),*base,'--form','vadd.vv','--suite','chips','--arm','B']
receipt = stream.parent; held = receipt.with_name(receipt.name+'.task139-held')
receipt.rename(held)
try: invoke('missing-current', [*args,'--output',str(checks/'missing-current')], rejection=True)
finally: held.rename(receipt)
stream.write_bytes(original+b'TASK139_CORRUPTION_CONTROL\n')
try: invoke('corrupt-current', [*args,'--output',str(checks/'corrupt-current')], rejection=True)
finally: stream.write_bytes(original)
results['status']='PASS'
(checks/'RESULT.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results['summary']))
