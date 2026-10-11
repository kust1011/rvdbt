# SPDX-License-Identifier: Apache-2.0
"""Stage the retained Task53 evidence on xbd; never build or run an ISA test."""
import argparse
import collections
import csv
import difflib
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

PIN = 'c3e04e698e4ab753df41655d418edd95620c6c19'
PREFIX = 'artifacts/rvv_validation_delivery_20261009/act-generation53/'


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--campaign', type=Path, required=True)
    ap.add_argument('--metadata', type=Path, required=True)
    ap.add_argument('--canonical', type=Path, required=True)
    ap.add_argument('--act', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--tools', type=Path, required=True)
    ap.add_argument('--clear-license', type=Path, required=True)
    a = ap.parse_args()
    root = a.output
    root.mkdir(parents=True, exist_ok=False)
    selected, paths, identities, legal = {}, {}, {}, {}
    audit = json.loads((a.metadata/'AUDIT.json').read_text())
    immutable = {k.split(PREFIX, 1)[1]: v for k, v in audit['immutable_inputs'].items() if PREFIX in k}
    reg = json.loads((a.campaign/'REGISTERED.json').read_text())
    assert reg['revision'] == PIN
    if len(list((a.metadata/'cases').glob('*/SCOPE_AUDIT.json'))) != 1919:
        raise ValueError('author metadata transfer incomplete: expected 1919 case scope records')

    def save(name, value):
        p = root/name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(value, indent=2)+'\n')

    def add(p, name, original=None, license_basis=None):
        if not p.is_file() or p.is_symlink():
            raise ValueError('missing/nonregular dependency: '+str(p))
        h = digest(p)
        if name in selected:
            assert selected[name] == h
            return name
        original = original or name.removeprefix('records/')
        expected = immutable.get(original) or reg['source_sha256'].get(original)
        if expected:
            assert h == expected, ('retained identity changed', original)
            identities[name] = dict(sha256=h, authority='Task53 AUDIT/REGISTERED', original=original)
        dest = root/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, dest)
        selected[name] = h
        if name.startswith('records/'):
            for old in (PREFIX+original, '/home/vick/act-generation53/'+original):
                paths[old] = name
        if p.suffix in ('.S', '.h', '.c', '.py', '.ld', '.yaml', '.svh', '.csv') or p.name.endswith('.py.txt'):
            header = p.read_text(errors='replace')[:4000]
            m = re.search(r'SPDX-License-Identifier:\s*([^\s*]+)', header)
            legal[name] = dict(spdx=m[1] if m else None,
                              basis=license_basis or ('retained SPDX and author notice' if m else
                              'ACT pinned README Licensing; both code license texts retained; no relicensing'))
        return name

    # Originals remain byte exact. Task53 final author metadata overlays only files
    # absent from the remote campaign, without modifying that campaign.
    names = '''REGISTERED.json INPUT_DISPOSITIONS.json FINAL_COUNTS.json GENERATION_SUMMARY.json
        LAUNCH_REGISTRATION.json FLAGS_PROTOTYPE.json COMPILER_PROVENANCE.json PRIOR_ACCEPTED.json
        OUTPUT_SELECTION.json PILOT_SELECTION.json GATE_CORRECTIONS_V2.json GATE_REGEX_CORRECTION.json
        GATE_V2_CHECKS.json REFERENCE_DIAGNOSTICS.json PROFILE_GAPS.json REFERENCE_FAILURE_CLASSIFICATION.json
        FINAL_VALIDATION.json LEDGER_DELTA.json GLOBAL_PRIOR_IDENTITY_CHECK.json FULL_FLAGS_PROOF.json
        COVERAGE_DELTA.json PLANNED_STATUS_CORRECTION.json TRANSFER_INTERRUPTION.json SCOPE_AUDIT.json
        AUDIT.json README.md generate.py execute.py execute.compute.py.txt execute.remainder.py.txt
        memory_ls.py memory_ls.v1.py.txt memory_ls.v2.py.txt audit.py scope.py manifest_join.py
        check_gate_v2.py repair_preflight.py reference_diagnostic.py
        initial-pilot-path-error.txt compute.stdout compute.stderr remainder.stdout remainder.stderr
        generation.stdout generation.stderr correction-batch.stdout correction-batch.stderr
        reference-diagnostic.stdout reference-diagnostic.stderr'''.split()
    for n in names:
        p = a.metadata/n if (a.metadata/n).is_file() else a.campaign/n
        add(p, 'records/'+n)
    for folder in ('common', 'stage-flags', 'generation-logs', 'adapter-blocked-attempts',
                   'adapter-corrections-v2', 'offline-v2-gate-checks', 'reference-diagnostics'):
        base = a.metadata/folder if folder == 'stage-flags' else a.campaign/folder
        for p in sorted(base.rglob('*')):
            if p.is_file() and p.suffix not in ('.elf', '.pyc'):
                add(p, 'records/'+str(p.relative_to(base.parent)))
    # Only the selected testplans and vector generation entrypoints are included.
    # Registered hashes of all other generation inputs remain in REGISTERED.
    for n in ('testplans/Vx.csv', 'testplans/Vls.csv', 'testplans/Vf.csv',
              'generators/testgen/scripts/vector-testgen-unpriv.py',
              'generators/testgen/scripts/vector_testgen_common.py'):
        add(a.campaign/'pinned-source'/n, 'records/pinned-source/'+n)
    # The build helper is provenance; offline inspection imports only sig_modify.
    for n in ('sig_modify.py', 'build_plan.py'):
        p = a.act/'framework/src/act'/n
        original = subprocess.check_output(['git', '-C', str(a.act), 'show', PIN+':framework/src/act/'+n])
        assert p.read_bytes() == original
        add(p, 'sources/act/framework/'+n)
    for n in ('COPYING.APACHE', 'COPYING.BSD', 'COPYING.CC', 'README.md'):
        p = a.act/n
        assert p.read_bytes() == subprocess.check_output(['git', '-C', str(a.act), 'show', PIN+':'+n])
        add(p, 'licenses/ACT-'+n)
    add(a.clear_license, 'licenses/BSD-3-Clause-Clear.txt')
    for n in ('verify_rvv_act_inspection.py', 'check_rvv_act_rejection.py', 'package_rvv_act_inspection.py'):
        add(a.tools/n, 'tools/'+n, license_basis='Local delivery tools: Apache-2.0 SPDX')
    add(a.tools/'EXISTING_ARCHIVE_REVIEW.json', 'EXISTING_ARCHIVE_REVIEW.json')

    cases, outside = [], []
    for p in sorted((a.campaign/'cases').glob('*/RESULT.json')):
        r = json.loads(p.read_text()); n = r['case']; base = p.parent
        for f in sorted(base.rglob('*')):
            if f.is_file() and f.suffix not in ('.elf', '.pyc'):
                add(f, 'records/'+str(f.relative_to(a.campaign)))
        for f in (a.metadata/'cases'/n).glob('*'):
            if f.is_file(): add(f, 'records/cases/'+n+'/'+f.name)
        source = 'records/cases/'+n+'/'+n+'.S'
        assert digest(root/source) == r['source_sha256']
        paths[PREFIX+r['source_path']] = source
        paths['/home/vick/act-generation53/'+r['source_path']] = source
        record = dict(case=n, input_id=r['input_id'], form=r['form'], sew=r['sew'], status=r['status'],
                      source=source, result='records/cases/'+n+'/RESULT.json',
                      checker='records/common/user_env/signature.h',
                      original_checker='records/common/upstream/env/signature.h',
                      processor='records/common/reference_config/sig_modify.py',
                      adapter='records/common/user_env/rvmodel_macros.h',
                      linker='records/common/user_link.ld',
                      capture_config='records/common/reference_config/sail.json',
                      references=r['reference'], DUT=r['DUT'])
        if r['status'] == 'PRIOR_ACCEPTED':
            record['inspection_scope'] = 'OUTSIDE_PRIMARY_PACKAGE: Task49 receipt aliases only; no prior raw repackaging'
            outside.append(dict(case=n, source=source, prior_row_ids=[x['row_id'] for x in r['prior_joins']],
                                reason=record['inspection_scope']))
        else:
            for key, suffix in (('signature', '.sig'), ('expected', '.results')):
                record[key] = 'records/cases/'+n+'/'+n+suffix
            record['oracle'] = 'records/cases/'+n+'/ORACLE.json'
            record['preservation'] = 'records/cases/'+n+'/PRESERVATION.json'
            record['checker_scope'] = 'records/cases/'+n+'/CHECKER_SCOPE.json'
            record['source_scope'] = 'records/cases/'+n+'/SCOPE_AUDIT.json'
        cases.append(record)
    assert collections.Counter(x['status'] for x in cases) == {'PASS':1876, 'REFERENCE_ERROR':2, 'PRIOR_ACCEPTED':41}
    save('CASES.json', cases); save('OUTSIDE_PRIMARY.json', outside)
    forms = collections.defaultdict(list)
    for i, c in enumerate(cases): forms[c['form']].append(i)
    save('FORMS.json', dict(sorted(forms.items())))

    ledger, bindings = [], []
    canonical = {}
    for n in ('SUITE_RUN_MANIFEST.csv', 'ACTUAL_FORM_VALIDATION_BINDINGS.csv'):
        src = a.canonical/n
        canonical[n] = dict(sha256=digest(src), bytes=src.stat().st_size)
        with src.open() as f:
            reader = csv.DictReader(f); fields = reader.fieldnames
            rows = [r for r in reader if r['suite']=='ACT' and
                    (r.get('cohort')=='Task53-pinned-default-generation' or PREFIX in str(r))]
        with (root/n).open('w') as f:
            writer = csv.DictWriter(f, fieldnames=fields); writer.writeheader(); writer.writerows(rows)
        if n.startswith('SUITE'): ledger = rows
        else: bindings = rows
    assert len(ledger)==15364 and len(bindings)==7512
    case_by_name = {x['case']:x for x in cases}
    navigation = []
    for b in bindings:
        c = case_by_name[b['source_case']]
        raw = 'records/cases/'+c['case']+'/raw/DUT-'+b['arm'] if b['result']=='PASS' else None
        navigation.append(dict(form=b['target_forms'], case=c['case'], arm=b['arm'],
                               ledger_row_id=b['ledger_row_id'], result=b['result'], acceptance=b['acceptance'],
                               source=c['source'], checker=c['checker'], raw=raw,
                               oracle=c.get('oracle'), reference_case=c['case'],
                               flags_json=b['flags_json']))
    save('NAVIGATION.json', navigation); save('CANONICAL_INPUTS.json', canonical)
    save('PATHS.json', paths); save('ORIGINAL_IDENTITIES.json', identities)
    excluded = []
    for original, h in sorted({**reg['source_sha256'], **immutable}.items()):
        if PREFIX+original not in paths:
            excluded.append(dict(original=PREFIX+original, sha256=h,
                reason='deliberately excluded binary' if original.endswith('.elf') else
                       'outside selected inspection payload; retained generator/history identity only'))
    excluded_tools = dict(json.loads((root/'records/LAUNCH_REGISTRATION.json').read_text())['pins'])
    provenance = json.loads((root/'records/COMPILER_PROVENANCE.json').read_text())
    excluded_tools.update({p:v['sha256'] for p,v in provenance['tools'].items()})
    excluded_tools.update(provenance['runtime_libraries'])
    for original, h in sorted(excluded_tools.items()):
        if original.endswith('/sig_modify.py'):
            paths[original] = 'sources/act/framework/sig_modify.py'
        else:
            excluded.append(dict(original=original, sha256=h, reason='deliberately excluded tool executable/library'))
    save('PATHS.json', paths)
    save('EXCLUDED_IDENTITIES.json', excluded)
    deltas = []
    for p in sorted((root/'records/common/user_env').iterdir()):
        original = root/'records/common/upstream/env'/p.name
        if original.is_file() and original.read_bytes()!=p.read_bytes():
            name = 'deltas/'+p.name+'.diff'; out=root/name;out.parent.mkdir(exist_ok=True)
            out.write_text(''.join(difflib.unified_diff(original.read_text().splitlines(True), p.read_text().splitlines(True),
                           fromfile=str(original.relative_to(root)), tofile=str(p.relative_to(root)))))
            deltas.append(dict(original=str(original.relative_to(root)), adapter=str(p.relative_to(root)), diff=name))
    original = root/'records/common/reference_config/link.ld'; adapter=root/'records/common/user_link.ld'
    (root/'deltas/user_link.ld.diff').write_text(''.join(difflib.unified_diff(original.read_text().splitlines(True),adapter.read_text().splitlines(True),fromfile=str(original.relative_to(root)),tofile=str(adapter.relative_to(root)))))
    deltas.append(dict(original=str(original.relative_to(root)), adapter=str(adapter.relative_to(root)), diff='deltas/user_link.ld.diff'))
    save('ADAPTER_DELTAS.json', deltas)
    save('LICENSE_AUDIT.json', dict(files=legal, authority='licenses/ACT-README.md Licensing at pinned ACT revision',
         clear_license_source='https://spdx.org/licenses/BSD-3-Clause-Clear.html',
         notes='Original bytes/notices retained. Unmarked ACT code retains both upstream code licenses; unmarked configuration/testplan data retains CC-BY-4.0 as well. IBM vectors and unrelated sources excluded. No entire-package relicensing.'))
    save('DEPENDENCIES.json', dict(inspection_missing=[], exact_excluded_identities='EXCLUDED_IDENTITIES.json',
         outside_prior_receipts=outside,
         deliberately_excluded=['All guest ELFs, capture ELFs, objects and toolchain/runtime executables/libraries',
          'Task49 416 receipts, other candidates/suites, unrelated or restricted generator vectors',
          'Full generation-only Python package/templates/testplans (identities retained in REGISTERED)',
          'LEDGER_BEFORE full historical ledger; current selected original rows are included',
          'Author-local finalize.py has no license marker and is unnecessary for offline source/signature/raw inspection'],
         live_replay_missing=['clang22/lld/sysroot', 'pinned Sail executable', 'pinned QEMU executable',
          'clean961 elfrun/libdbtjitshared.so', 'guest capture and user ELFs',
          'generation-only Python dependencies and unselected generator corpus'],
         original_predicate_limit='Host verification reprocesses frozen Sail captures and evaluates original raw-summary predicates. Original RVV signature.h assertions execute only in the archived guest campaign; no host reconstruction of architectural results or new expected values.'))
    readme = a.tools/'ACT_INSPECTION_README.md'
    add(readme, 'README.md')
    # Repository documentation links become package-relative offline tool links.
    (root/'README.md').write_text((root/'README.md').read_text().replace('../../../scripts/', 'tools/').replace(
        ', and\n[focused tests](tools/test_rvv_act_inspection.py)', ''))
    (root/'NOTICE.md').write_text('ACT revision '+PIN+'. Copyrights and SPDX notices remain in each original source. '
        'Code: Apache-2.0 and BSD-3-Clause as marked or upstream README Licensing; documentation/configuration/testplans: CC-BY-4.0 retained. '
        'Generated UDB rvtest_config.h/svh: BSD-3-Clause-Clear; its full text and source are retained. '
        'Originals and historical adapters are separate, with readable deltas. No original header or raw receipt is modified. '
        'Delivery Python tools carry Apache-2.0. Read LICENSE_AUDIT.json and licenses/.\n')
    files = {str(p.relative_to(root)):dict(bytes=p.stat().st_size,sha256=digest(p))
             for p in sorted(root.rglob('*')) if p.is_file()}
    save('FILES.json', files)
    archive = root.parent/'act-primary-task99.tar.gz'
    with tarfile.open(archive, 'w:gz', compresslevel=6) as tar:
        for p in sorted(root.rglob('*')):
            if p.is_file(): tar.add(p, arcname=str(p.relative_to(root)), recursive=False)
    result = dict(file=archive.name, sha256=digest(archive), bytes=archive.stat().st_size,
                  payload_files=len(files)+1, payload_bytes=sum(x['bytes'] for x in files.values())+(root/'FILES.json').stat().st_size,
                  included_cases=1919, primary_cases=1878, new_DUT_calls=0, archived_DUT_calls=7504,
                  archived_primary_reference_calls=3756, reference_diagnostic_repeats=2,
                  ledger_rows=15364, bindings=7512, publication='STAGED_ON_XBD; Release upload pending authorization/authentication; no public payload URL')
    (root.parent/'ARCHIVE.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
