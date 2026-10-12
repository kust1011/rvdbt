# SPDX-License-Identifier: Apache-2.0
"""Package frozen Task109 db2 evidence, without compiling or executing guests."""
import argparse
import csv
import difflib
import hashlib
import json
from pathlib import Path
import shutil
import tarfile


def digest(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(1024*1024), b''):
            h.update(b)
    return h.hexdigest()


def save(p, value):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(value, indent=2)+'\n')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('campaign', 'output', 'tools', 'licenses', 'readme'):
        ap.add_argument('--'+name, type=Path, required=True)
    ap.add_argument('--refresh-tools', action='store_true', help='Refresh only delivery tools/README and reseal an existing Task110 package')
    a = ap.parse_args()
    if not __debug__:
        raise RuntimeError('remove optimized Python')
    if a.refresh_tools:
        for n in ('package_rvv_act_db2.py','verify_rvv_act_db2.py','replay_rvv_act_db2.py','test_rvv_act_db2.py','verify_rvv_act_inspection.py'):
            shutil.copyfile(a.tools/n, a.output/'tools'/n)
        (a.output/'README.md').write_text(a.readme.read_text().replace('scripts/', 'tools/').replace('../act-primary-task99/README.md', 'https://github.com/kust1011/rvdbt/blob/delivery/rvv-validation-20261012/docs/rvv-validation/act-primary-task99/README.md'))
        result_index(a.output)
        seal(a.output)
        return
    a.output.mkdir(parents=True, exist_ok=False)
    selected = {}; outside = []; paths = {}
    def add(p, name):
        if p.is_symlink() or not p.is_file():
            raise ValueError('missing/nonregular input: '+str(p))
        dst = a.output/name; dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, dst)
        selected[name] = dict(bytes=p.stat().st_size, sha256=digest(p))
        paths[str(p)] = name
    # Preserve all task-local old scripts, summary records and failures. Generated
    # sources are deduplicated by path mapping to each case's unchanged source.
    folders = ('common', 'producer', 'cases', 'source-differences',
               'reference-diagnostics', 'generation-logs', 'observer-controls',
               'prelaunch-Vls8-vluxei8.v', 'prelaunch-original-gates',
               'offline-corrected-gates')
    for p in sorted(a.campaign.iterdir()):
        if p.is_file() and p.suffix != '.pyc':
            add(p, 'records/'+p.name)
    for folder in folders:
        for p in sorted((a.campaign/folder).rglob('*')):
            if not p.is_file() or '__pycache__' in p.parts:
                continue
            rel = p.relative_to(a.campaign)
            if folder == 'producer' and 'tests' in rel.parts:
                continue
            if p.suffix in ('.elf', '.o') or p.name in ('tbmap.txt', 'user.disasm'):
                outside.append(dict(original=str(p), relative=str(rel),
                                    bytes=p.stat().st_size, sha256=digest(p),
                                    reason='full raw ELF/TB/disassembly; indexed outside inspection package'))
            else:
                add(p, 'records/'+str(rel))
    queue = json.loads((a.campaign/'EXACT_QUEUE.json').read_text())
    cases = []; forms = {}; joins = []
    for q in queue:
        o = q['output']; n = o['case']; base = a.campaign/'cases'/n
        if o['disposition'] == 'TASK104_ACCEPTED':
            add(a.campaign/o['path'], 'records/'+o['path'])
            joins.append(q)
            continue
        r = json.loads((base/'RESULT.json').read_text())
        src = 'records/cases/'+n+'/'+n+'.S'
        if selected[src]['sha256'] != o['sha256'] or r['source_sha256'] != o['sha256']:
            raise ValueError('source identity mismatch: '+n)
        paths[str(a.campaign/o['path'])] = src
        paths[o['path']] = src
        idx = dict(case=n, form=r['form'], sew=r['sew'], status=r['status'],
                   input_id=r['input_id'], source=src, result='records/cases/'+n+'/RESULT.json',
                   checker='records/common/user_env/signature.h',
                   expected='records/cases/'+n+'/'+n+'.results',
                   capture='records/cases/'+n+'/'+n+'.sig',
                   oracle='records/cases/'+n+'/ORACLE.json',
                   raw='records/cases/'+n+'/raw',
                   target_audit='records/cases/'+n+'/TARGET_EXECUTION_AUDIT.json',
                   full_raw=str(base))
        forms.setdefault(r['form'], []).append(len(cases)); cases.append(idx)
    for p in sorted(a.licenses.iterdir()):
        if p.is_file(): add(p, 'licenses/'+p.name)
    for n in ('package_rvv_act_db2.py', 'verify_rvv_act_db2.py',
              'replay_rvv_act_db2.py', 'test_rvv_act_db2.py', 'verify_rvv_act_inspection.py'):
        add(a.tools/n, 'tools/'+n)
    add(a.readme, 'README.md')
    readme=a.output/'README.md'
    readme.write_text(readme.read_text().replace('scripts/', 'tools/').replace('../act-primary-task99/README.md', 'https://github.com/kust1011/rvdbt/blob/delivery/rvv-validation-20261012/docs/rvv-validation/act-primary-task99/README.md'))
    save(a.output/'ACCOUNTING.json', json.loads((a.campaign/'FINAL_COUNTS_109.json').read_text()))
    with (a.output/'RESULT_INDEX.csv').open('w', newline='') as f:
        fields=['case','form','sew','status','source','checker','expected','capture','result','raw','target_audit','full_raw']
        writer=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore'); writer.writeheader(); writer.writerows(cases)
    deltas = []
    for p in (a.campaign/'common/user_env').iterdir():
        old = a.campaign/'common/upstream/env'/p.name
        if old.is_file() and p.read_bytes() != old.read_bytes():
            name = 'deltas/'+p.name+'.diff'; dst=a.output/name; dst.parent.mkdir(exist_ok=True)
            dst.write_text(''.join(difflib.unified_diff(old.read_text().splitlines(True), p.read_text().splitlines(True), fromfile='original/'+p.name,tofile='adapter/'+p.name)))
            deltas.append(dict(original=paths[str(old)], adapter=paths[str(p)], diff=name))
    for name, obj in [('CASES.json', cases), ('FORMS.json', forms), ('TASK104_JOIN.json', joins),
                      ('PATHS.json', paths), ('FULL_RAW_INDEX.json', outside), ('ADAPTER_DELTAS.json', deltas)]:
        save(a.output/name, obj)
    save(a.output/'DEPENDENCIES.json', dict(inspection=['Python 3.9+ standard library'],
        replay=['clang-22 and lld', 'pinned Sail', 'pinned QEMU rv32 user',
                'clean961 elfrun/libdbtjitshared.so; identity pins in LAUNCH_REGISTRATION.json'],
        generation='Included original generator sources and pyproject.toml requirements; original generate109.py depends on c3e comparison receipts. Replay uses frozen generated sources, no regeneration.',
        full_raw_root=str(a.campaign), excluded='FULL_RAW_INDEX.json',
        prior='TASK104_JOIN.json: one prior acceptance, no Task109 execution'))
    save(a.output/'LICENSE_AUDIT.json', dict(pin='db2b9fd7aa71a6e669417f711379988541f1464c',
        authority='licenses/ACT-README.md Licensing; retained SPDX/author notices per file',
        code='Upstream Apache-2.0 / BSD-3-Clause as marked; delivery tools Apache-2.0',
        data='Upstream documentation/config/testplans CC-BY-4.0; generated UDB headers BSD-3-Clause-Clear',
        no_relicensing=True))
    result_index(a.output)
    seal(a.output)


def result_index(root):
    queue=json.loads((root/"records/EXACT_QUEUE.json").read_text())
    cases={c["case"]:c for c in json.loads((root/"CASES.json").read_text())}
    diffs={d["case"]:d for d in json.loads((root/"records/CONCRETE_DIFFERENCES.json").read_text())["rows"]}
    fields=["case","form","sew","status","disposition","source","source_sha256","checker","checker_sha256","capture_config","config_sha256","XLEN","ELEN","VLEN","MAXINDEXEEW","testplan","testplan_line","input_id","c3e_comparison","expected","capture","result","raw","target_audit","full_raw"]
    config="records/common/reference_config/sail.json"
    with (root/"RESULT_INDEX.csv").open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore");w.writeheader()
        for q in queue:
            o=q["output"];i=q["input"];n=o["case"];row=dict(cases.get(n,dict(case=n,form=i["form"],sew=i["sew"],status="TASK104_ACCEPTED",source="records/"+o["path"],checker="records/common/user_env/signature.h",full_raw="xbd:/home/vick/rvv-task104")))
            comparisons=diffs[n]["comparisons"]
            kind="BYTE_EQUAL" if any(c["byte_equal"] for c in comparisons) else "GUARD_OR_FORMAT_ONLY" if any(c["source_equal_after_comments_whitespace_and_equivalent_defined_guard"] for c in comparisons) else "NORMALIZED_DIFFERENCE"
            row.update(disposition=o["disposition"],source_sha256=o["sha256"],checker_sha256=o["checker_sha256"],capture_config=config,config_sha256=digest(root/config),testplan="records/producer/testplans/"+Path(i["testplan"]).name,testplan_line=i["testplan_line"],input_id=i["id"],c3e_comparison=kind,**o["geometry"])
            w.writerow(row)


def seal(root):
    files = {str(p.relative_to(root)):dict(bytes=p.stat().st_size,sha256=digest(p))
             for p in sorted(root.rglob('*')) if p.is_file() and p != root/'FILES.json'}
    save(root/'FILES.json', files)
    archive = root.parent/'act-db2-task110.tar.gz'
    with tarfile.open(archive, 'w:gz', compresslevel=6) as t:
        for p in sorted(root.rglob('*')):
            if p.is_file(): t.add(p, arcname=str(p.relative_to(root)), recursive=False)
    report = dict(path=str(archive), bytes=archive.stat().st_size,sha256=digest(archive),
        payload_files=len(files)+1,payload_bytes=sum(v['bytes'] for v in files.values())+(root/'FILES.json').stat().st_size,
        case_results=len(json.loads((root/'CASES.json').read_text())), prior_Task104=len(json.loads((root/'TASK104_JOIN.json').read_text())),full_raw_indexed_files=len(json.loads((root/'FULL_RAW_INDEX.json').read_text())),
        new_guest_calls=0,publication='STAGED_ON_XBD; no push/release')
    save(root.parent/'ARCHIVE.json', report); print(json.dumps(report,indent=2))

if __name__ == '__main__':
    main()
