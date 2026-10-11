"""Finalize the small Ara inspection archive on xbd, without running guests."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import shutil
import tarfile


def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('package',type=Path);p.add_argument('--historical-ara89',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();root=a.package
    histories=json.loads((root/'FAILED_HISTORY.json').read_text())
    for h in histories:
        src=a.historical_ara89/'adapter'/(h['case']+'.c')
        if digest(src)!=h['compiled_historical_source']['source_sha256']:raise ValueError('preliminary compiled source mismatch: '+str(src))
        name='records/ara89/history/compiled-sources/'+src.name;out=root/name;out.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,out);h['source']=name
    (root/'FAILED_HISTORY.json').write_text(json.dumps(histories,indent=2)+'\n')
    for name in ('build.stdout','build.stderr','build-corrected.stdout','build-corrected.stderr'):
        src=a.historical_ara89/name
        if src.is_file():shutil.copyfile(src,root/'records/ara89'/name)
    joins=json.loads((root/'BINDINGS.json').read_text());e=json.loads((root/'ARA_EVIDENCE.json').read_text())
    aliases=json.loads((root/'DUPLICATE_ALIASES.json').read_text()) if (root/'DUPLICATE_ALIASES.json').exists() else {}
    for duplicate in (root/'records/ara89/remote-raw').glob('*/reference'):
        original=root/'records/ara89/raw'/duplicate.parent.name/'reference'
        if original.is_dir() and all((duplicate/f).read_bytes()==(original/f).read_bytes() for f in ('stdout','stderr','result.json')):
            aliases[str(duplicate.relative_to(root))]=str(original.relative_to(root))
            shutil.rmtree(duplicate)
    shutil.rmtree(root/'records/ara83/history/ara',ignore_errors=True)
    paths=json.loads((root/'PATHS.json').read_text())
    paths={k:v for k,v in paths.items() if not v.startswith('records/ara83/history/ara/')}
    for key,name in list(paths.items()):
        for old,new in aliases.items():
            if name.startswith(old+'/'):paths[key]=new+name[len(old):]
    (root/'PATHS.json').write_text(json.dumps(paths,indent=2)+'\n')
    (root/'DUPLICATE_ALIASES.json').write_text(json.dumps(aliases,indent=2)+'\n')
    restorations={r['file']:r for r in json.loads((root/'LEGAL_RESTORATIONS.json').read_text())}
    for name,r in restorations.items():
        if hashlib.sha256((root/name).read_bytes()[r['notice_prefix_bytes']:]).hexdigest()!=r['original_sha256']:raise ValueError('legal restoration changes historical payload')
    # Verify actual included dependency notices, not just an archive-level license label.
    for name in ('sources/apps/common/printf.c','sources/apps/common/printf.h'):
        text=(root/name).read_text()
        if not all(s in text for s in ('Marco Paland','The MIT License','Permission is hereby granted','THE SOFTWARE IS PROVIDED')):raise ValueError('printf MIT notice incomplete')
    text=(root/'sources/apps/common/encoding.h').read_text()
    if not all(s in text for s in ('Regents','Redistribution and use','IN NO EVENT','REGENTS SPECIFICALLY DISCLAIMS')):raise ValueError('encoding BSD notice incomplete')
    if 'Solderpad Hardware License' not in (root/'licenses/Ara-SHL-0.51.txt').read_text():raise ValueError('Ara license missing')
    license_files=[]
    for f in sorted(root.rglob('*')):
        if not f.is_file() or f.suffix not in ('.c','.h'):continue
        text=f.read_text(errors='replace')[:5000];name=str(f.relative_to(root))
        license='MIT printf' if 'Marco Paland' in text else 'BSD Regents' if 'Regents' in text or f.name=='test_macros.h' else 'MIT local adaptation' if 'repository MIT terms' in text else 'SHL-0.51 Ara source/derivative'
        license_files.append(dict(file=name,license=license,sha256=digest(f),notice_restored=name in restorations))
    audit=dict(Ara_revision='34bd3bc152421b4601a7bf3d6e8e91ffb545c99e',SHL_0_51=True,printf_MIT_notice_verified=True,encoding_BSD_notice_verified=True,regents_helper_license_included=True,legal_restoration_payloads_unchanged=True,files=license_files)
    (root/'LICENSE_AUDIT.json').write_text(json.dumps(audit,indent=2)+'\n')
    cases=collections.defaultdict(lambda:dict(forms=set(),arms=set(),scopes=set(),raw=set(),positive_bindings=0,bindings=0))
    for b in joins:
        r=cases[b['task'],b['case']];r['forms'].add(b['form']);r['arms'].add(b['arm']);r['scopes'].add(b['scope']);r['raw'].add(b['raw']);r['bindings']+=1;r['positive_bindings']+=b['positive']
    case_records=[dict(task=t,case=c,**{k:sorted(v) if isinstance(v,set) else v for k,v in r.items()}) for (t,c),r in sorted(cases.items())]
    (root/'CASES.json').write_text(json.dumps(case_records,indent=2)+'\n')
    raw_records=collections.Counter()
    for f in root.glob('records/**/result.json'):
        if (f.parent/'stdout').exists() and (f.parent/'stderr').exists():
            result=json.loads(f.read_text());raw_records[(f.relative_to(root).parts[1],str(result.get('status','UNKNOWN')))]+=1
    summary=dict(task=91,bindings=len(joins),case_records=len(case_records),case_list='CASES.json',form_map='FORMS.json',binding_map='BINDINGS.json',unique_binding_receipts=len({b['raw'] for b in joins}),positive_bindings=sum(b['positive'] for b in joins),task_binding_counts=dict(collections.Counter(b['task'] for b in joins)),scope_binding_counts=dict(collections.Counter(b['scope'] for b in joins)),included_raw_receipt_counts=[dict(task=t,status=s,records=n) for (t,s),n in sorted(raw_records.items())],cumulative_added_forms=e['diff']['added'],Task90_exact26=e['ara89']['checkpoint_diff']['added'],retained_preliminary_cases=[h['case'] for h in histories],licenses=dict(collections.Counter(f['license'] for f in license_files)),legal_restorations=len(restorations),M2_target_admission_status='UNOBSERVED',M2_fast_admission=None,new_DUT_executions=0)
    (root/'SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n')
    manifest={}
    for f in sorted(root.rglob('*')):
        if f.is_file() and f.name!='FILES.json' and '__pycache__' not in f.parts:
            manifest[str(f.relative_to(root))]=dict(bytes=f.stat().st_size,sha256=digest(f))
    (root/'FILES.json').write_text(json.dumps(manifest,indent=2)+'\n')
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with tarfile.open(a.output,'w:gz',compresslevel=9) as tar:
        for name in sorted(manifest):tar.add(root/name,arcname=name,recursive=False)
        tar.add(root/'FILES.json',arcname='FILES.json',recursive=False)
    external=dict(archive=a.output.name,bytes=a.output.stat().st_size,sha256=digest(a.output),uncompressed_bytes=sum(r['bytes'] for r in manifest.values()),payload_files=len(manifest),manifest_sha256=digest(root/'FILES.json'),summary=summary)
    a.output.with_suffix('.manifest.json').write_text(json.dumps(external,indent=2)+'\n')
    print(json.dumps({k:v for k,v in external.items() if k!='summary'},indent=2))

if __name__=='__main__':main()
