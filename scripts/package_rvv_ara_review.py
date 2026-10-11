"""Stream a Task91 Ara review bundle to stdout; assemble/extract on xbd."""
import argparse
import collections
import difflib
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile


def sha(data): return hashlib.sha256(data).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--delivery',type=Path,required=True)
    ap.add_argument('--coverage',type=Path,required=True)
    ap.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[1])
    a=ap.parse_args(); records=a.delivery; source=a.coverage/'ara/raw/source'
    data=json.loads((a.repo/'docs/rvv-validation/current-scope/compact-input.json').read_text()); e=data['ara_evidence']
    selected={}; generated={}; map_paths={}; legal=[]
    def add(file,name=None):
        file=Path(file)
        if not file.is_file(): raise ValueError('missing required package source: '+str(file))
        name=name or 'records/'+str(file.relative_to(records))
        if name in selected and selected[name]!=file:raise ValueError('package collision: '+name)
        selected[name]=file;map_paths[str(file)]=name;return name
    omitted={'FORM_DETAILS.json','INPUT_FORM_DETAILS.json','INPUT_CASES.json','SESSION_BEFORE.json','PRIOR_ARTIFACTS_BEFORE.json','TASK83_BEFORE.json','remote-build-and-raw.tgz'}
    for task in ['ara82','ara83','ara84','ara85','ara86','ara89']:
        r=records/task
        for f in r.iterdir():
            if f.is_file() and f.name not in omitted:add(f)
        for folder in ('adapter','upstream','raw','remote-raw','history','provenance','reproduction','remote-infrastructure','logs','baseline'):
            for f in (r/folder).rglob('*'):
                if f.is_file() and '__pycache__' not in f.parts and '.git' not in f.parts and not f.is_relative_to(r/'history/ara') and f.suffix not in ('.elf','.o','.a','.so','.ll','.bc','.tgz','.gz','.pyc'):
                    add(f)
    # Only the four reviewed MAC programs from the older campaign.
    prior=records/'ara-remainder52'
    for f in ('checker.py','run.original.py.txt','GROUPS.json','BUILD_COMMANDS.json','CONFIGS.json','PRESERVATION.json','COMPILER_RUNTIME_IDENTITY.json','REFERENCE_IDENTITY.json'):
        add(prior/f)
    for f in (prior/'adapter').iterdir():
        if f.suffix=='.h' or f.name in [n+'.c' for n in ('batch_vmacc','batch_vmadd','batch_vnmsac','batch_vnmsub')]:add(f)
    for name in ('batch_vmacc','batch_vmadd','batch_vnmsac','batch_vnmsub'):
        for arm in ('B','M1','M2','BOTH'):
            for f in (prior/'remote-raw'/name/arm).iterdir():
                if f.is_file():add(f)
    joins=[]
    for b in e['bindings']:
        scope=b['scope']; task=b.get('task','ara82_scoped_mac'); parser_task='ara-remainder52' if 'original_binding' in b else task
        case=b.get('case',b.get('original_binding',{}).get('source_case')); arm=b.get('arm',b.get('original_binding',{}).get('arm'))
        if 'original_binding' in b:
            base=Path(a.coverage.parent.parent/b['original_binding']['raw_stdout']).parent
            src=Path(a.coverage.parent.parent/b['original_binding']['source_file'])
            adapter=prior/'adapter'/(case+'.c')
        else:
            base=Path(b['raw_root']);adapter=records/task/'adapter'/(case+'.c')
            s=b['source'];relative=s.get('source_file')
            if relative:
                src=Path(relative)
                if not src.is_absolute():src=a.coverage.parent.parent/src
            else:
                filename=s.get('file') or s.get('group',{}).get('file')
                src=source/'apps/riscv-tests/isa/rv64uv'/(filename if filename.endswith('.c') else filename+'.c')
        if not src.is_file():raise ValueError('source join missing: '+str(src))
        source_name=add(src,'sources/'+str(src.relative_to(source))) if src.is_relative_to(source) else add(src)
        for f in ('stdout','stderr','result.json'):add(base/f)
        adapter_name=add(adapter) if adapter.exists() else None
        j=dict(identity=b['identity'],form=b['form'],task=task,case=case,arm=arm,scope=scope,positive=b['positive'],parser_task=parser_task,source=source_name,
               adapter=adapter_name,raw='records/'+str(base.relative_to(records)),checker='records/'+parser_task+'/checker.py',config='records/'+parser_task+'/CONFIGS.json',build='records/'+parser_task+'/BUILD_COMMANDS.json')
        s=b.get('source',{})
        if s.get('source_lines') and s.get('block_sha256'):
            j.update(source_range=s['source_lines'],block_sha256=s['block_sha256'])
        if s.get('source_sha256'):j['source_sha256']=s['source_sha256']
        if task=='ara89':j.update(M2_fast_admission=None,M2_target_admission_status='UNOBSERVED')
        joins.append(j)
    history=[]
    for h in e['ara89']['failed_history']:
        base=Path(h['root'])
        for f in base.iterdir():
            if f.is_file():add(f)
        history.append(dict(case=h['result']['case'],raw='records/'+str(base.relative_to(records)),positive=False,classification=h['classification'],compiled_historical_source=h['compiled_historical_source']))
    # Complete original header dependency context, including BSD and printf notices.
    for f in (source/'apps/riscv-tests/isa/macros/vector').glob('*'):
        if f.is_file():add(f,'sources/'+str(f.relative_to(source)))
    for name in ('encoding.h','printf.c','printf.h'):
        add(source/'apps/common'/name,'sources/apps/common/'+name)
    add(a.repo/'scripts/rvv/fixtures/ara-vredsum/LICENSE','licenses/Ara-SHL-0.51.txt')
    add(source/'apps/riscv-tests/LICENSE','licenses/riscv-tests-BSD.txt')
    add(source/'apps/riscv-tests/env/LICENSE','licenses/riscv-tests-env-BSD.txt')
    add(a.repo/'LICENSE','licenses/rvdbt-MIT.txt')
    for name in ('rvv_ara_accepted.py','test_rvv_ara_accepted.py','verify_rvv_ara_bundle.py','test_rvv_ara_bundle.py','package_rvv_ara_review.py'):
        add(a.repo/'scripts'/name,'tools/'+name)
    for name in ('TASK90_CHECK.json','TASK90_SOURCE_CHECK.json','TASK90_MANIFEST.json'):
        add(a.repo/'docs/rvv-validation/current-scope'/name,'task90/'+name)
    add(a.repo/'docs/rvv-validation/ara-review-task91/TASK90_CORRECTION.json','TASK90_CORRECTION.json')
    # Legal notices lost by historical block extraction are restored only in distributed copies.
    adapter_sources={j['adapter']:selected[j['source']] for j in joins if j['adapter']}
    for name,f in list(selected.items()):
        if '/adapter/' not in name or f.suffix not in ('.c','.h'):continue
        original=f.read_bytes(); text=original.decode()
        src=adapter_sources.get(name)
        prefix=''
        if 'Copyright' not in text[:2000] and src:
            lines=src.read_text().splitlines(keepends=True);header=[]
            for line in lines:
                if line.startswith('//') or not line.strip():header.append(line)
                else:break
            prefix=''.join(header)
        if not prefix and 'Copyright' not in text[:2000]:
            prefix='// Local observer/environment adaptation; repository MIT terms in licenses/rvdbt-MIT.txt.\n'
        if prefix:
            prefix+='// Task91 distribution: legal notice restored; compiled historical payload below is unchanged.\n'
            generated[name]=prefix.encode()+original
            legal.append(dict(file=name,original_sha256=sha(original),notice_prefix_bytes=len(prefix.encode()),distributed_sha256=sha(generated[name]),source_notice=map_paths.get(str(src)) if src else 'licenses/rvdbt-MIT.txt'))
    # Deltas are readable and do not replace the exact retained context records.
    for j in joins:
        name=j['adapter']
        if not name or 'deltas/'+name+'.diff' in generated:continue
        src=selected[j['source']].read_text().splitlines(keepends=True); adapted=selected[name].read_text().splitlines(keepends=True)
        generated['deltas/'+name+'.diff']=''.join(difflib.unified_diff(src,adapted,fromfile=j['source'],tofile=name+' (historical compiled payload)')).encode()
    def emit(name,value):generated[name]=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    emit('ARA_EVIDENCE.json',e);emit('BINDINGS.json',joins);emit('FAILED_HISTORY.json',history);emit('LEGAL_RESTORATIONS.json',legal)
    forms=collections.defaultdict(list)
    for index,j in enumerate(joins):forms[j['form']].append(index)
    emit('FORMS.json',dict(sorted(forms.items())))
    emit('PATHS.json',map_paths)
    generated['NOTICE.md']=b'''Ara original revision 34bd3bc152421b4601a7bf3d6e8e91ffb545c99e, ETH Zurich / University of Bologna, SHL-0.51. Original author/copyright headers retained in sources and upstream. Distributed adapters restore missing notices without changing the compiled historical payload; LEGAL_RESTORATIONS.json records exact prefix lengths and original hashes. Deltas describe the historical extraction/environment changes. Copyrights and licenses remain with their respective owners.\n\nAra files: licenses/Ara-SHL-0.51.txt. Regents encoding.h and riscv-tests helper dependencies: BSD notices in sources/apps/common/encoding.h and licenses/riscv-tests*-BSD.txt. Marco Paland 2014-2018 PALANDesign printf.c/h: complete MIT notice in both sources/apps/common/printf.*. Local checker/packaging and observer additions: repository MIT in licenses/rvdbt-MIT.txt. These notices apply independently; the package is not wholly relicensed as MIT. No toolchain or runtime binary is distributed.\n'''
    generated['README.md']=b'''# Accepted Ara review bundle (Task91)\n\nPortable inspection of accepted Ara82-86/89 additions and retained failures; zero new guests, surveys or goldens. A form, source block, binding, program and call are different units.\n\n1. Extract ara-review-task91.tar.gz into a fresh directory.\n2. Run `python3 tools/verify_rvv_ara_bundle.py .` (Python 3.9+, standard library, offline). The checker verifies all payload hashes, then calls the original parsers on raw stdout plus recorded exit codes, with exact Ara89 configurations/initialization and scoped MAC failure assertions. Archive integrity alone is not acceptance.\n3. Find a canonical form in FORMS.json. Its indices select BINDINGS.json records, each with package-relative source, adapter, raw, checker, config and build paths. Consult deltas/ and records/ara*/MAIN_REVIEW.json, original failures and context audits. PATHS.json translates historical locators; absolute paths in original records are provenance.\n4. Read TASK90_CORRECTION.json before interpreting FAST counters. M2 target admission is UNOBSERVED/null; RVV_ACTIVE_CHUNKS was never enabled in this batch. Functional B/M1/M2/BOTH predicates remain PASS.\n\nThis is portable inspection, not turnkey reexecution. Use the repo docs/rvv-validation/portable-external.md and scripts/rvv runner for live replay. Historical build/config/launch commands and binary identities are included, but compilers, LLVM, sysroots, newlib, Spike/pk, DUT executables/libraries, guest ELFs/objects, caches, huge TB dumps, ATG/RVISmith and unrelated suites are excluded. Assembly/disassembly text is retained; compiler IR/binaries are excluded. Original history records can name excluded files; BINDINGS.json is the navigation authority for included accepted evidence.\n\nLicenses: read NOTICE.md and licenses/. Legal-only header restoration is documented in LEGAL_RESTORATIONS.json; original raw receipts remain byte-identical. FILES.json covers all payload files except itself.\n'''
    file_manifest={}
    with tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz') as tar:
        for name in sorted(set(selected)|set(generated)):
            content=generated.get(name)
            if content is None:content=selected[name].read_bytes()
            file_manifest[name]=dict(bytes=len(content),sha256=sha(content))
            item=tarfile.TarInfo(name);item.size=len(content);item.mode=0o644;tar.addfile(item,io.BytesIO(content))
        content=(json.dumps(file_manifest,indent=2)+'\n').encode();item=tarfile.TarInfo('FILES.json');item.size=len(content);item.mode=0o644;tar.addfile(item,io.BytesIO(content))
    print(json.dumps(dict(files=len(file_manifest),bindings=len(joins),unique_receipts=len({j['raw'] for j in joins}),tasks=dict(collections.Counter(j['task'] for j in joins)),scopes=dict(collections.Counter(j['scope'] for j in joins)))),file=sys.stderr)

if __name__=='__main__':main()
