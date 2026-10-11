#!/usr/bin/env python3
"""Stream a finite retained CHIPS source/provenance selection; never copy ELFs."""
import argparse
import gzip
import json
from pathlib import Path
import subprocess
import sys
import tarfile


def selected(evidence, upstream):
    chips = evidence / 'chips_validation_20261007'
    registration = evidence / 'rvv_final_regression_20261007'
    manifest = json.loads((registration / 'MANIFEST.json').read_text())
    files = {}
    def add(p, name):
        if p.is_file() and not p.is_symlink():
            files[name] = p
    for batch in manifest['source_batches']:
        base = chips / batch
        # Root metadata and finite batch subtrees, never recurse root into all suites.
        for p in base.iterdir():
            if p.suffix in {'.py', '.json', '.md', '.S', '.txt'} or p.name == 'Makefrag':
                add(p, 'sources/chips/' + str(p.relative_to(chips)))
        for folder in ('stage1', 'stage2', 'patches', 'logs', 'user_env'):
            for p in (base / folder).glob('*'):
                if p.suffix in {'.S', '.patch', '.stdout', '.stderr', '.h'}:
                    add(p, 'sources/chips/' + str(p.relative_to(chips)))
    # Original failures and original reference stdout/metadata (no machine files).
    for batch in manifest['source_batches']:
        for folder in ('rvdbt', 'qemu'):
            for p in (chips / batch / folder).glob('*/*'):
                if p.name in {'stdout','stderr','command.json','meta.json','result.json'}:
                    add(p, 'sources/chips/' + str(p.relative_to(chips)))
    for p in registration.glob('*'):
        if p.suffix in {'.py','.md','.json','.csv','.jsonl'}:
            add(p, 'records/historical/' + p.name)
    for p in (registration / 'sources').glob('*'):
        add(p, 'records/historical/sources/' + p.name)
    # Upstream generator/adaptation source, omit fetched dependencies and build outputs.
    tracked = subprocess.check_output(['git','-C',str(upstream),'ls-files'], text=True).splitlines()
    for rel in tracked:
        if rel.startswith(('testfloat3/','build/','env/riscv-test-env/')): continue
        add(upstream / rel, 'upstream/chips/' + rel)
    env = upstream / 'env/riscv-test-env'
    for rel in ['LICENSE','p/riscv_test.h','encoding.h']:
        add(env / rel, 'upstream/chips/env/riscv-test-env/' + rel)
    return files


def extras(evidence):
    chips=evidence/'chips_validation_20261007'
    files={}
    manifest=json.loads((evidence/'rvv_final_regression_20261007/MANIFEST.json').read_text())
    for batch in manifest['source_batches']:
        base=chips/batch
        for p in base.glob('*'):
            if p.is_file() and p.suffix in {'.diff','.csv','.stdout','.stderr'}:
                files['sources/chips/'+str(p.relative_to(chips))]=p
        for folder in ('original','original-stage1','rd_control'):
            for p in (base/folder).rglob('*'):
                if p.is_file() and p.suffix in {'.S','.patch','.json','.stdout','.stderr'}:
                    files['sources/chips/'+str(p.relative_to(chips))]=p
    for p in (chips/'elen64_generator').glob('*'):
        if p.is_file() and p.suffix in {'.patch','.md','.json'}:
            files['sources/chips/'+str(p.relative_to(chips))]=p
    for name in ['CHIPS_INSTRUCTION_BATCH_COVERAGE.csv','CHIPS_ORACLE_AUDIT.json']:
        files['records/scope/'+name]=evidence/'external_suite_coverage_20261007'/name
    return files


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--evidence',type=Path,required=True)
    ap.add_argument('--upstream',type=Path,required=True)
    ap.add_argument('--stream',action='store_true')
    ap.add_argument('--extra-only',action='store_true')
    ap.add_argument('--skip-inventory',type=Path)
    a=ap.parse_args(); files=extras(a.evidence) if a.extra_only else selected(a.evidence,a.upstream)
    if a.skip_inventory:
        checkpoint=json.loads(a.skip_inventory.read_text())
        files={n:p for n,p in files.items() if checkpoint.get(n)!=p.stat().st_size}
    summary={'files':len(files),'bytes':sum(p.stat().st_size for p in files.values()),
             'largest':sorted([(p.stat().st_size,n) for n,p in files.items()],reverse=True)[:10]}
    if not a.stream: print(json.dumps(summary,indent=2));return
    print(json.dumps(summary),file=sys.stderr)
    with gzip.GzipFile(fileobj=sys.stdout.buffer, mode='wb', compresslevel=1) as gz, tarfile.open(fileobj=gz, mode='w|') as tf:
        for name,p in sorted(files.items()): tf.add(p,arcname=name,recursive=False)

if __name__=='__main__': main()
