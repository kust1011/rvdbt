#!/usr/bin/env python3
"""Rebuild the bundled external CHIPS fixture and replay four RVV configurations."""
import argparse
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys

from rvv_tests import digest, save


def run(args):
    scripts = Path(__file__).resolve().parent
    fixture = scripts / 'rvv/fixtures/chips-vsmul-vv'
    registration = json.loads((fixture / 'fixture.json').read_text())
    if not args.build_only and (args.engine is None or args.library_dir is None):
        raise ValueError('--engine and --library-dir are required unless --build-only is set')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = output / 'test.S'
    with gzip.open(fixture / 'test.S.gz', 'rb') as inp, source.open('wb') as dest:
        shutil.copyfileobj(inp, dest)
    if digest(source) != registration['source_sha256']:
        raise ValueError('bundled source does not match fixture registration')
    command = [sys.executable, str(scripts / 'build_rvv_chips.py'),
               '--upstream', str(args.upstream.resolve()), '--source', str(source),
               '--source-sha256', registration['source_sha256'],
               '--expected-elf-sha256', registration['elf_sha256'],
               '--compiler', args.compiler, '--output', str(output / 'build')]
    save(output / 'build-command.json', command)
    result = subprocess.run(command, check=False)
    if result.returncode:
        return result.returncode
    inputs = output / 'inputs'
    inputs.mkdir()
    shutil.copyfile(output / 'build/test.elf', inputs / (registration['elf_sha256'] + '.elf'))
    if args.build_only:
        save(output / 'fixture.json', registration)
        print('BUILD_ONLY: fixture rebuilt; no DUT executed')
        return 0
    engine = args.engine.resolve(strict=True)
    library_dir = args.library_dir.resolve(strict=True)
    library = (library_dir / 'libdbtjitshared.so').resolve(strict=True)
    manifest = {'schema': 1, 'timeout_seconds': 120,
                'candidate': {'identity_kind': 'new replay; executable bytes observed before launch',
                              'build': {'stage/elfrun': digest(engine),
                                        'stage/libdbtjitshared.so': digest(library)}},
                'fixture': registration, 'cells': registration['cells']}
    save(output / 'manifest.json', manifest)
    command = [sys.executable, str(scripts / 'rvv_tests.py'), '--manifest', str(output / 'manifest.json'),
               '--inputs', str(inputs), '--engine', str(engine), '--library-dir', str(library_dir),
               '--output', str(output / 'results'), '--jobs', str(args.jobs)]
    save(output / 'run-command.json', command)
    return subprocess.run(command, check=False).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--engine', type=Path)
    parser.add_argument('--library-dir', type=Path)
    parser.add_argument('--build-only', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', default='clang-20')
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    try:
        return run(args)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print('RVV smoke error: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
