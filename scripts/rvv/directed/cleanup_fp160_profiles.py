#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Remove only closed, successful FP full per-run profile caches, with receipts."""
import argparse
import hashlib
import json
from pathlib import Path


def run(base, output):
    assert (base / 'COMPLETE').is_file(), 'launcher must be closed'
    root = base / 'corpus'
    assert (root / 'results.json').is_file()
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal():
            continue
        try:
            command = (process / 'cmdline').read_bytes().split(b'\0')
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if command and Path(command[0].decode(errors='replace')).name in ('elfrun', 'spike', 'sail_riscv_sim'):
            assert not any(str(root).encode() in arg for arg in command), 'FP guest still live'
    records = []
    units = dict.fromkeys(c['unit'] for c in json.loads((root / 'manifest.json').read_text())['cases'])
    for unit in units:
        for arm in ('B', 'M1', 'M2', 'BOTH'):
            d = root / 'runs' / unit / arm
            receipt = json.loads((d / 'execution.json').read_text())
            checks = json.loads((d / 'checks.json').read_text())
            if receipt['returncode'] or receipt['timeout'] or any(c['status'] != 'PASS' for c in checks):
                continue
            cache = root / 'work' / unit / arm / 'cache'
            assert not cache.is_symlink()
            for profile in sorted(cache.glob('*.prof.gz')):
                metadata = profile.with_suffix('.storage.json')
                assert profile.is_file() and not profile.is_symlink()
                assert metadata.is_file() and not metadata.is_symlink()
                meta = json.loads(metadata.read_text())
                assert meta['logical_path'].endswith('.prof') and meta['stored_file'] == profile.name
                record = dict(unit=unit, arm=arm, path=str(profile.relative_to(root)),
                              stored_bytes=profile.stat().st_size, metadata_bytes=metadata.stat().st_size,
                              stored_sha256=hashlib.sha256(profile.read_bytes()).hexdigest(),
                              logical_sha256=meta['logical_sha256'], reason='closed run; execution0/no-timeout/all checks PASS')
                assert record['stored_sha256'] == meta['compressed_sha256']
                records.append(record)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'records.json').write_text(json.dumps(records, indent=2) + '\n')
    for record in records:
        profile = root / record['path']
        assert hashlib.sha256(profile.read_bytes()).hexdigest() == record['stored_sha256']
        profile.unlink()
        profile.with_suffix('.storage.json').unlink()
    summary = dict(deleted_profiles=len(records), freed_bytes=sum(r['stored_bytes'] + r['metadata_bytes'] for r in records),
                   scope='only .prof.gz and matching .prof.storage.json in closed successful per-run cache; failure caches preserved')
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('base', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    run(a.base, a.output)
