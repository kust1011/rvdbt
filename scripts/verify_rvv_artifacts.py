#!/usr/bin/env python3
"""Verify separately obtained archives against the repository's immutable registry."""
import argparse
import json
from pathlib import Path
from rvv_tests import digest


def verify(manifest, root):
    records = manifest['artifacts']
    names = [r['file'] for r in records]
    if len(set(names)) != len(names) or any(Path(n).name != n for n in names):
        raise ValueError('duplicate or non-basename archive name')
    result = []
    for record in records:
        matches = list(root.rglob(record['file']))
        if len(matches) != 1:
            raise ValueError(f"expected exactly one archive {record['file']}, found {len(matches)}")
        path = matches[0]
        if path.stat().st_size != record['bytes'] or digest(path) != record['sha256']:
            raise ValueError('archive identity mismatch: ' + record['file'])
        result.append(record['file'])
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', type=Path, default=Path(__file__).resolve().parent.parent / 'docs/rvv-validation-artifacts.json')
    p.add_argument('--archive-root', type=Path, required=True)
    a = p.parse_args()
    try:
        records = verify(json.loads(a.manifest.read_text()), a.archive_root)
    except (OSError, ValueError) as e:
        p.exit(1, str(e) + '\n')
    print(f'Verified {len(records)} archive identities; no ISA executions')


if __name__ == '__main__':
    main()
