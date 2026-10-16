#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fetch a pinned RVV corpus release without executing bundled code."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def validate_manifest(manifest):
    if manifest.get('schema') != 'rvv-corpus-release-1':
        raise ValueError('unsupported release manifest')
    for field in ('max_files', 'max_members', 'max_unpacked_bytes'):
        if type(manifest.get(field)) is not int or manifest[field] <= 0:
            raise ValueError('invalid extraction limit: ' + field)
    parts = manifest.get('archives')
    if not isinstance(parts, list) or not parts:
        raise ValueError('no archives in manifest')
    names = set()
    for part in parts:
        name = part.get('name', '')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name) or name in names:
            raise ValueError('invalid or duplicate archive name')
        names.add(name)
        if part.get('format') not in ('tar.gz', 'tar.zst'):
            raise ValueError('unsupported archive format')
        if not re.fullmatch(r'[0-9a-f]{64}', part.get('sha256', '')):
            raise ValueError('invalid archive digest')
        if type(part.get('bytes')) is not int or part['bytes'] <= 0:
            raise ValueError('invalid archive size')
        url = urllib.parse.urlsplit(part.get('url', ''))
        if url.scheme != 'https' or not url.netloc or url.username or url.password:
            raise ValueError('archive download requires HTTPS without credentials')


def fetch(part, cache):
    target = cache / part['name']
    if target.is_symlink():
        raise ValueError('cache file is a symlink: ' + str(target))
    if target.exists():
        if target.stat().st_size == part['bytes'] and digest(target) == part['sha256']:
            return target
        raise ValueError('cached archive does not match release: ' + str(target))
    fd, temporary = tempfile.mkstemp(prefix=part['name'] + '.', dir=cache)
    try:
        total = 0
        h = hashlib.sha256()
        with os.fdopen(fd, 'wb') as out, urllib.request.urlopen(part['url'], timeout=120) as response:
            if urllib.parse.urlsplit(response.geturl()).scheme != 'https':
                raise ValueError('download redirected outside HTTPS')
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > part['bytes']:
                    raise ValueError('download exceeds declared size')
                h.update(block)
                out.write(block)
        if total != part['bytes'] or h.hexdigest() != part['sha256']:
            raise ValueError('download size or digest mismatch')
        os.replace(temporary, target)
        return target
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def unpack_stream(archive, staging, limits):
    # Extract regular files/directories only; never follow archive links.
    for member in archive:
        limits['members'] -= 1
        if limits['members'] < 0:
            raise ValueError('archive exceeds member limit')
        path = PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or '\\' in member.name:
            raise ValueError('unsafe archive path: ' + member.name)
        if not path.parts:
            if member.isdir():
                continue
            raise ValueError('empty archive file path')
        target = staging.joinpath(*path.parts)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not member.isfile() or member.size < 0:
            raise ValueError('archive contains a link or special file: ' + member.name)
        limits['files'] -= 1
        limits['bytes'] -= member.size
        if limits['files'] < 0 or limits['bytes'] < 0:
            raise ValueError('archive exceeds extraction limits')
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.extractfile(member) as src, target.open('xb') as out:
            shutil.copyfileobj(src, out, 1024 * 1024)
        os.chmod(target, member.mode & 0o777)


def unpack(part, path, staging, limits):
    if part['format'] == 'tar.gz':
        with gzip.open(path, 'rb') as stream:
            with tarfile.open(fileobj=stream, mode='r|') as archive:
                unpack_stream(archive, staging, limits)
            while stream.read(1024 * 1024):
                pass
        return
    process = subprocess.Popen(['zstd', '-q', '-d', '-c', str(path)], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
            unpack_stream(archive, staging, limits)
        # Drain the decompressor so a trailing frame error is not hidden.
        while process.stdout.read(1024 * 1024):
            pass
        if process.wait() != 0:
            raise ValueError('zstd decompression failed')
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
            process.wait()


def install(manifest, output, cache):
    validate_manifest(manifest)
    output, cache = Path(output).absolute(), Path(cache).absolute()
    if os.path.lexists(output):
        raise ValueError('output must not exist: ' + str(output))
    if cache.resolve().is_relative_to(output.resolve()) or output.resolve().is_relative_to(cache.resolve()):
        raise ValueError('cache and output must be separate directories')
    output.parent.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    archives = [(part, fetch(part, cache)) for part in manifest['archives']]
    staging = Path(tempfile.mkdtemp(prefix=output.name + '.partial-', dir=output.parent))
    limits = dict(files=manifest['max_files'], members=manifest['max_members'],
                  bytes=manifest['max_unpacked_bytes'])
    try:
        for part, path in archives:
            unpack(part, path, staging, limits)
        if os.path.lexists(output):
            raise ValueError('output appeared during extraction')
        staging.rename(output)
    except BaseException:
        shutil.rmtree(staging)
        raise
    return dict(files=manifest['max_files'] - limits['files'],
                bytes=manifest['max_unpacked_bytes'] - limits['bytes'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'docs/rvv-validation/corpus-release.json',
                        help='release manifest from the reviewed repository revision')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--cache-dir', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = install(json.loads(args.manifest.read_text()), args.output, args.cache_dir)
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as exc:
        parser.exit(1, 'Corpus acquisition failed: ' + str(exc) + '\n')
    print(json.dumps(dict(status='ACQUIRED', output=str(args.output), **result)))
    print('Files acquired; no DUT execution or correctness validation was performed.')


if __name__ == '__main__':
    main()
