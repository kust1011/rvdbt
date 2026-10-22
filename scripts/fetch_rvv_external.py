#!/usr/bin/env python3
"""Fetch pinned licensed dependencies into a new directory; verify retained inputs."""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.request

from rvv_tests import digest, save


SCRIPTS = Path(__file__).resolve().parent


def publish(staging, output):
    # Linux RENAME_NOREPLACE avoids the check/rename race that can replace an empty directory.
    rename = getattr(ctypes.CDLL(None, use_errno=True), 'renameat2', None)
    if rename is None:
        raise OSError(errno.ENOTSUP, 'atomic no-replace publication requires renameat2')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(staging), -100, os.fsencode(output), 1) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(output))


def acquire(output):
    output = Path(output).absolute()
    if os.path.lexists(output):
        raise FileExistsError('output must not exist: ' + str(output))
    lock = json.loads((SCRIPTS / 'rvv/sources.lock.json').read_text())['sources']
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=output.name + '.partial-', dir=output.parent))
    try:
        ar = lock['ara']
        out = staging / 'ara'
        out.mkdir()
        for name, relative in {**ar['paths'], 'LICENSE': 'LICENSE'}.items():
            url = 'https://raw.githubusercontent.com/pulp-platform/ara/' + ar['revision'] + '/' + relative
            with urllib.request.urlopen(url, timeout=60) as response:
                (out / name).write_bytes(response.read())
            bundled = SCRIPTS / 'rvv/fixtures/ara-vredsum' / ('vredsum.original.c' if name == 'vredsum.c' else name)
            # The bundled vector_macros.h is an adapter, not the upstream original.
            if name != 'vector_macros.h' and digest(out / name) != digest(bundled):
                raise ValueError('pinned Ara input differs: ' + name)
        rv = lock['rvvts']
        checkout = staging / 'rvvts'
        subprocess.run(['git', 'clone', rv['url'], str(checkout)], check=True)
        subprocess.run(['git', '-C', str(checkout), 'checkout', '--detach', rv['revision']], check=True)
        if digest(checkout / 'LICENSE') != digest(SCRIPTS / 'rvv/fixtures/rvvts-20261089/LICENSE'):
            raise ValueError('pinned RVVTS license differs')
        receipt = dict(ara=ar, rvvts=rv,
                       files={str(x.relative_to(staging)): digest(x) for x in out.iterdir()})
        save(staging / 'fetch.json', receipt)
        publish(staging, output)
        staging = None
        return receipt
    finally:
        if staging is not None:
            shutil.rmtree(staging)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        acquire(args.output)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(1, 'External acquisition failed: ' + str(exc) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
