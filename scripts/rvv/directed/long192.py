#!/usr/bin/env python3
"""Bounded long-group/block-boundary composition using the Task177 observer.

No new answer generator: Task177 scalar/exact-rational sequential semantics and
pinned Spike supply the two independent checks. Never run a historical matrix.
"""
import argparse
import json
import os
import hashlib
from pathlib import Path

import sequences177 as s
import vadd as v

PIN191 = '37a25624345214d97e3691cfd9f951166abfe92419ce2bbeca9c786b68227c14'


def cases():
    rows = []
    # Existing177: integer e16/e32/e64 m1 and e32 m2; FP e32/e64 m1/m2,
    # e32 mf2. New composition also exceeds the old five-member chain length.
    for w in (2048, 4096):
        for fp, sew, exp in ((False, 8, -3), (False, 16, 2),
                             (False, 8, 3), (True, 32, -1),
                             (True, 32, 2), (True, 64, 3)):
            template = next(c for c in s.cases('fp' if fp else 'integer')
                            if c['vlen'] == w and c['scenario'] == 'chain')
            n = int(w / sew * 2**exp)
            lm = 'mf'+str(2**-exp) if exp < 0 else 'm'+str(2**exp)
            unit = f'long192-{"fp" if fp else "int"}-w{w}-e{sew}-{lm}'
            # Distinct groups are aligned even for m8. Alternating overwrites
            # require the prior definition, including across the TB boundary.
            add, sub = ('vfadd', 'vfsub') if fp else ('vadd', 'vsub')
            ops = [(add, 8, 16, 24, False)]
            ops += [(sub if i % 2 else add, 8 if i % 3 else 16,
                     8, 24, False) for i in range(1, 65)]
            # Integer masked member cuts the run and must publish earlier SSA
            # definitions before reading the mask and then resuming a new run.
            if not fp:
                ops[32] = (add, 8, 8, 16, True)
            for vl in sorted({0, min(n, 512//sew+1), min(n, w//sew+1), n-1}):
                c = dict(template, id=f'{unit}-vl{vl}', unit=unit,
                         sew=sew, lmul=lm, lmul_exp=exp, vlmax=n, vl=vl,
                         vstart=0, group_registers=max(1, 2**exp),
                         ta=fp, ma=False, ops=ops, special=False,
                         tag=f'vl{vl}', scenario='long192')
                for _, d, a, b, masked in ops:
                    assert all(r % c['group_registers'] == 0 and
                               r+c['group_registers'] <= 32 for r in (d, a, b))
                    assert not masked or d != 0
                rows.append(c)
    # Adaptive path controls: large groups and fractional shapes were observed
    # as singleton frames. Eight-chunk geometries must also exercise the actual
    # M1/BOTH run bodies at the new 65-operation boundary, not just their flags.
    for w, exp in ((2048, 1), (4096, 0)):
        template = next(c for c in rows if c['fp'] and c['vlen'] == w and
                        c['sew'] == 32 and c['lmul_exp'] == 2)
        n = w//32 * 2**exp
        unit = f'long192-fp-w{w}-e32-m{2**exp}'
        for vl in (0, 17, w//32+1 if exp else n//2+1, n-1):
            rows.append(dict(template, id=f'{unit}-vl{vl}', unit=unit,
                             lmul=f'm{2**exp}', lmul_exp=exp, vlmax=n,
                             vl=vl, group_registers=2**exp, tag=f'vl{vl}'))
    for i, c in enumerate(rows):
        c['ordinal'] = i
    return rows


def install():
    s.install('integer')
    v.manifest_cases = lambda family: cases()
    v.PIN = PIN191


def resources(root):
    stat = os.statvfs(root)
    free = stat.f_bavail * stat.f_frsize
    assert free >= 10 * 1024**3
    assert os.getpriority(os.PRIO_PROCESS, 0) == 10
    return dict(free_bytes=free, nice=10,
                affinity='inherited; no affinity assignment')


def replay(original, root, engine, unit):
    """Retain the original failing ELF and independent answers verbatim."""
    root.mkdir(exist_ok=False)
    manifest = json.loads((original/'manifest.json').read_text())
    cs = [c for c in manifest['cases'] if c['unit'] == unit]
    assert cs
    v.save(root/'manifest.json', dict(manifest, cases=cs, units=1))
    (root/unit).symlink_to(original/unit, target_is_directory=True)
    builds = [r for r in json.loads((original/'build-commands.json').read_text())
              if Path(r['command'][-1]).parent.name == unit]
    assert len(builds) == 1 and v.sha(root/unit/'test.elf') == builds[0]['elf_sha256']
    v.save(root/'build-commands.json', builds)
    for name in ('user.ld', 'sail.ld'):
        (root/name).symlink_to(original/name)
    runs = root/'runs'/unit
    runs.mkdir(parents=True)
    (runs/'Reference').symlink_to(original/'runs'/unit/'Reference', target_is_directory=True)
    reference = v.storage.verify(runs/'Reference'/'packets.bin')
    size = v.packet_size(cs[0])
    pins = {str(p): v.sha(p) for p in (engine, engine.parent.parent/'lib/libdbtjitshared.so')}
    v.save(root/'identities-before.json', pins)
    results = []
    for arm in s.ARMS[1:]:
        resources(root)
        d = runs/arm
        fs = root/'work'/unit/arm/'fs'
        fs.mkdir(parents=True)
        cache = fs.parent/'cache'
        cache.mkdir()
        (fs/'t.elf').write_bytes(v.storage.verify(root/unit/'test.elf'))
        old = original/'runs'/unit/arm
        cmd = json.loads((old/'command.json').read_text())
        cmd[0] = str(engine)
        # The installed capture wrapper supplies these two diagnostic hooks.
        cmd = [x for x in cmd if not x.startswith(('--dump-tbcode=', '--rvv-pc-census=', '--rvv-pc-census-out='))]
        for i, x in enumerate(cmd):
            for flag, target in (('dump-tbmap', d/'tbmap'), ('fsroot', fs), ('cache', cache)):
                if x.startswith('--'+flag+'='):
                    cmd[i] = '--'+flag+'='+str(target)
        rec = v.execute(cmd, d, dict(os.environ, LD_LIBRARY_PATH=str(engine.parent.parent/'lib')))
        raw = v.storage.verify(d/'stdout')
        v.storage.write(d/'packets.bin', raw, alias=d/'stdout')
        checks = []
        for i, c in enumerate(cs):
            assert len(raw) == len(reference) == size*len(cs)
            packet = raw[i*size:(i+1)*size]
            s.check_isa(c, packet, rec['returncode'], rec['timeout'])
            s.check_reference(c, packet, reference[i*size:(i+1)*size])
            checks.append(dict(case=c['id'], arm=arm, status='PASS'))
        v.save(d/'checks.json', checks)
        v.storage.compress(d/'tbmap')
        results += checks
    assert pins == {p: v.sha(Path(p)) for p in pins}
    v.save(root/'identities-after.json', pins)
    v.save(root/'REUSE.json', dict(original=str(original), unit=unit,
                                 elf_sha256=builds[0]['elf_sha256'],
                                 reference_sha256=hashlib.sha256(reference).hexdigest(),
                                 reference_executions=0, guest_rebuilds=0))
    v.save(root/'results.json', results)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=('build', 'run', 'audit', 'replay'))
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--units', type=Path)
    p.add_argument('--engine', type=Path, default=Path('/home/vick/rvdbt-exception-task186/build/bin/elfrun'))
    p.add_argument('--pin', default=PIN191)
    p.add_argument('--original', type=Path)
    p.add_argument('--unit')
    a = p.parse_args()
    install()
    v.PIN = a.pin
    before = resources(a.root.parent)
    if a.mode == 'build':
        units = json.loads(a.units.read_text()) if a.units else None
        v.build(a.root, 'clang-22', Path('/home/vick/rvv-directed-task145/link.ld'),
                'long192', 2, units)
    elif a.mode == 'run':
        v.run(a.root, a.engine,
              Path('/home/vick/rvv-directed-task145/deps/spike'),
              Path('/home/vick/rvv-directed-task145/deps/pk'),
              Path('/home/vick/rvv-act4-tools/bin/sail_riscv_sim'),
              Path('/home/vick/rvv-directed-task177/FLAGS.json'), 2)
    elif a.mode == 'replay':
        assert v.sha(a.engine) == a.pin
        replay(a.original, a.root, a.engine, a.unit)
    else:
        import review_sequences177 as review
        review.audit([a.root], a.root/'audit')
    v.save(a.root/(a.mode+'-resources.json'),
           dict(before=before, after=resources(a.root)))


if __name__ == '__main__':
    main()
