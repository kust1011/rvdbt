#!/usr/bin/env python3
"""Check Task106 byte replay against original RV64 scalar execution, never a DUT."""
import argparse
import difflib
import hashlib
import json
import pathlib
import subprocess

PROOF_SHA = 'e627b9e5ea1b8e4478d361de70b2e7bbe892349131b9b5711dbde2fb139ffece'
SOURCE_SHA = 'e98938129b9c3b69e3bb1e1e3f6f9aef2c6ad081a41268cbc1bc42e17a69f791'

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'proof', 'qemu', 'output'):
        p.add_argument('--' + name, type=pathlib.Path, required=True)
    p.add_argument('--compiler', default='/usr/bin/clang-22')
    a = p.parse_args()
    if digest(a.source) != SOURCE_SHA:
        p.error('source differs from pinned QEMU f9587d4 test-zicclsm.S')
    if digest(a.proof) != PROOF_SHA:
        p.error('proof differs from accepted Task106 replay; no new expected values')
    proof = json.loads(a.proof.read_text())
    expected = bytes.fromhex(proof['final_bytes'])
    if len(expected) != 256:
        p.error('Task106 proof must contain exactly 256 bytes')
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    def save(name, value):
        (out / name).write_text(json.dumps(value, indent=2) + '\n')
    def call(name, cmd):
        d = out / name
        d.mkdir()
        (d / 'command.json').write_text(json.dumps(list(map(str, cmd)), indent=2) + '\n')
        try:
            r = subprocess.run(list(map(str, cmd)), capture_output=True, timeout=30)
            rc, so, se, expired = r.returncode, r.stdout, r.stderr, False
        except OSError as e:
            rc, so, se, expired = None, b'', str(e).encode(), False
        except subprocess.TimeoutExpired as e:
            rc, so, se, expired = None, e.stdout or b'', e.stderr or b'', True
        (d / 'stdout').write_bytes(so)
        (d / 'stderr').write_bytes(se)
        result = dict(returncode=rc, timeout=expired,
                      stdout_sha256=digest(d / 'stdout'), stderr_sha256=digest(d / 'stderr'))
        (d / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    cpu = 'rv64,v=true,vlen=128,elen=64,zfh=true'
    available = a.qemu.is_file()
    save('availability.json', dict(qemu=str(a.qemu), executable_present=available,
         Zfh_actual_execution='pending' if available else 'UNOBSERVED: RV64 executable absent'))
    call('qemu-version', [a.qemu, '--version'])
    original = a.source.read_text()
    startup = original[original.index('\t/* Install the trap handler. */'):original.index('\t/* Initialise persistent state. */')]
    adapted = original.replace(startup, '\t/* Linux user provides FP/vector access; signals terminate on trap. */\n', 1)
    # Save every register touched by write transport. No buffer/vector/FP/CSR writes.
    capture = '''vector_entry_capture:
\taddi sp, sp, -48
\tsd a0, 0(sp)
\tsd a1, 8(sp)
\tsd a2, 16(sp)
\tsd a7, 24(sp)
\tsd t0, 32(sp)
\tli a0, 1
\tmv a1, s4
\tli a2, 256
\tli a7, 64
\tecall
\tli t0, 256
\tbne a0, t0, fail
\tld a0, 0(sp)
\tld a1, 8(sp)
\tld a2, 16(sp)
\tld a7, 24(sp)
\tld t0, 32(sp)
\taddi sp, sp, 48
vector_entry:
'''
    marker = '\tvsetvli\tt1, x0, e16, m1, ta, ma\n'
    if adapted.count(marker) != 1:
        p.error('original vector entry changed')
    adapted = adapted.replace(marker, capture + marker, 1)
    begin = adapted.index('_exit:\n')
    end = adapted.index('\n\t.data', begin)
    adapted = adapted[:begin] + '_exit:\n\tli a7, 93\n\tecall\n\tj .\n' + adapted[end:]
    # Original macros, entire scalar/vector body and unused M-mode handler remain literal.
    body = original[original.index('\t/* Initialise persistent state. */'):original.index('\t/* Success. */')]
    if body != adapted[adapted.index('\t/* Initialise persistent state. */'):adapted.index('\t/* Success. */')].replace(capture, ''):
        raise ValueError('original scalar/vector body changed')
    (out / 'reference.S').write_text(adapted)
    (out / 'original-to-user.diff').write_text(''.join(difflib.unified_diff(original.splitlines(True), adapted.splitlines(True), fromfile='pinned/test-zicclsm.S', tofile='reference.S')))
    (out / 'link.ld').write_text('OUTPUT_ARCH(riscv)\nENTRY(_start)\nSECTIONS { . = 0x10000; .text : { *(.text*) } . = ALIGN(4096); .data : { *(.data*) } }\n')
    base = [a.compiler, '--target=riscv64-unknown-elf', '-fuse-ld=lld', '-march=rv64gv_zfh', '-mabi=lp64d', '-mno-relax', '-ffreestanding', '-nostdlib', '-static', '-Wl,-T,' + str(out / 'link.ld')]
    built = call('build', base + [out / 'reference.S', '-o', out / 'reference.elf'])
    call('compiler-version', [a.compiler, '--version'])
    if built['returncode'] != 0:
        raise RuntimeError('original RV64/Zfh build failed; see retained raw')
    call('disassembly', ['llvm-objdump-22', '-d', out / 'reference.elf'])
    save('identity.json', dict(source_sha256=digest(a.source), proof_sha256=digest(a.proof), adapter_sha256=digest(out / 'reference.S'), elf_sha256=digest(out / 'reference.elf'), qemu_sha256=digest(a.qemu) if available else None, compiler_sha256=digest(pathlib.Path(a.compiler)), original_body_literal_preserved=True))
    if not available:
        save('comparison.json', dict(status='BLOCKED_REFERENCE_UNAVAILABLE', captured_bytes=0, equal=None, mismatches=None, reference_calls=0, DUT_calls=0, reason='Requested existing qemu-riscv64 executable absent; Zfh actual availability cannot be checked. Static Task106 proof retained, not replaced.'))
        raise SystemExit(2)
    # An actual Zfh load/store probe precedes execution of the full original body.
    (out / 'zfh-probe.S').write_text('.text\n.global _start\n_start:\n lla t0, data\n flh fa0, 0(t0)\n fsh fa0, 2(t0)\n li a0, 0\n li a7, 93\n ecall\n.data\n.balign 4\ndata: .word 0\n')
    if call('probe-build', base + [out / 'zfh-probe.S', '-o', out / 'zfh-probe.elf'])['returncode'] != 0:
        raise RuntimeError('Zfh probe build failed')
    probe = call('zfh-probe', [a.qemu, '-cpu', cpu, out / 'zfh-probe.elf'])
    if probe['returncode'] != 0 or probe['timeout']:
        save('comparison.json', dict(status='BLOCKED_ZFH_UNAVAILABLE', equal=None, reference_calls=0, DUT_calls=0, probe=probe))
        raise SystemExit(2)
    run = call('reference', [a.qemu, '-cpu', cpu, '-d', 'in_asm,exec', '-D', out / 'reference-trace.txt', out / 'reference.elf'])
    raw = (out / 'reference/stdout').read_bytes()
    mismatch = [i for i in range(min(len(raw), 256)) if raw[i] != expected[i]]
    ok = run['returncode'] == 0 and not run['timeout'] and len(raw) == 256 and raw == expected
    save('comparison.json', dict(status='PASS' if ok else 'FAIL', captured_bytes=len(raw), captured_hex=raw.hex(), expected_hex=expected.hex(), equal=raw == expected, mismatches=mismatch, reference_calls=1, DUT_calls=0, original_check_exit=run['returncode'], Zfh_probe=probe, scope='Task106 extraction input validation only; no additional rvdbt coverage or original M-mode PASS'))
    if not ok:
        raise RuntimeError('reference/precondition check failed')

if __name__ == '__main__':
    main()
