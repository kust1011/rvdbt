"""Offline exact-PC/operand and one-time capture audit; executes no guest code."""
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path
root = Path(sys.argv[1]).resolve()
rows = []
for path in sorted(root.glob('sites-*.txt')):
    key = path.stem.removeprefix('sites-')
    binary = root / ('emitted-' + key + '.bin')
    output = subprocess.check_output(['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
                                      '-Mintel', '--no-show-raw-insn', str(binary)], text=True)
    (root / ('emitted-' + key + '.disasm')).write_text(output)
    decoded = {int(m[1], 16): m[2] for line in output.splitlines()
               if (m := re.match(r'^\s*([0-9a-f]+):\s*(.+)$', line))}
    sites = []
    for line in path.read_text().splitlines():
        site = {k: int(v, 16 if k in ('guest_pc', 'raw') else 10)
                for k, v in (s.split('=') for s in line.split())}
        off = site['offset']
        inst = decoded[off]
        mnemonic, operands = inst.split(None, 1)
        masked = site['mask'] != 255
        assert mnemonic == ('vmovdqu32' if masked and site['eew'] == 4 else 'vmovdqu64')
        assert site['addr_reg'] == 0 and site['bytes'] == 64
        assert ('{k7}' in operands) == masked
        assert ('{z}' in operands) == (masked and not site['store'])
        data = 'zmm' + str(site['data_reg'])
        memory = 'ZMMWORD PTR [rax' + (('+0x%x' % site['disp']) if site['disp'] else '') + ']'
        left, right = operands.split(',')
        if site['store']:
            assert left.startswith(memory) and right == data
        else:
            assert left.startswith(data) and right == memory
            later_vectors = [(pc, s) for pc, s in decoded.items() if pc > off and s.startswith('vmovdqu')]
            publication = min(later_vectors)[1]
            assert 'PTR [r13+' in publication and publication.split(',')[1] == data
        assert site['raw'] & 127 == (0x27 if site['store'] else 7)
        sites.append({'site': site, 'instruction': inst})
    rows.append({'shape': key, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                 'sites': sites})
assert len(rows) == 8
captures = []
names = ('R8','R9','R10','R11','R12','R13','R14','R15','RDI','RSI','RBP','RBX',
         'RDX','RAX','RCX','RSP','RIP','EFL','CSGSFS','ERR','TRAPNO','OLDMASK','CR2')
for path in sorted(root.glob('capture-*.bin')):
    raw = path.read_bytes()
    assert len(raw) == 416  # actual Linux x86-64 fixture struct (23 gregs + header + arrays)
    regs = dict(zip(names, struct.unpack_from('<23Q', raw)))
    address, signo, code, ip, vstart, vl, gpr6 = struct.unpack_from('<QiiIIII', raw, 184)
    assert signo == 11 and code == 2 and ip == 0x80001238 and vstart == 0 and gpr6 == 0x123
    dest, prefix, inside_bytes = raw[216:344], raw[344:408], raw[408:416]
    match = re.fullmatch(r'capture-(load|store)-eew(4|8)-partial([01])-inside(0|4|8)', path.stem)
    assert match
    store, eew, partial, inside = match.groups()
    eew, partial, inside = int(eew), int(partial), int(inside)
    shape = f'{store}-eew{eew}-partial{partial}'
    record = next(r for r in rows if r['shape'] == shape)['sites'][3 if partial else 1]['site']
    assert address == 0x24001000 and regs['RAX'] + record['disp'] + inside == address
    assert vl == (96 if partial else 128) // eew
    if store == 'load':
        assert dest[:64] == prefix and dest[64:] == bytes([0x67])*64
    else:
        assert dest == bytes([0x67])*128 and prefix == bytes([0x67])*64
    captures.append({'file': path.name, 'sha256': hashlib.sha256(raw).hexdigest(),
                     'host_regs': regs, 'address': address, 'guest_pc': ip, 'vl': vl,
                     'observed_vstart': vstart, 'gpr6': gpr6, 'destination_hex': dest.hex(),
                     'earlier_memory_hex': prefix.hex(),
                     'fault_chunk_accessible_bytes_hex': inside_bytes[:inside].hex(),
                     'precise_element_frontier': 'UNAVAILABLE', 'recovery': False, 'retry': False})
assert len(captures) == 16
result = {'guest_executions_by_auditor': 0, 'shapes': rows, 'captures': captures,
          'contract': 'Exact access identification and published chunk prefix; no native recovery.'}
(root / 'EMITTED_CAPTURE_AUDIT.json').write_text(json.dumps(result, indent=2) + '\n')
print('OFFLINE_NATIVE_AUDIT_PASS shapes=8 sites=24 captures=16 no-guests')
