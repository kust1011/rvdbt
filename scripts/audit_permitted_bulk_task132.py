"""Offline byte-array audit of terminal Task132 captures; executes no guest code."""
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
lines = (root / 'rv32_permitted_bulk_fault_test.stdout').read_text().splitlines()
cells = []
for i, line in enumerate(lines):
    if not line.startswith('BULK132_CELL '):
        continue
    c = json.loads(line.split(' ', 1)[1])
    s = json.loads(lines[i+1].split(' ', 1)[1])
    memory = bytes.fromhex(lines[i+2].split(' ', 1)[1])
    rb, eew, prefix = c['vlen']//8, c['eew'], c['prefix']
    registers = [bytearray((r*17+b*3)&255 for b in range(rb)) for r in range(32)]
    vl = 0 if c['whole'] else 2*rb//eew
    if c['masked']:
        registers[0] = bytearray(rb)
        for e in range(vl):
            if e % 2 == 0:
                registers[0][e//8] |= 1 << (e%8)
    want_mem = bytearray((b*13+5)&255 for b in range(4096))
    for e in range(c['start'], prefix):
        if c['masked'] and e % 2:
            continue
        byte = e*eew
        r, b, off = 8+byte//rb, byte%rb, c['off']+byte
        if c['store']:
            want_mem[off:off+eew] = registers[r][b:b+eew]
        else:
            registers[r][b:b+eew] = want_mem[off:off+eew]
    if c['split'] and c['store']:
        byte = prefix*eew
        r, b, off = 8+byte//rb, byte%rb, c['off']+byte
        want_mem[off:off+eew-1] = registers[r][b:b+eew-1]
    width = {1:0, 2:5, 4:6, 8:7}[eew]
    raw = ((not c['masked']) << 25) | (5 << 15) | (width << 12) | (8 << 7) | (0x27 if c['store'] else 7)
    if c['whole']:
        raw |= (8 << 20) | ((c['nr']-1) << 29)
    assert s['origin'] == 'HostCopy' and s['reason'] == 'host_fault'
    assert (s['host_signal'], s['host_code']) == ((7,2) if c['bus'] else (11,2))
    assert (s['pc'],s['raw'],s['address'],s['element'],s['eew_bytes'],s['nf'],s['field']) == (0x80001234,raw,0x24001000,prefix,eew,c['nr'],0)
    assert s['gpr'][6] == 0x123
    assert s['csrs']['vstart'] == prefix and s['csrs']['vl'] == vl
    assert s['csrs']['vtype'] == (0x80000000 if c['whole'] else ({1:0,2:8,4:16,8:24}[eew] | 3))
    assert s['csrs']['fflags'] & 16
    assert s['vreg_hex'] == [r.hex() for r in registers]
    assert memory == want_mem
    cells.append(c)
assert len(cells) == 266, len(cells)
assert sum(c['bus'] for c in cells) == 133
report = {'terminal_bulk_cells': len(cells), 'actual_sigbus':133, 'actual_sigsegv':133,
          'complete_active_register_files_checked':266, 'full_accessible_memory_checked':266,
          'guest_executions':0, 'differences':[],
          'stdout_sha256':hashlib.sha256((root/'rv32_permitted_bulk_fault_test.stdout').read_bytes()).hexdigest()}
print(json.dumps(report, indent=2))
