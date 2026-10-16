"""Read the retained corpus index without importing historical generators/owners."""
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT/'docs/rvv-validation/delivery-task182/forms.json.gz'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path):
    path = Path(path)
    raw = path.read_bytes()
    return json.loads(gzip.decompress(raw) if path.suffix == '.gz' else raw)


def form(case):
    op = case.get('mnemonic', 'vadd')
    return op if '.' in op or op.startswith('vset') else op+'.'+case['form']


def relocated(path, old, new):
    # Historical absolute names are keys, never host filesystem dependencies.
    return Path(new)/Path(path).relative_to(old)


def accepted_cases(entry, cases):
    ranges = entry.get('accepted_ranges')
    if ranges is None:
        raise ValueError('index lacks accepted selectors; regenerate index')
    indices = []
    last = 0
    for lo, hi in ranges:
        if not (isinstance(lo, int) and isinstance(hi, int)
                and last <= lo < hi <= len(cases)):
            raise ValueError('invalid accepted range')
        indices.extend(range(lo, hi))
        last = hi
    if sha(json.dumps(indices, separators=(',', ':')).encode()) != entry['accepted_selector_sha256']:
        raise ValueError('accepted selector identity')
    return [(i, cases[i]) for i in indices]
