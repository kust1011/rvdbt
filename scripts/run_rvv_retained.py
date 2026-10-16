#!/usr/bin/env python3
"""Local directed-corpus replay using existing selectors and packet predicates.

Inputs and retained independent references are supplied separately. No source
rewriting, reference generation, archive extraction, SSH or historical PASS reuse.
"""
import argparse
import collections
import csv
import functools
import fcntl
import importlib
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from rvv import retained_index as verify
from run_rvv_external import execution_contract, prepare_output
from rvv_tests import digest, save
from rvv import retained_storage as storage
READER = 'original-tool-pins-v1'
FILTERS = ('form', 'unit', 'sew', 'lmul', 'vlen', 'mask', 'vl', 'vstart')


def selection(a):
    return {k: getattr(a, k) for k in FILTERS if getattr(a, k, None) is not None}


def selected_entries(index, a):
    if getattr(a, 'entry', None):
        if a.entry not in index['entries']:
            raise ValueError('unknown entry: '+a.entry)
        entries = [a.entry]
    else:
        entries = list(index['entries'])
    if getattr(a, 'form', None):
        row = next((r for r in index['rows'] if r['form'] == a.form), None)
        if row is None:
            raise ValueError('unknown form: '+a.form)
        owners = {r['entry'] for r in row['entries']}
        entries = [e for e in entries if e in owners]
        if not entries:
            raise ValueError('entry does not own form')
    return entries


def selected_units(index, entry, a):
    filters = selection(a)
    count = 0
    for unit in corpus_units(index, entry, a.raw_root, a.reference_root):
        chosen = [i for i in unit['selected'] if all(
            (verify.form(unit['cases'][i]) if k == 'form' else unit['cases'][i].get(k)) == v
            for k, v in filters.items())]
        if not chosen:
            continue
        limit = getattr(a, 'max_units', None)
        if limit is not None and count >= limit:
            break
        # Execute the original complete ELF; never rewrite packets or selectors.
        yield dict(unit, selected=chosen)
        count += 1


def selection_arguments(a):
    return [x for k, v in selection(a).items() for x in ('--'+k, str(v))]


def atomic_save(path, value):
    temporary = path.with_name(path.name+'.tmp-'+str(os.getpid()))
    save(temporary, value)
    os.replace(temporary, path)


def corpus_units(index, entry, raw_root, reference_root):
    definition = index['entries'][entry]
    original = verify.relocated(definition['original'], index['original_root'], raw_root)
    reference = verify.relocated(definition['original'], index['original_root'], reference_root)
    raw = (original / 'manifest.json').read_bytes()
    if verify.sha(raw) != definition['manifest_sha256']:
        raise ValueError('manifest identity mismatch: ' + entry)
    cases = json.loads(raw)['cases']
    if len({c['id'] for c in cases}) != len(cases):
        raise ValueError('manifest case IDs are not unique within entry')
    accepted = verify.accepted_cases(definition, cases)
    groups = collections.defaultdict(list)
    for position, case in enumerate(cases):
        groups[case['unit']].append((position, case))
    allowed = {position for position, _ in accepted}
    builds_path = original / 'build-commands.json'
    if digest(builds_path) != definition['build_commands_sha256']:
        raise ValueError('build record identity mismatch: ' + entry)
    builds = verify.load(builds_path)
    builds = {Path(r['command'][-1]).parent.name: r for r in builds
              if Path(r['command'][-1]).name == 'test.elf'}
    for unit, group in groups.items():
        selected = [i for i, (position, _) in enumerate(group) if position in allowed]
        if not selected:
            continue
        record = builds[unit]
        if record['returncode'] != 0:
            raise ValueError('failed retained build: ' + unit)
        yield dict(entry=entry, unit=unit, definition=definition, original=original,
                   reference=reference / 'runs' / unit / 'Reference', reference_corpus=reference,
                   cases=[c for _, c in group], selected=selected,
                   elf=original / unit / 'test.elf', elf_sha256=record['elf_sha256'])


def checker(definition, raw_root, original_root):
    # Exactly the entry's original predicate snapshot, including relative data.
    pins = predicate_sources(definition, raw_root, original_root)
    names = {p.stem for p in pins if p.suffix == '.py'}
    for name in names:
        module = sys.modules.get(name)
        if module is not None and Path(getattr(module, '__file__', '')).resolve() not in pins:
            raise ValueError('predicate module already loaded outside snapshot: '+name)
    tools = verify.relocated(definition['tools'], original_root, raw_root)
    sys.path.insert(0, str(tools))
    v = importlib.import_module('vadd')
    if not hasattr(v, 'check_isa'):
        original_decode = v.decode
        decoded = {}
        def cached_decode(c, raw):
            key = (c['id'], raw)
            if key not in decoded:
                if len(decoded) >= 4:
                    decoded.clear()
                decoded[key] = original_decode(c, raw)
            return decoded[key]
        v.decode = cached_decode
        v.check_isa = lambda c, raw, rc=0, timeout=False: v.check(c, raw, rc, timeout)
        v.check_reference = lambda c, raw, ref: v.check(c, raw, 0, False, ref)
    if definition['install']:
        importlib.import_module(definition['install']).install(v)
    resolved_modules(pins)
    return v, pins


def predicate_sources(definition, raw_root, original_root):
    pins = {}
    for name, expected in definition['tool_pins'].items():
        path = verify.relocated(name, original_root, raw_root)
        if digest(path) != expected:
            raise ValueError('original checker/data identity mismatch: '+str(path))
        pins[path.resolve()] = expected
    data = verify.ROOT/'docs/rvv-validation/directed-task178/PREDICATE_DATA_PINS.json'
    for name, expected in verify.load(data).get(str(definition['batch']), {}).items():
        path = verify.relocated(name, original_root, raw_root)
        if digest(path) != expected:
            raise ValueError('original predicate data identity mismatch: '+str(path))
        pins[path.resolve()] = expected
    return pins


def resolved_modules(pins):
    names = {p.stem for p in pins if p.suffix == '.py'}
    parents = {p.parent for p in pins if p.suffix == '.py'}
    result = {}
    for name, module in list(sys.modules.items()):
        filename = getattr(module, '__file__', None)
        if not filename:
            continue
        path = Path(filename).resolve()
        if (name not in names and path not in pins
                and not any(path.is_relative_to(p) for p in parents)):
            continue
        actual = digest(path)
        if pins.get(path) != actual:
            raise ValueError('loaded predicate outside original pins: '+name+' '+str(path))
        result[name] = dict(path=str(path), sha256=actual, expected_sha256=pins[path], match=True)
    return result


LEGACY_LEDGERS = {'b168-039', 'b171-068', 'b171-069'}


@functools.lru_cache(maxsize=3)
def reference_ledger(path):
    rows = {}
    for row in json.loads(storage.verify(path)):
        if row['arm'] == 'Reference' and row['status'] == 'PASS':
            if row['case'] in rows and rows[row['case']] != row:
                raise ValueError('ambiguous retained reference ledger: '+row['case'])
            rows[row['case']] = row
    return rows


def acceptance_path(unit):
    p = unit['reference']/'checks.json'
    if storage.physical(p).is_file():
        return p
    if unit['entry'] not in LEGACY_LEDGERS:
        raise FileNotFoundError(p)
    p = unit['reference_corpus']/'results.json'
    if not storage.physical(p).is_file():
        raise FileNotFoundError(p)
    return p


def retained_inputs(unit, v):
    guest = storage.verify(unit['elf'])
    if verify.sha(guest) != unit['elf_sha256']:
        raise ValueError('retained ELF identity mismatch')
    refdir = unit['reference']
    rec = verify.load(refdir / 'execution.json')
    reference = storage.verify(refdir / 'packets.bin')
    if rec['returncode'] != 0 or rec['timeout']:
        raise ValueError('failed retained reference')
    if verify.sha(reference) != rec['stdout_sha256']:
        # Legacy Sail adapters retain decoded packets separately from stdout.
        # Apply the original four-byte signature decoder, without running an oracle.
        if (not storage.physical(refdir/'stdout').is_file()
                or verify.sha(storage.verify(refdir/'stdout')) != rec['stdout_sha256']):
            raise ValueError('retained reference identity mismatch')
        recorded = verify.load(refdir/'command.json')
        if ('--test-signature' not in recorded or '--signature-granularity' not in recorded
                or recorded[recorded.index('--signature-granularity')+1] != '4'):
            raise ValueError('unknown retained reference packet transport')
        decoded = b''.join(int(line, 16).to_bytes(4, 'little')
                           for line in storage.verify(refdir/'signature').decode().splitlines())
        if decoded != reference:
            raise ValueError('retained Sail signature/packet mismatch')
    size = v.packet_size(unit['cases'][0])
    if len(reference) != size * len(unit['cases']):
        raise ValueError('retained reference packet extent')
    acceptance = acceptance_path(unit)
    ledger = reference_ledger(acceptance) if acceptance.name == 'results.json' else None
    accepted = ledger if ledger is not None else {
        r['case'] for r in json.loads(storage.verify(acceptance)) if r['status'] == 'PASS'}
    for i in unit['selected']:
        c = unit['cases'][i]
        if c['id'] not in accepted:
            raise ValueError('reference case not accepted: ' + c['id'])
        if ledger is not None:
            row = ledger[c['id']]
            if row['offset'] != i*size or row['size'] != size:
                raise ValueError('retained reference ledger packet offset/size')
        v.check_isa(c, reference[i*size:(i+1)*size], 0, False)
    return guest, reference, size


def command(recorded, engine, work):
    # Keep every semantic option; relocate only filesystem/cache/diagnostic outputs.
    paths = {'fsroot': work/'fs', 'cache': work/'cache', 'dump-tbmap': work/'tbmap',
             'dump-tbcode': work/'tbcode', 'rvv-pc-census-out': work/'pc-census.csv'}
    result = [str(engine)]
    for option in recorded[1:]:
        key = option.split('=', 1)[0].removeprefix('--')
        # Diagnostics are not semantic options. Do not multiply historical TB dumps.
        if key in ('dump-tbmap', 'dump-tbcode', 'rvv-pc-census-out'):
            continue
        result.append('--'+key+'='+str(paths[key]) if key in paths else option)
    return result


def reconcile_or_execute(cmd, directory, env, timeout):
    if not directory.exists():
        return storage.execute(cmd, directory, env, timeout), True
    # A completed capture without checks is audited, never launched again.
    if not (directory/'execution.json').is_file():
        raise ValueError('incomplete launch needs diagnosis; refusing replay: '+str(directory))
    saved = verify.load(directory/'command.json')
    if execution_contract(saved) != execution_contract(cmd):
        raise ValueError('changed command in retained capture')
    rec = verify.load(directory/'execution.json')
    for name in ('stdout', 'stderr'):
        if verify.sha(storage.verify(directory/name)) != rec[name+'_sha256']:
            raise ValueError('changed retained capture: '+name)
    return rec, False


def campaign(a, index):
    if not all((a.engine, a.library_dir, a.output, a.cache_dir, a.all_units)):
        raise ValueError('campaign requires engine/library/output/cache and explicit --all-units')
    out, scratch = a.output.resolve(), a.cache_dir.resolve()
    if out == scratch or out in scratch.parents or scratch in out.parents:
        raise ValueError('campaign output/cache overlap')
    out.mkdir(parents=True, exist_ok=True)
    lock = (out/'controller.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    binding = dict(engine=digest(a.engine), library=digest(a.library_dir/'libdbtjitshared.so'),
                   index=digest(a.index), inputs=str(a.raw_root.resolve()),
                   references=str(a.reference_root.resolve()))
    if selection(a):
        binding['selection'] = selection(a)
    if getattr(a, 'entry', None):
        binding['entry'] = a.entry
    if getattr(a, 'max_units', None) is not None:
        raise ValueError('campaign uses all selected units; use run for --max-units')
    manifest = out/'campaign.json'
    if manifest.exists():
        if not a.resume or verify.load(manifest)['binding'] != binding:
            raise ValueError('existing/changed campaign requires matching --resume')
        plan = verify.load(manifest)['entries']
    else:
        plan = {}
        form_names = set()
        for entry in selected_entries(index, a):
            units = cases = 0
            for u in selected_units(index, entry, a):
                units += 1
                cases += len(u['selected'])
                form_names.update(verify.form(u['cases'][i]) for i in u['selected'])
            if units:
                plan[entry] = dict(units=units, cases_per_arm=cases)
        if not plan:
            raise ValueError('empty selection')
        save(manifest, dict(binding=binding, entries=plan, forms=len(form_names),
                            units=sum(e['units'] for e in plan.values()),
                            calls=sum(e['units']*4 for e in plan.values()),
                            checks=sum(e['cases_per_arm']*4 for e in plan.values())))
    pending, active, completed = list(plan), {}, {}
    stop = out/'STOP_NEW_UNITS'
    while pending or active:
        while pending and len(active) < a.jobs and not stop.exists():
            entry = pending.pop(0)
            cmd = [sys.executable, __file__, 'run', '--entry', entry, '--resume',
                   '--raw-root', str(a.raw_root), '--reference-root', str(a.reference_root),
                   '--index', str(a.index), '--engine', str(a.engine), '--library-dir', str(a.library_dir),
                   '--output', str(out/entry), '--cache-dir', str(scratch/entry),
                   '--max-units', str(plan[entry]['units']), '--timeout', str(a.timeout),
                   '--stop-file', str(stop), *selection_arguments(a)]
            log = (out/(entry+'.log')).open('ab')
            active[entry] = (subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT), log)
        for entry, (proc, log) in list(active.items()):
            rc = proc.poll()
            if rc is not None:
                log.close();completed[entry] = rc;del active[entry]
                if rc and not stop.exists():
                    save(stop, dict(entry=entry, returncode=rc, time=time.time(), log=str(out/(entry+'.log'))))
        progress = {}
        for entry in plan:
            path = out/entry/'progress.json'
            if path.exists():
                current = verify.load(path)
                if current.get('reader') == READER:
                    progress[entry] = current
        atomic_save(out/'STATUS.json', dict(time=time.time(), owner_pid=os.getpid(),
             state='BLOCKED_DRAINING' if stop.exists() else 'RUNNING', jobs=a.jobs,
             reader=READER,
             active={e:p.pid for e,(p,_) in active.items()}, pending_entries=len(pending),
             exit_codes=completed, checked_calls=sum(p['checked_calls'] for p in progress.values()),
             checked_units=sum(p['units'] for p in progress.values()), entries=progress))
        if stop.exists() and not active:
            lock.close()
            return 1
        if pending or active:
            time.sleep(10)
    for entry, expected in plan.items():
        rows = verify.load(out/entry/'summary.json')['results']
        if (len(rows) != expected['units']*4 or
                len({(r['unit'],r['arm']) for r in rows}) != len(rows) or
                sum(r['cases'] for r in rows) != expected['cases_per_arm']*4):
            raise ValueError('final ordinary key/count mismatch: '+entry)
    final = dict(time=time.time(), state='COMPLETE_ORDINARY_ONLY', entry_exit_codes=completed,
                 reader=READER,
                 scope='ordinary directed only; supplements separate', binding=binding,
                 units=sum(e['units'] for e in plan.values()),
                 calls=sum(e['units']*4 for e in plan.values()),
                 checks=sum(e['cases_per_arm']*4 for e in plan.values()))
    atomic_save(out/'COMPLETE.json', final)
    atomic_save(out/'STATUS.json', final)
    lock.close()
    return 0


def audit(a, index):
    """Recount actual receipts; no DUT call or full raw rehash."""
    if not all((a.engine, a.library_dir, a.output)):
        raise ValueError('audit requires engine/library/output')
    identity = {str(p.resolve()): digest(p) for p in
                (a.engine, a.library_dir/'libdbtjitshared.so')}
    entries = selected_entries(index, a)
    forms = collections.Counter()
    methods = {arm: collections.Counter() for arm in ('B', 'M1', 'M2', 'BOTH')}
    per_form = {}
    seen = set()
    units = cases = 0
    checked_entries = 0
    new_calls = reused_calls = 0
    index_hash = digest(a.index)
    for entry in entries:
        iterator = iter(selected_units(index, entry, a))
        first = next(iterator, None)
        if first is None:
            continue
        checked_entries += 1
        out = a.output/entry
        binding = verify.load(out/'identity.json')
        if binding['files'] != identity or binding['index_sha256'] != index_hash:
            raise ValueError('audit DUT/library/index identity: '+entry)
        if binding.get('selection', {}) != selection(a):
            raise ValueError('audit selection differs: '+entry)
        pins = predicate_sources(index['entries'][entry], a.raw_root, index['original_root'])
        modules = verify.load(out/'checker-bindings.json')['resolved_modules']
        definition = index['entries'][entry]
        required = {'vadd'}
        if definition['install']:
            required.add(definition['install'])
        tools = verify.relocated(definition['tools'], index['original_root'], a.raw_root)
        for name in required:
            if name not in modules:
                raise ValueError('missing required checker module binding: '+entry+'/'+name)
            expected_path = (tools/(name.replace('.', '/')+'.py')).resolve()
            if Path(modules[name]['path']).resolve() != expected_path:
                raise ValueError('wrong required checker module binding: '+entry+'/'+name)
        for name, module in modules.items():
            expected = pins.get(Path(module['path']).resolve())
            if (not expected or not module['match'] or
                    module['sha256'] != expected or module['expected_sha256'] != expected):
                raise ValueError('audit checker module binding: '+entry+'/'+name)
        summary = verify.load(out/'summary.json')
        if summary.get('reader') != READER or summary['status'] != 'PASS_SELECTED_UNITS':
            raise ValueError('not completed with original checker: '+entry)
        if summary.get('checker_modules', {}) != modules:
            raise ValueError('summary checker bindings differ: '+entry)
        new_calls += summary['new_dut_calls']
        reused_calls += summary['reused_captures']
        if summary['new_dut_calls'] + summary['reused_captures'] != len(summary['results']):
            raise ValueError('invocation call accounting differs: '+entry)
        declared = {(r['unit'], r['arm']): r for r in summary['results']}
        if len(declared) != len(summary['results']):
            raise ValueError('duplicate summary key: '+entry)
        actual = set()
        for u in itertools.chain([first], iterator):
            units += 1
            selected_forms = collections.Counter(verify.form(u['cases'][i]) for i in u['selected'])
            for form in selected_forms:
                row = per_form.setdefault(form, dict(entries=set(), units=0,
                    calls=0, checks=0, **{arm+'_'+k: 0 for arm in methods for k in ('calls', 'checks')}))
                row['entries'].add(entry)
                row['units'] += 1
            for arm in methods:
                key = (entry, u['unit'], arm)
                if key in seen:
                    raise ValueError('duplicate execution key: '+str(key))
                seen.add(key);actual.add((u['unit'], arm))
                d = out/'runs'/u['unit']/arm
                check = verify.load(d/'check.json')
                rec = verify.load(d/'execution.json')
                if (check != declared.get((u['unit'], arm)) or check['status'] != 'PASS'
                        or check['unit'] != u['unit'] or check['arm'] != arm
                        or check['cases'] != len(u['selected'])
                        or check['guest_sha256'] != u['elf_sha256']
                        or check['output_sha256'] != rec['stdout_sha256']
                        or rec['returncode'] != 0 or rec['timeout']):
                    raise ValueError('actual receipt mismatch: '+str(key))
                for name in ('stdout', 'stderr'):
                    if not storage.physical(d/name).is_file():
                        raise FileNotFoundError(d/name)
                for path in (u['elf'], u['reference']/'packets.bin'):
                    if not storage.physical(path).is_file():
                        raise FileNotFoundError(path)
                cmd = verify.load(d/'command.json')
                original = verify.load(u['original']/'runs'/u['unit']/arm/'command.json')
                expected = command(original, a.engine.resolve(), Path('/relocated'))
                if execution_contract(cmd) != execution_contract(expected):
                    raise ValueError('actual method command mismatch: '+str(key))
                opts = tuple('<unit-vlen>' if x.startswith('--vlen=') else x
                             for x in execution_contract(cmd)[1:])
                methods[arm][opts] += 1
                forms.update(selected_forms)
                for form, count in selected_forms.items():
                    row = per_form[form]
                    row['calls'] += 1
                    row['checks'] += count
                    row[arm+'_calls'] += 1
                    row[arm+'_checks'] += count
                cases += len(u['selected'])
        if actual != set(declared):
            raise ValueError('missing/extra actual unit/arm keys: '+entry)
    if identity != {p: digest(Path(p)) for p in identity}:
        raise ValueError('DUT/library changed during audit')
    if not seen:
        raise ValueError('empty selection')
    result = dict(status='PASS_ACTUAL_RECEIPT_RECOUNT', reader=READER,
                  scope='ordinary directed only; supplements remain separate',
                  selection=selection(a), max_units=getattr(a, 'max_units', None),
                  index_sha256=index_hash, audit_runner_sha256=digest(__file__),
                  binding=identity, entries=checked_entries, forms=len(forms),
                  units=units, calls=len(seen), checks=cases,
                  new_calls_in_final_entry_invocations=new_calls,
                  rechecked_captures_in_final_entry_invocations=reused_calls,
                  per_form_checks=dict(sorted(forms.items())),
                  method_configurations={arm: [dict(options=list(opts), calls=n)
                       for opts,n in counts.items()] for arm,counts in methods.items()},
                  raw_verification='existence plus original per-call checks/hashes; no full raw rehash',
                  timing_equivalence='not claimed: correctness retains diagnostic flags')
    save(a.output/('AUDIT-'+a.entry+'.json' if a.entry else 'AUDIT.json'), result)
    fields = ['form', 'status', 'entries', 'units', 'calls', 'checks'] + [
        arm+'_'+k for arm in methods for k in ('calls', 'checks')]
    name = 'AUDIT-'+a.entry+'_PER_FORM.csv' if a.entry else 'AUDIT_PER_FORM.csv'
    with (a.output/name).open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for form, row in sorted(per_form.items()):
            writer.writerow(dict(row, form=form, status='PASS_SELECTED_CASES',
                                 entries=';'.join(sorted(row['entries']))))
    return 0


def main(argv=None):
    if not __debug__:
        raise RuntimeError('retained predicates require assertions; run without -O')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['list', 'show', 'preflight', 'run', 'campaign', 'audit'])
    p.add_argument('--index', type=Path)
    p.add_argument('--bundle', type=Path, help='local received bundle: metadata/forms.json.gz and data/')
    p.add_argument('--raw-root', type=Path)
    p.add_argument('--reference-root', type=Path)
    p.add_argument('--entry', choices=None, help='one existing index entry (isolated checker process)')
    p.add_argument('--form', help='exact catalogue mnemonic/operand form, e.g. vadd.vv')
    p.add_argument('--unit', help='exact original unit ID; complete ELF still executes')
    for name in ('sew', 'vlen', 'vl', 'vstart'):
        p.add_argument('--'+name, type=int)
    for name in ('lmul', 'mask'):
        p.add_argument('--'+name, help='exact manifest value; see show')
    p.add_argument('--engine', type=Path)
    p.add_argument('--library-dir', type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--cache-dir', type=Path)
    p.add_argument('--max-units', type=int, help='per-entry limit; run defaults to 1, preflight/audit to all')
    p.add_argument('--timeout', type=int, default=120)
    p.add_argument('--resume', action='store_true', help='audit/skip captured calls, never repeat a launch')
    p.add_argument('--stop-file', type=Path, help='drain before the next unit when this file exists')
    p.add_argument('--all-units', action='store_true', help='explicitly authorize the indexed ordinary campaign')
    p.add_argument('--jobs', type=int, default=2, help='campaign entry processes, 1..4 (not timing lanes)')
    a = p.parse_args(argv)
    if not 1 <= a.timeout <= 600 or (a.max_units is not None and a.max_units < 1) or not 1 <= a.jobs <= 4:
        p.error('timeout must be 1..600 and max-units positive')
    if a.bundle:
        a.index = a.index or a.bundle/'metadata/forms.json.gz'
        a.raw_root = a.raw_root or a.bundle/'data'
        a.reference_root = a.reference_root or a.bundle/'data'
    a.index = a.index or verify.INDEX
    index = verify.load(a.index)
    entries = selected_entries(index, a)
    if a.action in ('list', 'show') and any(k != 'form' for k in selection(a)):
        p.error('list/show describe the catalogue; use preflight for configuration selectors')
    if a.action == 'list':
        print('form\tcases_per_arm\tentries')
        for row in index['rows']:
            owners = [e for e in row['entries'] if e['entry'] in entries]
            if owners and (not a.form or row['form'] == a.form):
                print(row['form'], sum(e['cases'] for e in owners),
                      ';'.join(e['entry'] for e in owners), sep='\t')
        return 0
    if a.action == 'show':
        if not a.form:
            p.error('show requires --form')
        row = next(r for r in index['rows'] if r['form'] == a.form)
        sources = {}
        for entry in entries:
            definition = index['entries'][entry]
            sources[entry] = {k: definition[k] for k in (
                'family', 'generator_module', 'source_test', 'install',
                'manifest_sha256', 'build_commands_sha256', 'accepted_selector_sha256')}
            sources[entry]['cases_per_arm'] = next(e['cases'] for e in row['entries'] if e['entry'] == entry)
            for name in ('original', 'tools'):
                sources[entry][name+'_relative'] = str(Path(definition[name]).relative_to(index['original_root']))
            sources[entry]['tool_pins'] = {str(Path(n).relative_to(index['original_root'])): h
                                          for n, h in definition['tool_pins'].items()}
        print(json.dumps(dict(status='CASE_CATALOGUE_ONLY', form=a.form,
            cases_per_arm=sum(s['cases_per_arm'] for s in sources.values()),
            index_sha256=digest(a.index),
            definitions={k: row[k] for k in ('origin', 'dimensions', 'missing_fields',
                'length_classes', 'checked_state', 'independent_oracle')},
            entries=sources,
            measured_result='docs/rvv-validation/delivery-task182/MEASURED_D252_PER_FORM.csv',
            replay='run --form '+a.form+' --entry ENTRY --bundle BUNDLE --engine DUT '
                   '--library-dir LIB --output NEW --cache-dir NEW_CACHE',
            limits='catalogue, not a new execution or historical PASS credit; dimensions are '
                   'marginals, not a Cartesian product; preflight resolves actual cases'), indent=2))
        return 0
    if not all((a.raw_root, a.reference_root)):
        p.error('requires --bundle or both --raw-root and --reference-root')
    if a.action == 'audit':
        return audit(a, index)
    if a.action == 'campaign':
        return campaign(a, index)
    if a.action == 'preflight':
        counts = collections.Counter()
        units = 0
        details = []
        for entry in entries:
            predicate_sources(index['entries'][entry], a.raw_root, index['original_root'])
            for u in selected_units(index, entry, a):
                # No guest, checker import, ELF decompression or all-raw hashing here.
                for path in (u['elf'], u['reference']/'packets.bin'):
                    if not path.is_file() and not Path(str(path)+'.gz').is_file():
                        raise FileNotFoundError(path)
                for name in ('execution.json',):
                    if not (u['reference']/name).is_file():
                        raise FileNotFoundError(u['reference']/name)
                acceptance_path(u)
                for arm in ('B', 'M1', 'M2', 'BOTH'):
                    verify.load(u['original']/'runs'/u['unit']/arm/'command.json')
                counts.update(verify.form(u['cases'][i]) for i in u['selected'])
                units += 1
                if a.max_units is not None:
                    details.append(dict(entry=entry, unit=u['unit'], elf=str(u['elf']),
                        test_source=str(u['elf'].with_name('test.S')),
                        elf_sha256=u['elf_sha256'], reference=str(u['reference']),
                        selected_cases=[u['cases'][i] for i in u['selected']],
                        recorded_method_commands={arm: verify.load(u['original']/'runs'/u['unit']/arm/'command.json')
                                         for arm in ('B', 'M1', 'M2', 'BOTH')},
                        reference_command=verify.load(u['reference']/'command.json')))
        if not units:
            raise ValueError('empty selection: no accepted manifest cases match')
        print(json.dumps(dict(status='INPUT_INVENTORY_ONLY', entries=len(entries),
                              units=units, forms=len(counts), cases_per_arm=sum(counts.values()),
                              selection=selection(a), details=details,
                              new_dut_calls=0, fresh_reference_calls=0)))
        return 0
    if not a.entry and a.form and len(entries) == 1:
        a.entry = entries[0]
    if not all((a.entry, a.engine, a.library_dir, a.output)):
        p.error('run requires --entry --engine --library-dir --output')
    engine = a.engine.resolve()
    os.environ['RVV_COMPRESS'] = '1'
    library = a.library_dir.resolve()/'libdbtjitshared.so'
    identity = {str(x): digest(x) for x in (engine, library)}
    definition = index['entries'][a.entry]
    v, predicate_pins = checker(definition, a.raw_root, index['original_root'])
    binding = dict(files=identity, index_sha256=digest(a.index), entry=a.entry,
                                  selection=selection(a),
                                  runner_sha256=digest(__file__),
                                  scope='fresh DUT; retained independent reference; ordinary directed only')
    if a.resume and a.output.exists():
        out = a.output.resolve()
        scratch = a.cache_dir.resolve() if a.cache_dir else out/'work'
        previous = verify.load(out/'identity.json')
        if any(previous.get(k) != binding[k] for k in ('files', 'index_sha256')):
            raise ValueError('changed resume DUT/library/index')
        if previous.get('entry', a.entry) != a.entry:
            raise ValueError('changed resume entry')
        if previous.get('selection', {}) != selection(a):
            raise ValueError('changed resume selection')
        # Recheck retained captures with the current predicates, not old PASS rows.
        save(out/('invocation-'+str(time.time_ns())+'.json'), binding)
    else:
        out, scratch = prepare_output(a.output, a.cache_dir)
        save(out/'identity.json', binding)
    entry_lock = (out/'entry.lock').open('a')
    fcntl.flock(entry_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    save(out/'checker-bindings.json', dict(resolved_modules=resolved_modules(predicate_pins),
         verified_pins={str(p):h for p,h in predicate_pins.items()}))
    results = []
    new_calls = 0
    env = dict(os.environ, LD_LIBRARY_PATH=str(library.parent)+os.pathsep+os.environ.get('LD_LIBRARY_PATH',''))
    for n, u in enumerate(selected_units(index, a.entry, a)):
        if n >= (a.max_units or 1):
            break
        if a.stop_file and a.stop_file.exists():
            print('DRAINED before '+u['unit'])
            return 3
        guest, reference, size = retained_inputs(u, v)
        unit_work = scratch/u['unit']
        materialized = False
        for arm in ('B', 'M1', 'M2', 'BOTH'):
            storage.reserve(out, len(reference)*2 + 64*1024**2)
            work = scratch/u['unit']/arm
            saved = verify.load(u['original']/'runs'/u['unit']/arm/'command.json')
            d = out/'runs'/u['unit']/arm
            if not d.exists():
                (unit_work/'fs').mkdir(parents=True, exist_ok=True)
                if not (unit_work/'fs/t.elf').exists():
                    (unit_work/'fs/t.elf').write_bytes(guest)
                    materialized = True
                elif (unit_work/'fs/t.elf').read_bytes() != guest:
                    raise ValueError('existing scratch guest differs; refusing overwrite')
                work.mkdir()
                (work/'fs').symlink_to(unit_work/'fs', target_is_directory=True)
                (work/'cache').mkdir()
            elif not a.resume:
                raise ValueError('existing capture requires --resume')
            # Stream lossless raw output; failures remain complete, not just PASS rows.
            atomic_save(out/'ACTIVE.json', dict(unit=u['unit'], arm=arm,
                        time=time.time(), captured=d.exists(), entry=a.entry))
            rec, launched = reconcile_or_execute(command(saved, engine, work), d, env, a.timeout)
            new_calls += int(launched)
            raw = storage.verify(d/'stdout')
            if rec['returncode'] or rec['timeout'] or len(raw) != len(reference):
                raise ValueError('execution/packet extent failed: '+u['unit']+'/'+arm)
            for i in u['selected']:
                c = u['cases'][i]
                packet, rp = raw[i*size:(i+1)*size], reference[i*size:(i+1)*size]
                v.check_isa(c, packet, rec['returncode'], rec['timeout'])
                v.check_reference(c, packet, rp)
            result = dict(unit=u['unit'], arm=arm, cases=len(u['selected']),
                          status='PASS', guest_sha256=verify.sha(guest),
                          reference_sha256=verify.sha(reference), output_sha256=verify.sha(raw))
            save(d/'check.json', result)
            results.append(result)
            if launched and (work/'cache').exists():
                shutil.rmtree(work/'cache')  # New successful scratch only, never inputs/raw.
        if materialized and (unit_work/'fs/t.elf').exists():
            (unit_work/'fs/t.elf').unlink()
        if n == 0:
            save(out/'checker-bindings.json', dict(resolved_modules=resolved_modules(predicate_pins),
                 verified_pins={str(p):h for p,h in predicate_pins.items()}))
        atomic_save(out/'progress.json', dict(entry=a.entry, units=n+1, checked_calls=len(results),
                                       reader=READER, new_calls=new_calls,
                                       rechecked_calls=len(results)-new_calls,
                                       time=time.time(), last_unit=u['unit']))
    if not results:
        raise ValueError('empty selection')
    if identity != {x: digest(x) for x in identity}:
        raise ValueError('DUT/library changed')
    modules = resolved_modules(predicate_pins)
    save(out/'checker-bindings.json', dict(resolved_modules=modules,
         verified_pins={str(p):h for p,h in predicate_pins.items()}))
    save(out/'summary.json', dict(status='PASS_SELECTED_UNITS', results=results,
                                  selection=selection(a), max_units=a.max_units or 1,
                                  reader=READER,
                                  new_dut_calls=new_calls, reused_captures=len(results)-new_calls,
                                  fresh_reference_calls=0,
                                  checker_modules=modules, full_595_replay=False))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, AssertionError, ImportError, KeyError, StopIteration) as e:
        print('ERROR:', e, file=sys.stderr)
        sys.exit(1)
