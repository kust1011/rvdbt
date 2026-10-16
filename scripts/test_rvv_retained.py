"""Retained-corpus adapter contracts; synthetic files, no ISA acceptance."""
import contextlib
import csv
import io
import gzip
import json
from pathlib import Path
import tempfile
import subprocess
import sys
from unittest import mock
from types import SimpleNamespace
import unittest

import run_rvv_retained as replay


class RetainedChecks(unittest.TestCase):
    def test_catalogue_does_not_silently_ignore_configuration_filter(self):
        with self.assertRaises(SystemExit) as error, contextlib.redirect_stderr(io.StringIO()):
            replay.main(['show', '--form', 'vadd.vv', '--sew', '32'])
        self.assertEqual(error.exception.code, 2)

    def test_catalogue_without_private_data_or_historical_imports(self):
        script = Path(replay.__file__).resolve()
        result = subprocess.run([sys.executable, '-B', str(script), 'list'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        catalogue = list(csv.DictReader(io.StringIO(result.stdout), delimiter='\t'))
        forms = [r['form'] for r in catalogue]
        self.assertEqual(len(forms), 595)
        self.assertEqual(len(set(forms)), 595)
        self.assertIn('vadd.vv', forms)
        self.assertTrue(all(int(r['cases_per_arm']) > 0 for r in catalogue))
        result = subprocess.run([sys.executable, '-B', str(script), 'show', '--form', 'vadd.vv'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        shown = json.loads(result.stdout)
        self.assertEqual(shown['form'], 'vadd.vv')
        self.assertEqual(shown['status'], 'CASE_CATALOGUE_ONLY')
        self.assertGreater(shown['cases_per_arm'], 0)
        self.assertNotIn('historical', shown)
        self.assertNotIn('final179', shown)
        self.assertNotIn('/home/vick', result.stdout)
        probe = subprocess.run([sys.executable, '-B', '-c',
            'import json, sys; import run_rvv_retained; '
            'print(json.dumps(sorted(sys.modules)))'], cwd=script.parent,
            capture_output=True, text=True)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        imported = json.loads(probe.stdout)
        self.assertNotIn('rvv_verify', imported)
        self.assertNotIn('rvv.directed.storage149', imported)

    def test_optimized_predicates_refused(self):
        result = subprocess.run([sys.executable, '-B', '-O', replay.__file__, 'list'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('retained predicates require assertions', result.stderr)

    def test_selection_intersects_original_accepted_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); index, u = self.fixture(root)
            cases = [dict(id=str(i), unit='u', mnemonic=op, form='vv', sew=sew,
                          vlen=128, lmul='m1', mask='none', vl=1, vstart=0)
                     for i, (op, sew) in enumerate([('vadd', 8), ('vadd', 16), ('vsub', 8)])]
            raw = json.dumps(dict(cases=cases)).encode()
            (u['original']/'manifest.json').write_bytes(raw)
            e = index['entries']['entry']
            e.update(manifest_sha256=replay.verify.sha(raw), accepted_ranges=[[0, 2]],
                     accepted_selector_sha256=replay.verify.sha(b'[0,1]'))
            a = SimpleNamespace(raw_root=root/'inputs', reference_root=root/'refs',
                                form='vadd.vv', sew=8, max_units=1)
            selected = list(replay.selected_units(index, 'entry', a))
            self.assertEqual(len(selected), 1)
            self.assertEqual(selected[0]['selected'], [0])
            self.assertEqual(selected[0]['cases'], cases)  # ELF/packet extent unchanged
            a.form = 'vsub.vv'
            self.assertEqual(list(replay.selected_units(index, 'entry', a)), [])
            a.form = 'vadd.vv'; a.sew = 32
            self.assertEqual(list(replay.selected_units(index, 'entry', a)), [])

    def test_bundle_missing_data_never_executes(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(replay.storage, 'execute') as execute:
                with self.assertRaises(FileNotFoundError):
                    replay.main(['preflight', '--bundle', tmp, '--form', 'vadd.vv'])
                execute.assert_not_called()

    def test_empty_configuration_preflight_is_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); index, _ = self.fixture(root)
            index['rows'] = [dict(form='vadd.vv', entries=[dict(entry='entry')])]
            path = root/'index.json'; replay.save(path, index)
            with mock.patch.object(replay.storage, 'execute') as execute:
                with self.assertRaisesRegex(ValueError, 'empty selection'):
                    replay.main(['preflight', '--index', str(path),
                        '--raw-root', str(root/'inputs'), '--reference-root', str(root/'refs'),
                        '--form', 'vadd.vv', '--sew', '128'])
                execute.assert_not_called()

    def test_unknown_form_and_wrong_owner_rejected(self):
        index = dict(entries={'a': {}, 'b': {}},
                     rows=[dict(form='vadd.vv', entries=[dict(entry='a')])])
        for form, entry, message in [('not-an-op', None, 'unknown form'),
                                     ('vadd.vv', 'b', 'does not own form')]:
            with self.subTest(form=form, entry=entry):
                with self.assertRaisesRegex(ValueError, message):
                    replay.selected_entries(index, SimpleNamespace(form=form, entry=entry))

    def test_resume_rejects_changed_selection_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); index, _ = self.fixture(root)
            index['rows'] = [dict(form='vadd.vv', entries=[dict(entry='entry')])]
            path = root/'index.json'; replay.save(path, index)
            engine = root/'elfrun'; engine.write_bytes(b'dut')
            library = root/'libdbtjitshared.so'; library.write_bytes(b'library')
            out = root/'out'; out.mkdir()
            replay.save(out/'identity.json', dict(entry='entry',
                files={str(p.resolve()): replay.digest(p) for p in (engine, library)},
                index_sha256=replay.digest(path), selection=dict(form='vadd.vv', sew=16)))
            with mock.patch.object(replay, 'checker', return_value=(None, {})), \
                    mock.patch.object(replay.storage, 'execute') as execute:
                with self.assertRaisesRegex(ValueError, 'changed resume selection'):
                    replay.main(['run', '--index', str(path), '--raw-root', str(root/'inputs'),
                        '--reference-root', str(root/'refs'), '--form', 'vadd.vv', '--sew', '8',
                        '--engine', str(engine), '--library-dir', str(root),
                        '--output', str(out), '--resume'])
                execute.assert_not_called()

    def fixture(self, root):
        corpus = root/'inputs/corpus'
        ref = root/'refs/corpus/runs/u/Reference'
        corpus.mkdir(parents=True)
        ref.mkdir(parents=True)
        raw = json.dumps({'cases':[{'id':'c','unit':'u','mnemonic':'vadd','form':'vv'}]}).encode()
        (corpus/'manifest.json').write_bytes(raw)
        builds = [{'command':['cc','-o','u/test.elf'],'returncode':0,'elf_sha256':replay.verify.sha(b'elf')}]
        (corpus/'build-commands.json').write_text(json.dumps(builds))
        (corpus/'u').mkdir()
        (corpus/'u/test.elf').write_bytes(b'elf')
        (ref/'packets.bin').write_bytes(b'packet')
        (ref/'execution.json').write_text(json.dumps({'returncode':0,'timeout':False,'stdout_sha256':replay.verify.sha(b'packet')}))
        (ref/'checks.json').write_text(json.dumps([{'case':'c','status':'PASS'}]))
        entry = dict(original='/recorded/corpus',tool_pins={},batch=145,manifest_sha256=replay.verify.sha(raw),
                     build_commands_sha256=replay.digest(corpus/'build-commands.json'),
                     accepted_ranges=[[0,1]],accepted_selector_sha256=replay.verify.sha(b'[0]'))
        index = dict(original_root='/recorded',entries={'entry':entry})
        return index, next(replay.corpus_units(index,'entry',root/'inputs',root/'refs'))

    def test_separate_reference_and_selector(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);index,u=self.fixture(root)
            self.assertEqual(u['reference'],root/'refs/corpus/runs/u/Reference')
            self.assertEqual(u['selected'],[0])
            index['entries']['entry']['accepted_selector_sha256']='changed'
            with self.assertRaisesRegex(ValueError,'selector identity'):
                list(replay.corpus_units(index,'entry',root/'inputs',root/'refs'))

    def test_changed_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);index,u=self.fixture(root)
            (u['original']/'manifest.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'manifest identity'):
                list(replay.corpus_units(index,'entry',root/'inputs',root/'refs'))
            raw=json.dumps({'cases':[dict(id='c',unit='u')]*2}).encode()
            (u['original']/'manifest.json').write_bytes(raw)
            index['entries']['entry']['manifest_sha256']=replay.verify.sha(raw)
            with self.assertRaisesRegex(ValueError,'not unique'):
                list(replay.corpus_units(index,'entry',root/'inputs',root/'refs'))

    def test_reference_hash_exit_extent_and_predicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);_,u=self.fixture(root)
            calls=[]
            v=SimpleNamespace(storage=SimpleNamespace(verify=lambda p:p.read_bytes()),
                              packet_size=lambda c:6,check_isa=lambda *a:calls.append(a))
            self.assertEqual(replay.retained_inputs(u,v),(b'elf',b'packet',6))
            self.assertEqual(len(calls),1)
            (u['reference']/'packets.bin').write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError,'reference identity'):replay.retained_inputs(u,v)
            (u['reference']/'packets.bin').write_bytes(b'packet')
            v.packet_size=lambda c:5
            with self.assertRaisesRegex(ValueError,'packet extent'):replay.retained_inputs(u,v)
            v.packet_size=lambda c:6
            (u['reference']/'execution.json').write_text(json.dumps({'returncode':1,'timeout':False}))
            with self.assertRaisesRegex(ValueError,'failed retained reference'):replay.retained_inputs(u,v)

    def test_sail_signature_is_not_stdout_and_remains_authenticated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);_,u=self.fixture(root);d=u['reference']
            packet=b'abcdefgh';stdout=b'original Sail transport log'
            (d/'packets.bin').write_bytes(packet);(d/'stdout').write_bytes(stdout)
            (d/'execution.json').write_text(json.dumps(dict(returncode=0,timeout=False,stdout_sha256=replay.verify.sha(stdout))))
            (d/'command.json').write_text(json.dumps(['sail','--test-signature','signature','--signature-granularity','4']))
            signature='\n'.join(format(int.from_bytes(packet[i:i+4],'little'),'08x') for i in (0,4))
            (d/'signature').write_text(signature)
            v=SimpleNamespace(storage=SimpleNamespace(verify=lambda p:p.read_bytes()),packet_size=lambda c:8,check_isa=lambda *a:None)
            self.assertEqual(replay.retained_inputs(u,v),(b'elf',packet,8))
            (d/'signature').write_text('00000000\n00000000')
            with self.assertRaisesRegex(ValueError,'signature/packet'):replay.retained_inputs(u,v)
            (d/'stdout').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'reference identity'):replay.retained_inputs(u,v)

    def test_execution_options_not_rewritten(self):
        saved=['/old/dut','--vlen=4096','--rvv-vector-run=1','--fsroot=/old/fs','--cache=/old/cache','--','/t.elf']
        command=replay.command(saved,Path('/new/dut'),Path('/new/work'))
        self.assertEqual(command,['/new/dut',*saved[1:3],'--fsroot=/new/work/fs','--cache=/new/work/cache','--','/t.elf'])

    def test_compressed_checks_and_legacy_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);_,u=self.fixture(root)
            p=u['reference']/'checks.json'
            Path(str(p)+'.gz').write_bytes(gzip.compress(p.read_bytes()));p.unlink()
            self.assertEqual(replay.acceptance_path(u),p)
            Path(str(p)+'.gz').unlink()
            u['entry']='b171-068'
            ledger=u['reference_corpus']/'results.json'
            ledger.write_text(json.dumps([dict(case='c',arm='Reference',status='PASS',offset=0,size=6)]))
            v=SimpleNamespace(storage=SimpleNamespace(verify=lambda p:p.read_bytes()),
                              packet_size=lambda c:6,check_isa=lambda *a:None)
            self.assertEqual(replay.retained_inputs(u,v),(b'elf',b'packet',6))
            replay.reference_ledger.cache_clear()
            ledger.write_text(json.dumps([dict(case='c',arm='Reference',status='PASS',offset=1,size=6)]))
            with self.assertRaisesRegex(ValueError,'offset/size'):replay.retained_inputs(u,v)

    def test_dump_options_removed_without_changing_semantics(self):
        cmd=replay.command(['/old','--rvv-stats=1','--dump-tbcode=/huge','--dump-tbmap=/old','--','/t.elf'],Path('/new'),Path('/work'))
        self.assertEqual(cmd,['/new','--rvv-stats=1','--','/t.elf'])

    def test_reconcile_never_relaunches_a_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)/'capture';d.mkdir()
            command=['/dut','--vlen=128','--cache=/old','--','/t.elf']
            (d/'command.json').write_text(json.dumps(command))
            with mock.patch.object(replay.storage,'execute',side_effect=AssertionError('must not relaunch')):
                with self.assertRaisesRegex(ValueError,'incomplete launch'):
                    replay.reconcile_or_execute(command,d,{},1)
                for name in ('stdout','stderr'):(d/name).write_bytes(b'raw')
                rec=dict(returncode=0,timeout=False,stdout_sha256=replay.verify.sha(b'raw'),stderr_sha256=replay.verify.sha(b'raw'))
                (d/'execution.json').write_text(json.dumps(rec))
                relocated=['/dut','--vlen=128','--cache=/new','--','/t.elf']
                self.assertEqual(replay.reconcile_or_execute(relocated,d,{},1),(rec,False))
                with self.assertRaisesRegex(ValueError,'changed command'):
                    replay.reconcile_or_execute(['/other',*command[1:]],d,{},1)

    def test_campaign_final_cardinality(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);index,_=self.fixture(root);index['rows']=[{}]
            path=root/'index.json';path.write_text(json.dumps(index))
            engine=root/'dut';engine.write_bytes(b'engine')
            (root/'libdbtjitshared.so').write_bytes(b'library')
            out=root/'campaign';(out/'entry').mkdir(parents=True)
            rows=[dict(unit='u',arm=arm,cases=1) for arm in ('B','M1','M2','BOTH')]
            (out/'entry/summary.json').write_text(json.dumps(dict(results=rows)))
            args=SimpleNamespace(engine=engine,library_dir=root,output=out,cache_dir=root/'scratch',
                all_units=True,raw_root=root/'inputs',reference_root=root/'refs',index=path,
                jobs=2,timeout=120,resume=True)
            proc=SimpleNamespace(pid=42,poll=lambda:0)
            with mock.patch.object(replay.subprocess,'Popen',return_value=proc) as launch:
                self.assertEqual(replay.campaign(args,index),0)
            self.assertEqual(launch.call_count,1)
            final=json.loads((out/'COMPLETE.json').read_text())
            self.assertEqual((final['units'],final['calls'],final['checks']),(1,4,4))

    def test_transitive_snapshot_module_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'snapshot/toy_predicate.py';p.parent.mkdir();p.write_text('# pinned\n')
            pins={p.resolve():replay.digest(p)}
            with mock.patch.dict(replay.sys.modules,{'toy_predicate':SimpleNamespace(__file__=str(p))}):
                self.assertTrue(replay.resolved_modules(pins)['toy_predicate']['match'])
                q=p.with_name('unexpected_dependency.py');q.write_text('# not pinned\n')
                with mock.patch.dict(replay.sys.modules,{'unexpected_dependency':SimpleNamespace(__file__=str(q))}):
                    with self.assertRaisesRegex(ValueError,'outside original pins'):replay.resolved_modules(pins)

    def test_actual_receipt_recount_and_command_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);index,u=self.fixture(root)
            definition=index['entries']['entry']
            definition.update(tools='/recorded/corpus/tools',install='family')
            bindings={}
            for name in ('vadd','family'):
                p=u['original']/'tools'/(name+'.py');p.parent.mkdir(exist_ok=True);p.write_text('# synthetic pinned module\n')
                h=replay.digest(p);definition['tool_pins']['/recorded/corpus/tools/'+p.name]=h
                bindings[name]=dict(path=str(p),sha256=h,expected_sha256=h,match=True)
            path=root/'index.json';path.write_text(json.dumps(index))
            engine=root/'dut';engine.write_bytes(b'engine')
            library=root/'libdbtjitshared.so';library.write_bytes(b'library')
            out=root/'campaign';entry=out/'entry';entry.mkdir(parents=True)
            replay.save(entry/'identity.json',dict(files={str(p.resolve()):replay.digest(p) for p in (engine,library)},index_sha256=replay.digest(path)))
            rows=[]
            for arm in ('B','M1','M2','BOTH'):
                d=entry/'runs/u'/arm;d.mkdir(parents=True)
                original=u['original']/'runs/u'/arm;original.mkdir(parents=True)
                cmd=[str(engine),'--vlen=128','--rvv-stats=1','--','/t.elf']
                replay.save(original/'command.json',cmd);replay.save(d/'command.json',cmd)
                for name in ('stdout','stderr'):(d/name).write_bytes(b'packet')
                replay.save(d/'execution.json',dict(returncode=0,timeout=False,stdout_sha256=replay.verify.sha(b'packet')))
                row=dict(unit='u',arm=arm,cases=1,status='PASS',guest_sha256=u['elf_sha256'],output_sha256=replay.verify.sha(b'packet'))
                replay.save(d/'check.json',row);rows.append(row)
            summary=dict(status='PASS_SELECTED_UNITS',reader=replay.READER,results=rows,new_dut_calls=0,reused_captures=4,checker_modules=bindings)
            replay.save(entry/'summary.json',summary)
            replay.save(entry/'checker-bindings.json',dict(resolved_modules=bindings))
            args=SimpleNamespace(engine=engine,library_dir=root,output=out,entry=None,index=path,raw_root=root/'inputs',reference_root=root/'refs')
            self.assertEqual(replay.audit(args,index),0)
            result=replay.verify.load(out/'AUDIT.json')
            self.assertEqual([result[k] for k in ('forms','units','calls','checks')],[1,1,4,4])
            self.assertEqual(result['rechecked_captures_in_final_entry_invocations'],4)
            with (out/'AUDIT_PER_FORM.csv').open() as stream:
                rows=list(csv.DictReader(stream))
            self.assertEqual(len(rows),1)
            self.assertEqual([rows[0][k] for k in ('units','calls','checks','B_checks')],['1','4','4','1'])
            self.assertIn('--rvv-stats=1',result['method_configurations']['B'][0]['options'])
            original_binding = replay.verify.load(entry/'identity.json')
            replay.save(entry/'identity.json', dict(original_binding, selection=dict(form='vsub.vv')))
            with self.assertRaisesRegex(ValueError, 'audit selection differs'):
                replay.audit(args, index)
            replay.save(entry/'identity.json', original_binding)
            for missing in ({}, {'vadd':bindings['vadd']}, {'family':bindings['family']}):
                with self.subTest(modules=list(missing)):
                    replay.save(entry/'checker-bindings.json',dict(resolved_modules=missing))
                    replay.save(entry/'summary.json',dict(summary,checker_modules=missing))
                    with self.assertRaisesRegex(ValueError,'missing required checker module binding'):replay.audit(args,index)
            replay.save(entry/'summary.json',summary)
            replay.save(entry/'checker-bindings.json',dict(resolved_modules=dict(bindings,wrong=dict(path='/outside/predicate.py',match=True,sha256='x',expected_sha256='x'))))
            with self.assertRaisesRegex(ValueError,'checker module binding'):replay.audit(args,index)
            replay.save(entry/'checker-bindings.json',dict(resolved_modules=bindings))
            replay.save(entry/'runs/u/B/command.json',[str(engine),'--vlen=128','--rvv-stats=0','--','/t.elf'])
            with self.assertRaisesRegex(ValueError,'method command mismatch'):replay.audit(args,index)
            (entry/'runs/u/B/command.json').write_text(json.dumps(cmd))
            (entry/'runs/u/B/stdout').unlink()
            with self.assertRaises(FileNotFoundError):replay.audit(args,index)

    def test_missing_archive_preflight_fails_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);index,u=self.fixture(root)
            (u['reference']/'checks.json').unlink()
            path=root/'index.json';path.write_text(json.dumps(index))
            with self.assertRaises(FileNotFoundError):
                replay.main(['preflight','--index',str(path),'--raw-root',str(root/'inputs'),'--reference-root',str(root/'refs')])
            self.assertFalse((root/'out').exists())

    def test_invalid_bounds_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            for option,value in [('--timeout','0'),('--max-units','0')]:
                with self.assertRaises(SystemExit) as result:
                    replay.main(['run','--raw-root','/missing','--reference-root','/missing',option,value])
                self.assertEqual(result.exception.code,2)


if __name__=='__main__':
    unittest.main()
