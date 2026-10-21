"""Local source copying, independent annotations and model-free production preflight."""
import copy
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from artemis_v3.evaluation import (
    EvaluationError, check_suite, digest, encode, prepare_suite, run_suite,
)

FIXTURES = Path(__file__).parent / 'fixtures' / 'semantic_eval'


class NeverCalled:
    model = 'synthetic-never-called'
    def generate(self, context):
        raise AssertionError('Preparation or invalid input reached a model')


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.report = self.root / '本地 报告.json'
        # Exact-byte identity must survive encoding and newline differences.
        raw = (FIXTURES / 'history_current.json').read_bytes()
        self.report.write_bytes(b'\xef\xbb\xbf' + raw.replace(b'\n', b'\r\n'))
        self.rules = self.root / 'local rules.json'
        self.rules.write_bytes((FIXTURES / 'rules.json').read_bytes())
        self.history = self.root / 'historical.json'
        self.history.write_bytes((FIXTURES / 'history_prior.json').read_bytes())
        self.destination = self.root / 'prepared'

    def tearDown(self):
        self.temporary.cleanup()

    def prepare(self, **kwargs):
        return prepare_suite(self.report, self.rules, self.destination, case_id='local_case', **kwargs)

    def annotate(self, score=6, critical=False):
        path = self.destination / 'suite.json'
        suite = json.loads(path.read_bytes())
        suite['cases'][0].update(expected_base_score=score, expected_critical=critical,
            reference_notes='Independent synthetic reference: inspect current API failure and distinguish prior assertions.')
        path.write_bytes(encode(suite))
        return path

    def test_default_private_draft_preserves_exact_sources_and_leaves_expectations_blank(self):
        with patch.object(socket, 'create_connection', side_effect=AssertionError('Unexpected network')):
            packet = self.prepare()
        suite = json.loads((self.destination / 'suite.json').read_bytes())
        case = suite['cases'][0]
        self.assertFalse(case['synthetic'])
        self.assertIsNone(case['historical'])
        self.assertIsNone(case['expected_base_score'])
        self.assertIsNone(case['expected_critical'])
        self.assertEqual(case['reference_notes'], '')
        self.assertEqual((self.destination / case['report']).read_bytes(), self.report.read_bytes())
        self.assertEqual((self.destination / case['ruleset']).read_bytes(), self.rules.read_bytes())
        self.assertEqual(case['report_sha256'], digest(self.report.read_bytes()))
        self.assertEqual(packet['draft_suite_sha256'], digest((self.destination / 'suite.json').read_bytes()))
        self.assertEqual(packet['status'], 'draft')
        self.assertFalse(packet['model_called'])
        self.assertEqual(packet['observed_rule_result']['base_score'], 6)
        self.assertTrue(packet['ruleset']['synthetic'])  # Source/catalog labels remain separate.
        self.assertEqual(packet['current_source']['sample_identity_kind'], 'report_asserted')
        self.assertEqual(packet['current_source']['category_counts']['api_call'], 1)
        self.assertNotIn(str(self.report), json.dumps(packet))
        self.assertEqual(json.loads((self.destination / 'preparation.json').read_bytes()), packet)

    def test_history_preview_matches_the_context_actually_sent_after_manual_annotation(self):
        packet = self.prepare(historical_path=self.history, synthetic=True)
        manifest = self.annotate()
        preview = json.loads((self.destination / 'model-context.json').read_bytes())
        snapshot = packet['context_preflight']['snapshot']
        self.assertEqual(snapshot['file_sha256'], digest((self.destination / snapshot['path']).read_bytes()))
        self.assertEqual((self.destination / 'sources/historical-report.json').read_bytes(), self.history.read_bytes())
        class Capture:
            model = 'synthetic-capture'
            def generate(self, context):
                self.context = copy.deepcopy(context)
                ref = context['evidence'][0]['evidence_id']
                return {'output': {'source_observations': [{'text': 'Synthetic assertion.', 'evidence_refs': [ref]}],
                    'hypotheses': [], 'limitations': ['Synthetic protocol only.'], 'adjustment': None}}
        provider = Capture()
        with patch.object(socket, 'create_connection', side_effect=AssertionError('Unexpected network')):
            checked = check_suite(manifest)
            run = run_suite(manifest, self.root / 'run', provider=provider)
        self.assertTrue(checked['ready'])
        self.assertFalse(checked['model_called'])
        self.assertEqual(run['summary']['accepted'], 1)
        self.assertEqual(packet['implementation_sha256'], run['implementation_sha256'])
        self.assertEqual(checked['implementation_sha256'], run['implementation_sha256'])
        self.assertEqual(provider.context, preview)
        self.assertEqual(checked['cases'][0]['context_preflight']['current_evidence_ids'],
                         packet['context_preflight']['current_evidence_ids'])
        self.assertEqual(checked['cases'][0]['historical_report_sha256'], digest(self.history.read_bytes()))
        self.assertNotIn('reference_notes', preview)
        self.assertNotIn('expected_base_score', preview)

    def test_draft_refuses_check_and_run_before_any_model_or_result_creation(self):
        self.prepare()
        manifest = self.destination / 'suite.json'
        for partial in ({}, {'expected_base_score': 6}, {'expected_base_score': 6, 'expected_critical': False}):
            suite = json.loads(manifest.read_bytes()); suite['cases'][0].update(partial)
            manifest.write_bytes(encode(suite))
            with self.subTest(partial=partial), self.assertRaisesRegex(EvaluationError, 'Draft suite'):
                check_suite(manifest)
            with self.assertRaises(EvaluationError):
                run_suite(manifest, self.root / 'never-created', provider=NeverCalled())
        self.assertFalse((self.root / 'never-created').exists())

    def test_wrong_human_expectation_is_reported_without_rewriting_it(self):
        self.prepare()
        manifest = self.annotate(score=5)
        original = manifest.read_bytes()
        with self.assertRaisesRegex(EvaluationError, 'Rule assessment differs'):
            check_suite(manifest)
        self.assertEqual(manifest.read_bytes(), original)

    def test_changed_original_is_not_followed_and_tampered_copies_fail_fingerprint_check(self):
        self.prepare(historical_path=self.history)
        manifest = self.annotate()
        self.report.write_bytes(b'original report changed')
        self.history.write_bytes(b'original history changed')
        self.assertTrue(check_suite(manifest)['ready'])
        for relative in ('sources/report.json', 'sources/historical-report.json', 'sources/ruleset.json'):
            path = self.destination / relative; original = path.read_bytes()
            self.assertFalse(path.is_symlink())
            path.write_bytes(original + b' ')
            with self.subTest(relative=relative), self.assertRaisesRegex(EvaluationError, 'fingerprint'):
                check_suite(manifest)
            path.write_bytes(original)

    def test_invalid_identity_structure_and_provenance_fail_before_creating_output(self):
        original_report, original_rules, original_history = self.report.read_bytes(), self.rules.read_bytes(), self.history.read_bytes()
        mutations = [
            lambda: self.report.write_bytes(b'{"signatures":[],"signatures":[]}'),
            lambda: self.rules.write_bytes(b'{}'),
            lambda: self.history.write_bytes(original_report),
            lambda: self.history.write_bytes(encode({'target': {'file': {'sha256': 'b'*64}}, 'signatures': []})),
            lambda: self.report.write_bytes(b'{"signatures":[]}'),
        ]
        for mutation in mutations:
            self.report.write_bytes(original_report); self.rules.write_bytes(original_rules); self.history.write_bytes(original_history)
            mutation()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.prepare(historical_path=self.history)
            self.assertFalse(self.destination.exists())
        self.report.write_bytes(original_report); self.rules.write_bytes(original_rules)
        for options in ({'case_id': '../escape'}, {'name': ' '}, {'synthetic': 1}):
            arguments = {'case_id': 'case', **options}
            with self.subTest(options=options), self.assertRaises(ValueError):
                prepare_suite(self.report, self.rules, self.destination, **arguments)
            self.assertFalse(self.destination.exists())

    def test_input_and_combined_byte_limits_are_checked_before_output_creation(self):
        current_bytes = len(self.report.read_bytes()) + len(self.rules.read_bytes())
        for setting, value in (('MAX_BYTES', 10), ('MAX_RULESET_BYTES', 10), ('MAX_SUITE_SOURCE_BYTES', current_bytes)):
            with self.subTest(setting=setting), patch('artemis_v3.evaluation.' + setting, value), self.assertRaises(EvaluationError):
                self.prepare(historical_path=self.history)
            self.assertFalse(self.destination.exists())
        with self.assertRaises(EvaluationError):
            prepare_suite(self.root, self.rules, self.destination, case_id='directory_input')
        self.assertFalse(self.destination.exists())

    def test_empty_evidence_is_profiled_but_context_preflight_stays_blocked(self):
        self.report.write_bytes(b'{"signatures":[]}')
        packet = self.prepare()
        self.assertFalse(packet['context_preflight']['ready'])
        self.assertEqual(packet['current_source']['evidence_count'], 0)
        self.assertGreater(packet['current_source']['coverage_warning_count'], 0)
        self.assertFalse((self.destination / 'model-context.json').exists())
        manifest = self.annotate(score=0)
        checked = check_suite(manifest)
        self.assertFalse(checked['ready'])
        self.assertEqual(checked['cases'][0]['current_evidence_count'], 0)
        self.assertGreater(checked['cases'][0]['current_coverage_warning_count'], 0)
        self.assertTrue(checked['cases'][0]['current_coverage_warnings'])
        run = run_suite(manifest, self.root / 'rejected', provider=NeverCalled())
        self.assertEqual(run['summary']['failed'], 1)
        self.assertEqual(run['summary']['accepted'], 0)

    def test_oversize_critical_context_is_not_silently_reduced_to_a_ready_preview(self):
        self.report.write_bytes(encode({'signatures': [{'name': 'synthetic_critical_assertion', 'description': 'x'*20000}]}))
        packet = self.prepare()
        self.assertEqual(packet['observed_rule_result']['base_score'], 8)
        self.assertTrue(packet['observed_rule_result']['critical_signals_present'])
        self.assertFalse(packet['context_preflight']['ready'])
        self.assertFalse((self.destination / 'model-context.json').exists())
        self.assertFalse(check_suite(self.annotate(score=8, critical=True))['ready'])

    def test_existing_destinations_and_symlinks_are_preserved(self):
        self.destination.mkdir()
        sentinel = self.destination / 'keep'; sentinel.write_bytes(b'keep')
        before = self.report.read_bytes()
        with self.assertRaises(FileExistsError):
            self.prepare()
        for name, target in (('existing-link', self.destination), ('broken-link', self.root / 'absent')):
            path = self.root / name; path.symlink_to(target, target_is_directory=True)
            with self.subTest(name=name), self.assertRaises(FileExistsError):
                prepare_suite(self.report, self.rules, path, case_id='case')
            self.assertTrue(path.is_symlink())
        with self.assertRaises(FileExistsError):
            prepare_suite(self.report, self.rules, self.report, case_id='case')
        self.assertEqual(self.report.read_bytes(), before)
        self.assertEqual(sentinel.read_bytes(), b'keep')

    def test_cli_private_defaults_draft_gate_and_annotated_preflight(self):
        prepared = subprocess.run([sys.executable, '-m', 'artemis_v3.evaluation', 'prepare',
            '--report', str(self.report), '--ruleset', str(self.rules), '--historical-report', str(self.history),
            '--case-id', 'local_case', '--output-dir', str(self.destination)], capture_output=True, text=True, timeout=10)
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        self.assertFalse(json.loads(prepared.stdout)['current_source']['synthetic'])
        command = [sys.executable, '-m', 'artemis_v3.evaluation', 'check', '--suite', str(self.destination / 'suite.json')]
        draft = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(draft.returncode, 2)
        self.assertIn('Draft suite', draft.stderr)
        self.annotate()
        ready = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(ready.returncode, 0, ready.stderr)
        self.assertTrue(json.loads(ready.stdout)['ready'])
        self.assertFalse(json.loads(ready.stdout)['model_called'])

    def test_cli_context_failure_returns_one_and_legacy_suite_still_checks(self):
        self.report.write_bytes(b'{"signatures":[]}')
        self.prepare(); manifest = self.annotate(score=0)
        failed = subprocess.run([sys.executable, '-m', 'artemis_v3.evaluation', 'check', '--suite', str(manifest)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(failed.returncode, 1, failed.stderr)
        self.assertFalse(json.loads(failed.stdout)['ready'])
        for name, count in (('suite.json', 6), ('historical_suite.json', 5)):
            with self.subTest(name=name), patch.object(socket, 'create_connection', side_effect=AssertionError('Unexpected network')):
                checked = check_suite(FIXTURES / name)
            self.assertTrue(checked['ready'])
            self.assertEqual(len(checked['cases']), count)
