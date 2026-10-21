"""Fixed two-source runs, rejection accounting and source-bound human judgements."""
import copy
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

from artemis_v3.evaluation import EvaluationError, digest, encode, run_suite, summarize_ratings
from artemis_v3.semantic import OllamaLocalProvider
from test_v3_semantic import FakeOllama

FIXTURES = Path(__file__).parent / 'fixtures' / 'semantic_eval'


class HistoricalEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sources = self.root / 'sources'
        shutil.copytree(FIXTURES, self.sources)
        self.manifest = self.sources / 'historical_suite.json'
        self.replay = self.sources / 'historical_replay.json'
        self.destination = self.root / 'results'

    def tearDown(self):
        self.temporary.cleanup()

    def replay_run(self, destination=None):
        return run_suite(self.manifest, destination or self.destination, replay_path=self.replay)

    def test_offline_round_trip_preserves_source_identity_scores_and_omissions(self):
        with patch.object(socket, 'create_connection', side_effect=AssertionError('Unexpected network')):
            run = self.replay_run()
        self.assertEqual(run['schema_version'], 'artemis-eval-run/2')
        self.assertEqual(run['summary']['accepted'], 5)
        self.assertEqual(run['summary']['by_context']['with_history']['accepted'], 4)
        self.assertEqual(run['summary']['by_context']['current_only']['accepted'], 1)
        self.assertEqual(run['summary']['critical_negative_proposed'], 1)
        self.assertEqual(run['summary']['critical_negative_blocked'], 1)
        self.assertEqual(run['summary']['base_score_violations'], 0)
        self.assertIn('historical', run['implementation_sha256'])
        self.assertIn('case_store', run['implementation_sha256'])
        rows = {row['case_id']: row for row in run['attempts']}
        comparison = rows['history_comparison']['explanation']
        self.assertEqual(comparison['proposal_review']['adjustment_proposal']['applied_score'], 6)
        self.assertEqual(comparison['proposal_review']['adjustment_proposal']['status'], 'awaiting_analyst_review')
        history = comparison['historical_context']
        self.assertEqual(history['report_sha256'], digest((self.sources / 'history_prior.json').read_bytes()))
        self.assertEqual(history['association'], 'same_report_asserted_sample_sha256')
        self.assertNotIn('ruleset_sha256', history)
        self.assertNotIn('rule_summary', history)
        self.assertEqual([item['source_scope'] for item in comparison['source_observations']], ['current', 'historical'])
        self.assertEqual(comparison['hypotheses'][0]['source_scope'], 'mixed')
        omitted = rows['history_omission']['explanation']
        self.assertEqual(len(omitted['historical_context']['evidence']), 8)
        self.assertGreater(omitted['historical_context']['omitted_evidence_count'], 0)
        self.assertIn(omitted['report_sha256'] + '#/signatures/0', omitted['supplied_evidence_ids'])
        control = rows['single_source_control']['explanation']
        self.assertEqual(control['schema_version'], 'artemis-explanation/1')
        self.assertNotIn('historical_context', control)
        self.assertNotIn('source_scope', control['source_observations'][0])

    def test_mismatched_provenance_identity_and_fingerprints_fail_before_any_model_call(self):
        originals = {path: path.read_bytes() for path in self.sources.glob('*.json')}
        original = json.loads(self.manifest.read_bytes())

        def change_source(case, historical, change):
            source = case['historical'] if historical else case
            path = self.sources / source['report']
            value = json.loads(path.read_bytes()); change(value)
            raw = encode(value); path.write_bytes(raw); source['report_sha256'] = digest(raw)

        mutations = [
            lambda case: case['historical'].update(report_sha256='0'*64),
            lambda case: case['historical'].update(synthetic=False),
            lambda case: case['historical'].update(synthetic=1),
            lambda case: change_source(case, True, lambda value: value['target']['file'].update(sha256='b'*64)),
            lambda case: change_source(case, True, lambda value: value.pop('target')),
            lambda case: change_source(case, False, lambda value: value.pop('target')),
            lambda case: case['historical'].update(report=case['report'], report_sha256=case['report_sha256']),
            lambda case: case['historical'].update(report='/etc/passwd'),
            lambda case: case['historical'].update(report='../outside.json'),
            lambda case: case['historical'].update(ruleset='rules.json'),
        ]

        class NeverCalled:
            model = 'synthetic-never-called'
            def generate(self, context):
                raise AssertionError('Invalid suite reached model')

        for mutation in mutations:
            with self.subTest(mutation=mutation):
                for path, raw in originals.items():
                    path.write_bytes(raw)
                value = copy.deepcopy(original); mutation(value['cases'][0])
                self.manifest.write_bytes(encode(value))
                with self.assertRaises(ValueError):
                    run_suite(self.manifest, self.destination, provider=NeverCalled())
                self.assertFalse(self.destination.exists())

    def test_historical_symlink_escape_is_refused(self):
        path = self.sources / 'history_prior.json'
        outside = self.root / 'outside.json'; outside.write_bytes(path.read_bytes())
        path.unlink(); path.symlink_to(outside)
        with self.assertRaises(EvaluationError):
            self.replay_run()
        self.assertFalse(self.destination.exists())

    def test_historical_bytes_count_toward_total_suite_budget_before_model_calls(self):
        suite = json.loads(self.manifest.read_bytes()); suite['cases'] = suite['cases'][:1]
        self.manifest.write_bytes(encode(suite))
        case = suite['cases'][0]
        current_bytes = len((self.sources / case['report']).read_bytes()) + len((self.sources / case['ruleset']).read_bytes())
        class NeverCalled:
            model = 'synthetic-never-called'
            def generate(self, context):
                raise AssertionError('Over-budget suite reached model')
        with patch('artemis_v3.evaluation.MAX_SUITE_SOURCE_BYTES', current_bytes), self.assertRaisesRegex(EvaluationError, '32 MiB'):
            run_suite(self.manifest, self.destination, provider=NeverCalled())
        self.assertFalse(self.destination.exists())

    def test_mixed_spoofed_unsent_and_historical_adjustment_refs_stay_failures(self):
        original = json.loads(self.replay.read_bytes())
        compare = original['outputs']['history_comparison']
        current = compare['source_observations'][0]['evidence_refs'][0]
        history = compare['source_observations'][1]['evidence_refs'][0]
        suite = json.loads(self.manifest.read_bytes())
        omitted_hash = suite['cases'][3]['historical']['report_sha256']
        changes = [
            ('history_comparison', lambda value: value['source_observations'][0].update(evidence_refs=[current, history])),
            ('history_comparison', lambda value: value['adjustment'].update(cited_evidence=[history])),
            ('history_comparison', lambda value: value['adjustment'].update(cited_evidence=[current, history])),
            ('history_comparison', lambda value: value['source_observations'][1].update(source_scope='current')),
            ('history_omission', lambda value: value['source_observations'][1].update(evidence_refs=[omitted_hash + '#/signatures/24'])),
        ]
        for index, (case_id, change) in enumerate(changes):
            with self.subTest(case_id=case_id, index=index):
                value = copy.deepcopy(original); change(value['outputs'][case_id])
                self.replay.write_bytes(encode(value))
                run = self.replay_run(self.root / str(index))
                self.assertEqual(run['summary']['attempts'], 5)
                self.assertEqual(run['summary']['accepted'], 4)
                self.assertEqual(run['summary']['failed'], 1)
                self.assertEqual(run['summary']['by_context']['with_history']['contract_acceptance_fraction'], 3/4)
                rejected = next(row for row in run['attempts'] if row['case_id'] == case_id)
                self.assertEqual(rejected['status'], 'rejected')
                self.assertIsNone(rejected['explanation'])
                self.assertIsNotNone(rejected['error'])

    def test_human_scope_groups_keep_false_attribution_unreviewed_until_a_person_rates_it(self):
        self.replay_run()
        run_path, review_path = self.destination / 'run.json', self.destination / 'review.json'
        ratings = json.loads(review_path.read_bytes())
        self.assertEqual(ratings['schema_version'], 'artemis-eval-ratings/2')
        initial = summarize_ratings(run_path, review_path)
        for counts in initial['by_source_scope'].values():
            self.assertIsNone(counts['supported_fraction_of_rated'])
            self.assertEqual(counts['coverage'], 0)
        false_claim = next(item for item in ratings['items'] if item['case_id'] == 'history_false_current'
                           and item['section'] == 'source_observations' and item['source_scope'] == 'historical')
        self.assertIn('当前', false_claim['text'])
        self.assertEqual(false_claim['rating'], 'unreviewed')
        false_claim.update(rating='unsupported', reason='引用属于历史报告，不能支持当前成功注入；当前 API status=false。')
        ratings['reviewer'] = 'Declared synthetic reviewer'
        review_path.write_bytes(encode(ratings))
        result = summarize_ratings(run_path, review_path)
        self.assertEqual(result['by_source_scope']['historical']['unsupported'], 1)
        self.assertEqual(result['by_source_scope']['historical']['coverage'], 1/4)
        self.assertEqual(result['by_source_scope']['historical']['supported_fraction_of_rated'], 0)
        self.assertEqual(result['by_source_scope']['current']['reviewed'], 0)
        self.assertEqual(result['by_source_scope']['mixed']['reviewed'], 0)
        false_claim['source_scope'] = 'current'
        review_path.write_bytes(encode(ratings))
        with self.assertRaises(EvaluationError):
            summarize_ratings(run_path, review_path)

    def test_declared_private_two_source_data_refuses_synthetic_replay(self):
        suite = json.loads(self.manifest.read_bytes())
        for case in suite['cases']:
            case['synthetic'] = False
            if case['historical'] is not None:
                case['historical']['synthetic'] = False
        raw = encode(suite); self.manifest.write_bytes(raw)
        replay = json.loads(self.replay.read_bytes()); replay['suite_sha256'] = digest(raw)
        self.replay.write_bytes(encode(replay))
        with self.assertRaises(EvaluationError):
            self.replay_run()
        self.assertFalse(self.destination.exists())

    def test_pinned_local_protocol_repeats_use_production_context_without_reference_notes(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), FakeOllama)
        server.mode, server.requests = 'history_adjustment', []
        thread = Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True); thread.start()
        try:
            provider = OllamaLocalProvider('test', port=server.server_port, timeout=3, expected_digest='a'*64)
            run = run_suite(self.manifest, self.destination, provider=provider, repeat=2)
            self.assertEqual(run['summary']['accepted'], 10)
            self.assertEqual(run['summary']['critical_negative_blocked'], 4)
            contexts = [json.loads(request['messages'][1]['content']) for path, request in server.requests if path == '/api/chat']
            self.assertEqual(len(contexts), 10)
            self.assertEqual(sum('historical_context' in context for context in contexts), 8)
            for context in contexts:
                self.assertNotIn('reference_notes', context)
                self.assertNotIn('expected_base_score', context)
                self.assertNotIn('expected_critical', context)
                history = context.get('historical_context')
                if history:
                    self.assertNotIn('rule_summary', history)
                    self.assertLessEqual(len(context['evidence']) + len(history['evidence']), 32)
                    self.assertLessEqual(len(json.dumps(context, ensure_ascii=False, separators=(',', ':')).encode()), 12*1024)
            server.requests.clear()
            wrong = OllamaLocalProvider('test', port=server.server_port, timeout=3, expected_digest='b'*64)
            refused = run_suite(self.manifest, self.root / 'wrong-model', provider=wrong)
            self.assertEqual(refused['summary']['failed'], 5)
            self.assertFalse(any(path == '/api/chat' for path, _ in server.requests))
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_historical_interruption_retains_partial_v2_run_without_review_template(self):
        outputs = json.loads(self.replay.read_bytes())['outputs']
        class Interrupted:
            model = 'synthetic-interruption'
            calls = 0
            def generate(self, context):
                self.calls += 1
                if self.calls == 2:
                    raise KeyboardInterrupt()
                return {'output': outputs['history_comparison']}
        with self.assertRaises(KeyboardInterrupt):
            run_suite(self.manifest, self.destination, provider=Interrupted())
        partial = json.loads((self.destination / 'run.json').read_bytes())
        self.assertEqual(partial['schema_version'], 'artemis-eval-run/2')
        self.assertEqual(len(partial['attempts']), 1)
        self.assertNotIn('summary', partial)
        self.assertFalse((self.destination / 'review.json').exists())

    def test_cli_creates_v2_artifacts_and_returns_failure_for_rejected_history(self):
        command = [sys.executable, '-m', 'artemis_v3.evaluation', 'run', '--suite', str(self.manifest),
                   '--replay', str(self.replay), '--output-dir', str(self.destination)]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)['by_context']['with_history']['accepted'], 4)
        summary = subprocess.run([sys.executable, '-m', 'artemis_v3.evaluation', 'review',
            '--run', str(self.destination / 'run.json'), '--ratings', str(self.destination / 'review.json')],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(summary.returncode, 0, summary.stderr)
        self.assertEqual(json.loads(summary.stdout)['schema_version'], 'artemis-eval-human-summary/2')
        value = json.loads(self.replay.read_bytes())
        value['outputs']['history_comparison']['adjustment']['cited_evidence'] = [
            value['outputs']['history_comparison']['source_observations'][1]['evidence_refs'][0]]
        self.replay.write_bytes(encode(value))
        command[-1] = str(self.root / 'rejected')
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)['failed'], 1)
