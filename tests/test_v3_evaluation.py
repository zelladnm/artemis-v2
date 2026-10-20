"""Synthetic evaluation provenance, failure accounting, human ratings and local HTTP."""
import contextlib
import copy
from http.server import ThreadingHTTPServer
import io
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

from artemis_v3.evaluation import (
    EvaluationError, digest, encode, load_suite, main, run_suite, summarize_ratings,
)
from artemis_v3.semantic import OllamaLocalProvider
from artemis_v3.semantic import explain as production_explain
from test_v3_semantic import FakeOllama

FIXTURES = Path(__file__).parent / 'fixtures' / 'semantic_eval'


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.suite = self.root / 'suite'
        shutil.copytree(FIXTURES, self.suite)
        self.manifest = self.suite / 'suite.json'
        self.replay = self.suite / 'replay.json'
        self.destination = self.root / 'results'

    def tearDown(self):
        self.temporary.cleanup()

    def run_replay(self):
        return run_suite(self.manifest, self.destination, replay_path=self.replay)

    def change_json(self, path, change):
        value = json.loads(path.read_bytes()); change(value); path.write_bytes(encode(value))

    def test_offline_provenance_critical_gates_and_omission(self):
        with patch.object(socket, 'create_connection', side_effect=AssertionError('Unexpected network')):
            run = self.run_replay()
        self.assertEqual(run['mode'], 'synthetic_replay')
        self.assertEqual(run['summary']['accepted'], 6)
        self.assertEqual(run['summary']['critical_negative_proposed'], 2)
        self.assertEqual(run['summary']['critical_negative_blocked'], 2)
        self.assertEqual(run['summary']['base_score_violations'], 0)
        self.assertIsNone(run['summary']['human_factual_support'])
        self.assertEqual(run['suite_sha256'], digest(self.manifest.read_bytes()))
        self.assertIn('semantic', run['implementation_sha256'])
        omission = next(row for row in run['attempts'] if row['case_id'] == 'context_omission')['explanation']
        self.assertGreater(omission['omitted_evidence_count'], 0)
        self.assertTrue(any(ref.endswith('#/signatures/80') for ref in omission['supplied_evidence_ids']))
        ratings = json.loads((self.destination / 'review.json').read_bytes())
        self.assertEqual(ratings['run_sha256'], digest((self.destination / 'run.json').read_bytes()))
        # A valid citation with an intentionally false success claim remains unjudged.
        false_claim = next(item for item in ratings['items'] if item['case_id'] == 'failed_api' and item['section'] == 'source_observations')
        self.assertIn('成功', false_claim['text']); self.assertEqual(false_claim['rating'], 'unreviewed')

    def test_rejected_output_does_not_abort_or_inflate_success(self):
        self.change_json(self.replay, lambda value: value['outputs']['installer']['source_observations'][0].update(evidence_refs=['invented']))
        run = self.run_replay()
        self.assertEqual(run['summary']['accepted'], 5)
        self.assertEqual(run['summary']['failed'], 1)
        self.assertEqual(run['attempts'][0]['status'], 'rejected')
        self.assertIsNone(run['attempts'][0]['explanation'])
        self.assertEqual(len(run['attempts']), 6)
        self.assertTrue((self.destination / 'review.json').is_file())

    def test_gate_regressions_are_counted_as_failures(self):
        def broken_gate(*args, **kwargs):
            result, suggestion = production_explain(*args, **kwargs)
            packet = result['proposal_review']
            if packet:
                proposal = packet['adjustment_proposal']
                proposal['applied_score'] = proposal['proposed_score']
                proposal['status'] = 'awaiting_analyst_review'
            return result, suggestion
        with patch('artemis_v3.evaluation.explain', side_effect=broken_gate):
            run = self.run_replay()
        self.assertEqual(run['summary']['failed'], 3)
        self.assertEqual(run['summary']['base_score_violations'], 3)
        self.assertEqual(run['summary']['critical_negative_proposed'], 2)
        self.assertEqual(run['summary']['critical_negative_blocked'], 0)
        self.assertEqual(run['attempts'][0]['status'], 'checks_failed')

    def test_suite_sources_expectations_and_replay_are_bound_before_model_calls(self):
        mutations = [
            lambda value: value['cases'][0].update(report_sha256='0'*64),
            lambda value: value['cases'][0].update(ruleset_sha256='0'*64),
            lambda value: value['cases'][0].update(expected_base_score=0),
            lambda value: value['cases'][0].update(expected_critical=True),
            lambda value: value['cases'][0].update(synthetic='yes'),
            lambda value: value['cases'][1].update(case_id=value['cases'][0]['case_id']),
            lambda value: value['cases'][0].update(report='../outside.json'),
        ]
        original = self.manifest.read_bytes()
        class Uncalled:
            model = 'not-called'
            def generate(self, context):
                raise AssertionError('Invalid suite must not reach a model')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.manifest.write_bytes(original); self.change_json(self.manifest, mutation)
                with self.assertRaises(EvaluationError):
                    run_suite(self.manifest, self.destination, provider=Uncalled())
                self.assertFalse(self.destination.exists())
        self.manifest.write_bytes(original)
        self.change_json(self.replay, lambda value: value.update(suite_sha256='0'*64))
        with self.assertRaises(EvaluationError):
            self.run_replay()
        self.assertFalse(self.destination.exists())

    def test_synthetic_replay_cannot_relabel_nonsynthetic_sources(self):
        self.change_json(self.manifest, lambda value: value['cases'][0].update(synthetic=False))
        with self.assertRaises(EvaluationError):
            self.run_replay()
        self.assertFalse(self.destination.exists())

    def test_symlink_escape_duplicate_json_and_byte_limits(self):
        outside = self.root / 'outside.json'; outside.write_bytes((self.suite / 'installer.json').read_bytes())
        (self.suite / 'installer.json').unlink(); (self.suite / 'installer.json').symlink_to(outside)
        with self.assertRaises(EvaluationError):
            load_suite(self.manifest)
        self.manifest.write_bytes(b'{"name":"a","name":"b"}')
        with self.assertRaises(EvaluationError):
            load_suite(self.manifest)
        self.manifest.write_bytes(b' '*65537)
        with self.assertRaises(EvaluationError):
            load_suite(self.manifest)

    def test_output_refuses_overwrite_and_replay_repetition(self):
        self.destination.mkdir(); original = self.destination / 'run.json'; original.write_text('keep')
        with self.assertRaises(FileExistsError):
            self.run_replay()
        self.assertEqual(original.read_text(), 'keep')
        for repeat in (0, 6, True, 2):
            with self.subTest(repeat=repeat), self.assertRaises(EvaluationError):
                run_suite(self.manifest, self.root / 'unused', replay_path=self.replay, repeat=repeat)
        self.assertFalse((self.root / 'unused').exists())

    def test_interruption_leaves_partial_run_without_final_ratings(self):
        replay = json.loads(self.replay.read_bytes())['outputs']
        class Interrupted:
            model = 'synthetic-interruption'
            calls = 0
            def generate(self, context):
                self.calls += 1
                if self.calls == 2:
                    raise KeyboardInterrupt()
                return {'output': replay['installer']}
        with self.assertRaises(KeyboardInterrupt):
            run_suite(self.manifest, self.destination, provider=Interrupted())
        partial = json.loads((self.destination / 'run.json').read_bytes())
        self.assertEqual(len(partial['attempts']), 1)
        self.assertNotIn('summary', partial)
        self.assertFalse((self.destination / 'review.json').exists())
        with self.assertRaises(EvaluationError):
            summarize_ratings(self.destination / 'run.json', self.replay)

    def test_human_ratings_keep_unknowns_and_denominators_explicit(self):
        self.run_replay()
        run_path, ratings_path = self.destination / 'run.json', self.destination / 'review.json'
        initial = summarize_ratings(run_path, ratings_path)
        for section in initial['by_section'].values():
            self.assertIsNone(section['supported_fraction_of_rated'])
            self.assertEqual(section['coverage'], 0)
        ratings = json.loads(ratings_path.read_bytes()); ratings['reviewer'] = 'Declared synthetic reviewer'
        for item in ratings['items']:
            if item['case_id'] == 'failed_api' and item['section'] == 'source_observations':
                item.update(rating='unsupported', reason='Source status=false and return_value=0 do not support success.')
            if item['case_id'] == 'sparse' and item['section'] == 'hypotheses':
                item.update(rating='uncertain', reason='Insufficient source coverage to judge the premise.')
        ratings_path.write_bytes(encode(ratings))
        summary = summarize_ratings(run_path, ratings_path)
        observations = summary['by_section']['source_observations']
        self.assertEqual(observations['unsupported'], 1); self.assertEqual(observations['unreviewed'], 5)
        self.assertEqual(observations['coverage'], 1/6)
        self.assertEqual(observations['supported_fraction_of_rated'], 0)
        self.assertEqual(summary['by_section']['hypotheses']['uncertain'], 1)
        self.assertEqual(summary['mode'], 'synthetic_replay')

    def test_ratings_reject_stale_modified_duplicate_or_unattributed_claims(self):
        self.run_replay()
        run_path, ratings_path = self.destination / 'run.json', self.destination / 'review.json'
        original = ratings_path.read_bytes()
        mutations = [
            lambda v: v.update(run_sha256='0'*64),
            lambda v: v['items'][0].update(text='Modified claim'),
            lambda v: v['items'].pop(),
            lambda v: v['items'].__setitem__(1, copy.deepcopy(v['items'][0])),
            lambda v: v['items'][0].update(rating='supported', reason='Unauthored decision'),
            lambda v: v.update(reviewer='analyst') or v['items'][0].update(rating='supported'),
            lambda v: v['items'][0].update(rating='safe'),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                ratings_path.write_bytes(original); self.change_json(ratings_path, mutation)
                with self.assertRaises(EvaluationError):
                    summarize_ratings(run_path, ratings_path)

    def test_cli_exit_codes_outputs_and_digest_requirement(self):
        args = [sys.executable, '-m', 'artemis_v3.evaluation', 'run', '--suite', str(self.manifest),
                '--replay', str(self.replay), '--output-dir', str(self.destination)]
        completed = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)['accepted'], 6)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(['run', '--suite', str(self.manifest), '--ollama-model', 'test', '--output-dir', str(self.root / 'uncreated')])
        self.assertEqual(raised.exception.code, 2)
        self.assertFalse((self.root / 'uncreated').exists())
        self.change_json(self.replay, lambda value: value['outputs']['installer'].update(verdict='safe'))
        args[-1] = str(self.root / 'rejected')
        completed = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)['failed'], 1)

    def test_repeated_local_protocol_runs_with_pinned_artifact_and_hidden_annotations(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), FakeOllama)
        server.mode, server.requests = 'adjustment', []
        thread = Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True); thread.start()
        try:
            provider = OllamaLocalProvider('test', port=server.server_port, timeout=3, expected_digest='a'*64)
            run = run_suite(self.manifest, self.destination, provider=provider, repeat=2)
            self.assertEqual(run['mode'], 'local_model')
            self.assertEqual(run['summary']['accepted'], 12)
            self.assertEqual(run['summary']['critical_negative_proposed'], 6)
            self.assertEqual(run['summary']['critical_negative_blocked'], 6)
            self.assertEqual(run['requested_model_digest'], 'a'*64)
            ratings = json.loads((self.destination / 'review.json').read_bytes())
            self.assertEqual(len({item['claim_id'] for item in ratings['items']}), len(ratings['items']))
            contexts = [json.loads(request['messages'][1]['content']) for path, request in server.requests if path == '/api/chat']
            self.assertEqual(len(contexts), 12)
            self.assertTrue(all('reference_notes' not in context and 'expected_base_score' not in context for context in contexts))
            for variation in run['summary']['output_variation'].values():
                self.assertEqual(variation['completed_outputs'], 2)
                self.assertEqual(variation['distinct_outputs'], 1)
                self.assertEqual(variation['model_digests'], ['a'*64])
            server.requests.clear()
            provider = OllamaLocalProvider('test', port=server.server_port, timeout=3, expected_digest='b'*64)
            refused = run_suite(self.manifest, self.root / 'wrong-model', provider=provider)
            self.assertEqual(refused['summary']['failed'], 6)
            self.assertFalse(any(path == '/api/chat' for path, _ in server.requests))
        finally:
            server.shutdown(); server.server_close(); thread.join()
