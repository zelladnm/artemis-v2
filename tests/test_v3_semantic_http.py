"""Semantic endpoint success/failure isolation over real loopback HTTP."""
import base64
import http.client
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest

from artemis_v3.semantic import OllamaLocalProvider
from artemis_v3.workbench import WorkbenchServer
from test_v3_semantic import FakeOllama, ThreadingHTTPServer

FIXTURES = Path(__file__).parent / 'fixtures'


class SemanticHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ollama = ThreadingHTTPServer(('127.0.0.1', 0), FakeOllama)
        self.ollama.mode, self.ollama.requests = 'valid', []
        self.model_thread = Thread(target=lambda: self.ollama.serve_forever(poll_interval=0.01), daemon=True)
        self.model_thread.start()
        provider = OllamaLocalProvider('test', port=self.ollama.server_port, timeout=3)
        self.db = Path(self.temp.name) / 'reviews.sqlite'
        self.server = WorkbenchServer(0, review_db=self.db, semantic_provider=provider)
        self.thread = Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)
        self.thread.start()
        self.payload = {key: base64.b64encode((FIXTURES / name).read_bytes()).decode() for key, name in
                        [('report', 'cape_synthetic.json'), ('ruleset', 'scoring_synthetic.json')]}
        self.payload['synthetic'] = True
    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.ollama.shutdown(); self.ollama.server_close(); self.model_thread.join()
        self.temp.cleanup()
    def request(self, path, payload=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        connection.request('GET' if payload is None else 'POST', path,
                           body=json.dumps(payload) if payload is not None else None,
                           headers={'Content-Type': 'application/json', 'X-Artemis-Token': self.server.token})
        response = connection.getresponse(); value = json.loads(response.read())
        status = response.status; connection.close()
        return status, value

    def test_startup_and_analyze_do_not_send_report_to_model(self):
        self.assertEqual(self.ollama.requests, [])
        config = self.request('/api/config')[1]
        self.assertTrue(config['model_enabled'])
        self.assertEqual(config['model'], 'test:latest')
        self.assertEqual(self.request('/api/analyze', self.payload)[1]['model_status'], 'configured')
        self.assertEqual(self.ollama.requests, [])
        self.assertFalse(self.db.exists())

    def test_explanation_is_explicit_and_preserves_deterministic_score(self):
        status, value = self.request('/api/explain', self.payload)
        self.assertEqual(status, 200)
        self.assertEqual(value['model_status'], 'completed')
        self.assertEqual(value['rule_assessment']['base_score'], 1)
        self.assertEqual(value['semantic_review']['verdict'], 'not_assessed')
        self.assertFalse(self.db.exists())

    def test_invalid_model_output_degrades_without_losing_evidence(self):
        for mode in ('invalid_refs', 'incomplete', 'remote'):
            self.ollama.mode = mode
            status, value = self.request('/api/explain', self.payload)
            with self.subTest(mode=mode):
                self.assertEqual(status, 200)
                self.assertEqual(value['model_status'], 'failed')
                self.assertIn('semantic_error', value)
                self.assertEqual(len(value['report']['evidence']), 9)
                self.assertEqual(value['rule_assessment']['base_score'], 1)
                self.assertNotIn('semantic_review', value)
        self.assertFalse(self.db.exists())

    def test_model_proposal_requires_explicit_review_before_persistence(self):
        self.ollama.mode = 'adjustment'
        _, value = self.request('/api/explain', self.payload)
        self.assertFalse(self.db.exists())
        proposal = json.loads(base64.b64decode(value['suggestion_file_b64']))
        self.assertEqual(proposal['proposed_delta'], -1)
        request = {'source_sha256': value['report']['source_sha256'], 'ruleset_sha256': value['ruleset_sha256'],
                   'delta': -1, 'cited_evidence': proposal['cited_evidence'], 'rationale': proposal['rationale'],
                   'decision': 'defer', 'reason': 'Needs analyst verification', 'reviewer': 'synthetic analyst',
                   'expected_previous_id': None}
        status, reviewed = self.request('/api/review', {**self.payload, 'proposal': value['suggestion_file_b64'],
                                                       'review_request': request})
        self.assertEqual(status, 200)
        self.assertIsNone(reviewed['analyst_review']['analyst_score'])
        self.assertEqual(reviewed['analyst_review']['base_score'], 1)
        self.assertEqual(reviewed['analyst_review']['external_proposal_sha256'],
                         value['semantic_review']['proposal_review']['proposal_sha256'])

    def test_unconfigured_model_and_bad_selected_evidence(self):
        provider = self.server.semantic_provider
        self.server.semantic_provider = None
        self.assertEqual(self.request('/api/explain', self.payload)[0], 409)
        self.server.semantic_provider = provider
        status, value = self.request('/api/explain', {**self.payload, 'explanation_evidence_ids': ['invented']})
        self.assertEqual(status, 200)
        self.assertEqual(value['model_status'], 'failed')
        self.assertEqual(self.ollama.requests, [])
