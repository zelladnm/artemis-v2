"""Live loopback HTTP contracts and proposal-to-review integration (synthetic only)."""
import base64
import copy
import http.client
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest

from artemis_v3.proposals import parse_proposal
from artemis_v3.review import ReviewError, list_reviews, record_review
from artemis_v3.workbench import WorkbenchServer, investigate_payload

FIXTURES = Path(__file__).parent / 'fixtures'


def encoded(path):
    return base64.b64encode(path.read_bytes()).decode()


def payload():
    return {'report': encoded(FIXTURES / 'cape_synthetic.json'),
            'ruleset': encoded(FIXTURES / 'scoring_synthetic.json'), 'synthetic': True}


def external_proposal(report, catalog):
    return json.dumps({'schema_version': 'artemis-proposal/1', 'report_sha256': report.source_sha256,
                       'ruleset_sha256': catalog.source_sha256, 'ruleset_version': catalog.version,
                       'proposed_delta': -1, 'cited_evidence': [report.evidence[-1].evidence_id],
                       'rationale': 'Synthetic contextual review'}).encode()


class WorkbenchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.database = Path(cls.temp.name) / 'reviews.sqlite'
        cls.server = WorkbenchServer(0, review_db=cls.database)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()
        cls.temp.cleanup()

    def request(self, path='/', data=None, *, headers=None, method=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        headers = {'X-Artemis-Token': self.server.token, **(headers or {})}
        body = None if data is None else json.dumps(data).encode()
        if body is not None:
            headers.setdefault('Content-Type', 'application/json')
        connection.request(method or ('GET' if body is None else 'POST'), path, body=body, headers=headers)
        response = connection.getresponse()
        status, response_headers, raw = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return status, response_headers, raw

    def test_static_and_demo_assets_have_no_external_dependencies(self):
        status, headers, raw = self.request()
        self.assertEqual(status, 200)
        self.assertIn(self.server.token.encode(), raw)
        self.assertNotIn(b'__ARTEMIS_TOKEN__', raw)
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertNotIn('Access-Control-Allow-Origin', headers)
        for path in ('/app.js', '/style.css', '/api/demo'):
            self.assertEqual(self.request(path)[0], 200)
        self.assertEqual(self.server.server_address[0], '127.0.0.1')

    def test_origin_host_and_token_protection(self):
        for headers in ({'Host': 'hostile.example'}, {'Origin': 'https://hostile.example'},
                        {'X-Artemis-Token': 'wrong'}, {'Sec-Fetch-Site': 'cross-site'},
                        {'X-Artemis-Token': 'é'}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request('/api/analyze', payload(), headers=headers)[0], 403)
        self.assertEqual(self.request('/api/demo', headers={'X-Artemis-Token': ''})[0], 403)
        self.assertEqual(self.request('/api/analyze', payload(), headers={'Origin': self.server.origin})[0], 200)

    def test_analyze_retains_exact_sources_and_does_not_create_store(self):
        status, _, raw = self.request('/api/analyze', payload())
        result = json.loads(raw)
        self.assertEqual(status, 200)
        self.assertEqual(result['model_status'], 'not_configured')
        self.assertEqual(result['rule_assessment']['base_score'], 1)
        self.assertEqual(result['report']['schema_version'], 'cape-evidence/3')
        self.assertEqual(len(result['report']['timeline']['report_clock']), 2)
        self.assertFalse(self.database.exists())

    def test_report_only_and_proposal_requirements(self):
        self.assertEqual(self.request('/api/analyze', {'report': payload()['report']})[0], 200)
        for value in ({'report': 'not base64!'}, {'report': payload()['report'], 'synthetic': 'yes'},
                      {'report': payload()['report'], 'proposal': 'e30='}, [], None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                investigate_payload(value)

    def test_request_limits_routes_and_content_type(self):
        self.assertEqual(self.request('/api/analyze', {}, headers={'Content-Length': '16000000'})[0], 413)
        self.assertEqual(self.request('/api/analyze', {}, headers={'Content-Type': 'text/plain'})[0], 400)
        self.assertEqual(self.request('/../../etc/passwd')[0], 404)
        self.assertEqual(self.request('/api/unknown', {})[0], 404)

    def test_z_review_roundtrip_is_bound_to_imported_proposal(self):
        data = payload()
        _, report, catalog, _ = investigate_payload(data)
        raw_proposal = external_proposal(report, catalog)
        data['proposal'] = base64.b64encode(raw_proposal).decode()
        result, _, _, packet = investigate_payload(data)
        adjustment = packet['adjustment_proposal']
        request = {'source_sha256': report.source_sha256, 'ruleset_sha256': catalog.source_sha256,
                   'delta': adjustment['proposed_delta'], 'cited_evidence': list(adjustment['cited_evidence']),
                   'rationale': adjustment['rationale'], 'reviewer': 'synthetic analyst', 'decision': 'reject',
                   'reason': 'Synthetic test decision', 'expected_previous_id': None}
        data['review_request'] = {**request, 'delta': 0}
        self.assertEqual(self.request('/api/review', data)[0], 400)
        self.assertFalse(self.database.exists())
        data['review_request'] = request
        status, _, raw = self.request('/api/review', data)
        record = json.loads(raw)['analyst_review']
        self.assertEqual(status, 200)
        self.assertEqual(record['external_proposal_sha256'], packet['proposal_sha256'])
        self.assertEqual(record['base_score'], 1)
        history = json.loads(self.request('/api/history')[2])['reviews']
        self.assertEqual(history, [record])
        self.assertEqual(self.request('/api/review', data)[0], 400)  # stale duplicate rejected

    def test_readonly_server_rejects_review_writes(self):
        readonly = WorkbenchServer(0)
        thread = Thread(target=readonly.serve_forever, daemon=True); thread.start()
        try:
            connection = http.client.HTTPConnection('127.0.0.1', readonly.server_port, timeout=5)
            connection.request('POST', '/api/review', body=json.dumps(payload()),
                               headers={'X-Artemis-Token': readonly.token, 'Content-Type': 'application/json'})
            response = connection.getresponse()
            self.assertEqual(response.status, 409); response.read(); connection.close()
        finally:
            readonly.shutdown(); readonly.server_close(); thread.join()
