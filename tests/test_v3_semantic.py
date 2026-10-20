"""Semantic schema/scope tests and a real loopback fake Ollama contract. No real model."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import Thread
import unittest
from unittest.mock import patch

from artemis_v3.cape import load_cape_report, parse_cape_report
from artemis_v3.ruleset import RuleSet, load_ruleset
from artemis_v3.scoring import SignatureRule
from artemis_v3.semantic import SemanticError, OllamaLocalProvider, build_context, explain

FIXTURES = Path(__file__).parent / 'fixtures'


def output(ref):
    return {'source_observations': [{'text': '来源报告记载了合成行为。', 'evidence_refs': [ref]}],
            'hypotheses': [{'text': '该行为的目的仍待验证。', 'evidence_refs': [ref], 'verification': '人工核对原始事件。'}],
            'limitations': ['合成输入，仅用于接口验证。'], 'adjustment': None}


class StubProvider:
    model = 'synthetic-stub'
    def __init__(self, value=None):
        self.value, self.context = value, None
    def generate(self, context):
        self.context = context
        return {'output': self.value or output(context['evidence'][0]['evidence_id'])}


class SemanticTests(unittest.TestCase):
    def setUp(self):
        self.report = load_cape_report(FIXTURES / 'cape_synthetic.json', synthetic=True)
        self.catalog = load_ruleset(FIXTURES / 'scoring_synthetic.json')

    def test_output_is_evidence_bound_and_not_a_verdict(self):
        provider = StubProvider()
        result, raw = explain(self.report, provider, catalog=self.catalog)
        self.assertEqual(result['verdict'], 'not_assessed')
        self.assertTrue(result['review_required']); self.assertTrue(result['synthetic'])
        self.assertEqual(result['omitted_evidence_count'], 0)
        self.assertIsNone(raw)
        self.assertEqual(result['report_sha256'], self.report.source_sha256)
        self.assertEqual(result['context_sha256'], explain(self.report, StubProvider(), catalog=self.catalog)[0]['context_sha256'])

    def test_unsent_or_fabricated_references_are_rejected(self):
        selected = self.report.evidence[0].evidence_id
        for ref in ('invented', self.report.evidence[-1].evidence_id):
            with self.subTest(ref=ref), self.assertRaises(SemanticError):
                explain(self.report, StubProvider(output(ref)), evidence_ids=[selected])

    def test_unexpected_fields_types_and_missing_verification(self):
        valid = output(self.report.evidence[0].evidence_id)
        bad = [{**valid, 'verdict': 'benign'}, {**valid, 'limitations': []}, {**valid, 'source_observations': 'safe'},
               {**valid, 'hypotheses': [{'text': 'injection', 'evidence_refs': [self.report.evidence[0].evidence_id]}]},
               {**valid, 'source_observations': [{'text': ' ', 'evidence_refs': [self.report.evidence[0].evidence_id]}]}]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(SemanticError):
                explain(self.report, StubProvider(value))

    def test_critical_signals_included_and_negative_adjustment_stays_blocked(self):
        critical = next(item for item in self.report.evidence if item.category == 'signature')
        catalog = RuleSet('critical-demo/1', (SignatureRule('C', critical.data['name'], 8, True),), 'b'*64, True)
        provider = StubProvider()
        result, _ = explain(self.report, provider, catalog=catalog, evidence_ids=[self.report.evidence[0].evidence_id])
        self.assertIn(critical.evidence_id, result['supplied_evidence_ids'])
        value = output(critical.evidence_id)
        value['adjustment'] = {'delta': -8, 'rationale': 'Synthetic hypothesis', 'cited_evidence': [critical.evidence_id]}
        result, raw = explain(self.report, StubProvider(value), catalog=catalog)
        self.assertEqual(result['proposal_review']['adjustment_proposal']['status'], 'blocked_critical_signal')
        self.assertEqual(result['proposal_review']['adjustment_proposal']['applied_score'], 8)
        self.assertEqual(json.loads(raw)['report_sha256'], self.report.source_sha256)

    def test_adjustment_needs_catalog_and_valid_points(self):
        value = output(self.report.evidence[0].evidence_id)
        value['adjustment'] = {'delta': -1, 'rationale': 'Review', 'cited_evidence': [self.report.evidence[0].evidence_id]}
        with self.assertRaises(SemanticError):
            explain(self.report, StubProvider(value))
        for invalid in (True, -11, '1'):
            value['adjustment']['delta'] = invalid
            with self.assertRaises(SemanticError):
                explain(self.report, StubProvider(value), catalog=self.catalog)
        value['adjustment']['delta'] = -1
        value['adjustment']['rationale'] = ' ' * 501 + 'Review'
        with self.assertRaises(SemanticError):
            explain(self.report, StubProvider(value), catalog=self.catalog)

    def test_context_budget_discloses_omissions_and_refuses_critical_oversize(self):
        report = parse_cape_report(json.dumps({'signatures': [{'name': 'demo', 'description': 'x'*1000} for _ in range(100)]}).encode())
        provider = StubProvider()
        result, _ = explain(report, provider)
        self.assertGreater(result['omitted_evidence_count'], 0)
        self.assertLessEqual(len(provider.context['evidence']), 32)
        with patch('artemis_v3.semantic.MAX_CONTEXT_BYTES', 100), self.assertRaises(SemanticError):
            build_context(self.report, evidence_ids=[self.report.evidence[0].evidence_id])
        with patch('artemis_v3.semantic.MAX_CONTEXT_BYTES', 100), self.assertRaises(SemanticError):
            build_context(self.report, RuleSet('critical/1', (SignatureRule('R', 'synthetic_behavior', 8, True),), 'b'*64, True))

    def test_selection_validation_and_empty_reports(self):
        for refs in ([], ['invented'], [True], [self.report.evidence[0].evidence_id]*2):
            with self.subTest(refs=refs), self.assertRaises(SemanticError):
                build_context(self.report, evidence_ids=refs)
        with self.assertRaises(SemanticError):
            build_context(parse_cape_report(b'{"signatures":[]}'))


class FakeOllama(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        self.do_POST()
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or b'{}')
        self.server.requests.append((self.path, request))
        entry = {'name': 'test:latest', 'digest': 'a'*64, 'details': {'format': 'gguf'}}
        metadata = {'details': {'format': 'gguf'}, 'model_info': {'general.architecture': 'synthetic'}}
        if self.server.mode == 'remote':
            metadata['remote_host'] = 'https://cloud.invalid'
        if self.server.mode == 'bad_metadata':
            metadata['details'] = None
        if self.path == '/api/tags':
            value = {'models': [] if self.server.mode == 'missing' else [entry]}
        elif self.path == '/api/show':
            value = metadata
        else:
            context = json.loads(request['messages'][1]['content'])
            content = output(context['evidence'][0]['evidence_id'])
            if self.server.mode in ('adjustment', 'history_adjustment'):
                content['adjustment'] = {'delta': -1, 'rationale': 'Synthetic model proposal',
                                         'cited_evidence': [context['evidence'][0]['evidence_id']]}
            if self.server.mode == 'history_adjustment' and context.get('historical_context'):
                content['source_observations'].append({'text': '历史来源报告记录了一条合成陈述，不能等同于当前行为。',
                    'evidence_refs': [context['historical_context']['evidence'][0]['evidence_id']]})
            if self.server.mode == 'invalid_refs':
                content['source_observations'][0]['evidence_refs'] = ['invented']
            value = {'model': 'test:latest', 'done': True, 'done_reason': 'stop',
                     'message': {'role': 'assistant', 'content': json.dumps(content)}}
            if self.server.mode == 'incomplete':
                value['done_reason'] = 'length'
            if self.server.mode == 'tools':
                value['message']['tool_calls'] = [{'function': {'name': 'execute'}}]
            if self.server.mode == 'wrong_identity':
                value['model'] = 'other'
            if self.server.mode == 'bad_json':
                value['message']['content'] = '{"a":1,"a":2}'
        raw = json.dumps(value).encode()
        self.send_response(302 if self.server.mode == 'redirect' else 200)
        self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)


class OllamaTransportTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), FakeOllama)
        self.server.mode, self.server.requests = 'valid', []
        self.thread = Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)
        self.thread.start()
        self.provider = OllamaLocalProvider('test', port=self.server.server_port, timeout=3)
        self.report = load_cape_report(FIXTURES / 'cape_synthetic.json', synthetic=True)
    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()

    def test_real_loopback_protocol_and_proxy_bypass(self):
        with patch.dict('os.environ', {'HTTP_PROXY': 'http://invalid.invalid:1', 'NO_PROXY': ''}):
            result, _ = explain(self.report, self.provider)
        self.assertEqual(result['model_digest'], 'a'*64)
        self.assertEqual([p for p, _ in self.server.requests], ['/api/tags', '/api/show', '/api/chat'])
        request = self.server.requests[-1][1]
        self.assertFalse(request['stream']); self.assertFalse(request['think'])
        self.assertNotIn('tools', request)
        self.assertIsInstance(request['format'], dict)

    def test_remote_missing_and_bad_metadata_never_receive_evidence(self):
        for mode in ('remote', 'missing', 'bad_metadata', 'redirect'):
            self.server.mode, self.server.requests = mode, []
            with self.subTest(mode=mode), self.assertRaises(SemanticError):
                explain(self.report, self.provider)
            self.assertNotIn('/api/chat', [p for p, _ in self.server.requests])

    def test_incomplete_tool_or_wrong_identity_is_rejected(self):
        for mode in ('incomplete', 'tools', 'wrong_identity', 'bad_json'):
            self.server.mode = mode
            with self.subTest(mode=mode), self.assertRaises(SemanticError):
                explain(self.report, self.provider)

    def test_size_budget_and_busy_slot(self):
        with patch('artemis_v3.semantic.MAX_HTTP_RESPONSE', 3), self.assertRaises(SemanticError):
            explain(self.report, self.provider)
        self.provider._slot.acquire()
        try:
            with self.assertRaises(SemanticError):
                explain(self.report, self.provider)
        finally:
            self.provider._slot.release()

    def test_expired_budget_and_network_failure(self):
        with self.assertRaises(SemanticError):
            self.provider._request('tags', None, 0)
        with patch('artemis_v3.semantic.http.client.HTTPConnection', side_effect=OSError('synthetic')):
            with self.assertRaises(SemanticError):
                explain(self.report, self.provider)

    def test_invalid_configuration(self):
        for model in ('', 'https://external.invalid', 'test:cloud', 'test-cloud', '../x', True):
            with self.subTest(model=model), self.assertRaises(ValueError):
                OllamaLocalProvider(model)
        for values in ({'port': 0}, {'port': True}, {'timeout': float('nan')}, {'timeout': 61}, {'timeout': True},
                       {'expected_digest': 'invalid'}, {'expected_digest': True}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                OllamaLocalProvider('test', **values)
