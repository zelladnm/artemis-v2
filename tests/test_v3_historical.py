"""Explicit historical retrieval, context budgets, citation isolation and HTTP."""
import base64
import copy
from http.server import ThreadingHTTPServer
import http.client
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest

from artemis_v3.cape import parse_cape_report
from artemis_v3.case_store import save_case
from artemis_v3.historical import HistoricalSource, load_historical_source
from artemis_v3.ruleset import RuleSet, load_ruleset
from artemis_v3.scoring import SignatureRule
from artemis_v3.semantic import OllamaLocalProvider, SemanticError, explain
from artemis_v3.workbench import WorkbenchServer
from test_v3_case_store import report_bytes
from test_v3_semantic import FakeOllama, output

FIXTURES = Path(__file__).parent / 'fixtures'


class HistoricalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.database = Path(self.temporary.name) / 'cases.sqlite'
        self.raw = report_bytes(number=2); self.report = parse_cape_report(self.raw, synthetic=True)
        self.catalog = load_ruleset(FIXTURES / 'scoring_synthetic.json')
        self.metadata = save_case(self.database, report_bytes(number=1), synthetic=True)['case']
        self.historical = load_historical_source(self.database, self.metadata['case_id'], self.report, self.raw)
        class Provider:
            model = 'synthetic-history'
            def __init__(self):
                self.context = None; self.value = None
            def generate(self, context):
                self.context = context
                return {'output': self.value or output(context['historical_context']['evidence'][0]['evidence_id'])}
        self.provider = Provider()

    def tearDown(self):
        self.temporary.cleanup()

    def test_history_observations_are_bound_to_sent_source_and_total_budget(self):
        result, raw = explain(self.report, self.provider, catalog=self.catalog, historical=self.historical)
        self.assertEqual(result['schema_version'], 'artemis-explanation/2')
        self.assertEqual(result['prompt_version'], 'artemis-semantic/4')
        self.assertIsNone(raw)
        history = result['historical_context']; context = self.provider.context
        self.assertEqual(history['case_id'], self.metadata['case_id'])
        self.assertEqual(history['association'], 'same_report_asserted_sample_sha256')
        self.assertNotEqual(history['report_sha256'], result['report_sha256'])
        self.assertLessEqual(len(context['evidence']) + len(history['evidence']), 32)
        self.assertLessEqual(len(history['evidence']), 8)
        self.assertLessEqual(len(json.dumps(context, ensure_ascii=False, separators=(',', ':')).encode()), 12*1024)
        self.assertEqual(result['omitted_evidence_count'], 0)
        self.assertEqual(history['omitted_evidence_count'], history['total_evidence_count']-len(history['evidence']))
        self.assertNotIn('rule_summary', history)
        self.assertNotIn('ruleset_sha256', history)
        self.assertEqual(result['source_observations'][0]['evidence_refs'][0].split('#')[0], history['report_sha256'])

    def test_server_derives_scopes_without_mutating_or_trusting_model_output(self):
        first, _ = explain(self.report, self.provider, historical=self.historical)
        current = first['supplied_evidence_ids'][0]
        historical = first['historical_context']['evidence'][0]['evidence_id']
        value = output(current)
        value['source_observations'].append({'text': '历史来源的合成陈述。', 'evidence_refs': [historical]})
        value['hypotheses'][0]['evidence_refs'] = [historical, current]
        self.provider.value = value
        original = copy.deepcopy(value)
        result, _ = explain(self.report, self.provider, historical=self.historical)
        self.assertEqual([entry['source_scope'] for entry in result['source_observations']], ['current', 'historical'])
        self.assertEqual(result['hypotheses'][0]['source_scope'], 'mixed')
        self.assertEqual(result['source_attribution_version'], 'artemis-source-attribution/1')
        self.assertEqual(value, original)
        result['source_observations'][0]['evidence_refs'].append('changed-result')
        self.assertEqual(value, original)
        for section in ('source_observations', 'hypotheses'):
            self.provider.value = copy.deepcopy(original)
            self.provider.value[section][0]['source_scope'] = 'current'
            with self.subTest(section=section), self.assertRaises(SemanticError):
                explain(self.report, self.provider, historical=self.historical)

    def test_mixed_source_observations_are_rejected_but_hypotheses_need_verification(self):
        first, _ = explain(self.report, self.provider, historical=self.historical)
        refs = [first['supplied_evidence_ids'][0], first['historical_context']['evidence'][0]['evidence_id']]
        for ordered in (refs, refs[::-1]):
            value = output(ordered[0]); value['source_observations'][0]['evidence_refs'] = ordered
            self.provider.value = value
            with self.subTest(ordered=ordered), self.assertRaisesRegex(SemanticError, 'one source'):
                explain(self.report, self.provider, historical=self.historical)
        value = output(refs[0]); value['hypotheses'][0]['evidence_refs'] = refs
        value['hypotheses'][0]['verification'] = ' '
        self.provider.value = value
        with self.assertRaises(SemanticError):
            explain(self.report, self.provider, historical=self.historical)

    def test_attribution_labels_do_not_claim_to_validate_the_model_prose(self):
        # Intentionally false attribution in prose: a valid historical ref cannot prove a current event.
        first, _ = explain(self.report, self.provider, historical=self.historical)
        self.provider.value = output(first['historical_context']['evidence'][0]['evidence_id'])
        self.provider.value['source_observations'][0]['text'] = '当前分析已确认发生注入。'
        result, _ = explain(self.report, self.provider, historical=self.historical)
        self.assertEqual(result['source_observations'][0]['source_scope'], 'historical')
        self.assertEqual(result['verdict'], 'not_assessed'); self.assertTrue(result['review_required'])

    def test_unsent_historical_refs_and_historical_adjustment_refs_are_rejected(self):
        result, _ = explain(self.report, self.provider, historical=self.historical)
        sent = {row['evidence_id'] for row in result['historical_context']['evidence']}
        omitted = next(row.evidence_id for row in self.historical.report.evidence if row.evidence_id not in sent)
        for ref in ('invented', omitted):
            self.provider.value = output(ref)
            with self.subTest(ref=ref), self.assertRaises(SemanticError):
                explain(self.report, self.provider, historical=self.historical)
        current = self.report.evidence[0].evidence_id
        history_ref = next(iter(sent))
        for refs in ([history_ref], [current, history_ref]):
            value = output(history_ref)
            value['adjustment'] = {'delta': -1, 'rationale': 'Historical story', 'cited_evidence': refs}
            self.provider.value = value
            with self.subTest(refs=refs), self.assertRaises(SemanticError):
                explain(self.report, self.provider, catalog=self.catalog, historical=self.historical)

    def test_current_critical_sources_and_blocked_negative_adjustment_survive_history(self):
        critical = next(row for row in self.report.evidence if row.category == 'signature')
        catalog = RuleSet('critical-history-test/1', (SignatureRule('C', critical.data['name'], 8, True),), 'b'*64, True)
        value = output(self.report.evidence[0].evidence_id)
        value['adjustment'] = {'delta': -8, 'rationale': 'Synthetic contextual request', 'cited_evidence': [critical.evidence_id]}
        self.provider.value = value
        result, raw = explain(self.report, self.provider, catalog=catalog, historical=self.historical,
                              evidence_ids=[self.report.evidence[0].evidence_id])
        self.assertIn(critical.evidence_id, result['supplied_evidence_ids'])
        self.assertEqual(result['proposal_review']['adjustment_proposal']['status'], 'blocked_critical_signal')
        self.assertEqual(result['proposal_review']['adjustment_proposal']['applied_score'], 8)
        self.assertEqual(json.loads(raw)['report_sha256'], self.report.source_sha256)

    def test_source_association_requires_distinct_exact_assertion_and_same_provenance(self):
        cases = [report_bytes(sample='b'*64, number=3), report_bytes(sample=None, number=3), self.raw]
        ids = [save_case(self.database, raw, synthetic=True)['case']['case_id'] for raw in cases]
        ids.append(save_case(self.database, report_bytes(number=3), synthetic=False)['case']['case_id'])
        for case_id in ids + ['unknown', ['a'*64]]:
            with self.subTest(case_id=case_id), self.assertRaises(SemanticError):
                load_historical_source(self.database, case_id, self.report, self.raw)
        with self.assertRaises(SemanticError):
            load_historical_source(None, self.metadata['case_id'], self.report, self.raw)
        with self.assertRaises(SemanticError):
            load_historical_source(self.database, self.metadata['case_id'], self.report, report_bytes(number=8))
        missing_raw = report_bytes(sample=None, number=9)
        with self.assertRaises(SemanticError):
            load_historical_source(self.database, self.metadata['case_id'], parse_cape_report(missing_raw), missing_raw)

    def test_budget_and_stale_selections_fail_before_model(self):
        many_raw = json.dumps({'target': {'file': {'sha256': 'a'*64}},
                              'signatures': [{'name': 'synthetic_'+str(i)} for i in range(40)]}).encode()
        many = parse_cape_report(many_raw, synthetic=True)
        historical = load_historical_source(self.database, self.metadata['case_id'], many, many_raw)
        with self.assertRaises(SemanticError):
            explain(many, self.provider, historical=historical, evidence_ids=[row.evidence_id for row in many.evidence[:25]])
        self.assertIsNone(self.provider.context)
        stale = HistoricalSource(self.historical.case_id, 'a'*64, 'b'*64, self.historical.report)
        with self.assertRaises(SemanticError):
            explain(self.report, self.provider, historical=stale)
        self.assertIsNone(self.provider.context)
        for signatures in ([], [{'name': 'oversized', 'description': 'x'*20000}]):
            raw = json.dumps({'target': {'file': {'sha256': 'a'*64}}, 'signatures': signatures}).encode()
            saved = save_case(self.database, raw, synthetic=True)['case']
            source = load_historical_source(self.database, saved['case_id'], self.report, self.raw)
            with self.assertRaises(SemanticError):
                explain(self.report, self.provider, historical=source)
            self.assertIsNone(self.provider.context)


class HistoricalHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.database = Path(self.temporary.name) / 'cases.sqlite'
        self.metadata = save_case(self.database, report_bytes(number=1), synthetic=True)['case']
        self.ollama = ThreadingHTTPServer(('127.0.0.1', 0), FakeOllama)
        self.ollama.mode, self.ollama.requests = 'history_adjustment', []
        self.model_thread = Thread(target=lambda: self.ollama.serve_forever(poll_interval=0.01), daemon=True); self.model_thread.start()
        self.server = WorkbenchServer(0, case_db=self.database,
            semantic_provider=OllamaLocalProvider('test', port=self.ollama.server_port, timeout=3))
        self.thread = Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True); self.thread.start()
        self.payload = {'report': base64.b64encode(report_bytes(number=2)).decode(), 'synthetic': True,
                        'ruleset': base64.b64encode((FIXTURES / 'scoring_synthetic.json').read_bytes()).decode()}

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.ollama.shutdown(); self.ollama.server_close(); self.model_thread.join(); self.temporary.cleanup()

    def request(self, route, payload):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        connection.request('POST', route, body=json.dumps(payload), headers={
            'Content-Type': 'application/json', 'X-Artemis-Token': self.server.token})
        response = connection.getresponse(); status, result = response.status, json.loads(response.read()); connection.close()
        return status, result

    def test_only_explicit_explanation_loads_and_sends_selected_history(self):
        payload = {**self.payload, 'historical_case_id': self.metadata['case_id']}
        self.assertEqual(self.request('/api/analyze', payload)[0], 200)
        self.assertEqual(self.ollama.requests, [])
        status, result = self.request('/api/explain', payload)
        self.assertEqual(status, 200); self.assertEqual(result['model_status'], 'completed')
        history = result['semantic_review']['historical_context']
        self.assertEqual(history['report_sha256'], self.metadata['report_sha256'])
        self.assertEqual(result['rule_assessment']['base_score'], 1)
        self.assertEqual(len(self.ollama.requests), 3)
        context = json.loads(self.ollama.requests[-1][1]['messages'][1]['content'])
        self.assertEqual(context['historical_context']['case_id'], self.metadata['case_id'])
        proposal = json.loads(base64.b64decode(result['suggestion_file_b64']))
        self.assertTrue(all(ref.startswith(result['report']['source_sha256']+'#') for ref in proposal['cited_evidence']))

    def test_no_selection_preserves_single_source_contract(self):
        status, result = self.request('/api/explain', self.payload)
        self.assertEqual(status, 200)
        self.assertEqual(result['semantic_review']['schema_version'], 'artemis-explanation/1')
        self.assertNotIn('historical_context', result['semantic_review'])
        self.assertNotIn('source_attribution_version', result['semantic_review'])
        self.assertTrue(all('source_scope' not in entry for key in ('source_observations', 'hypotheses')
                            for entry in result['semantic_review'][key]))

    def test_mixed_observation_fails_without_changing_current_evidence_or_score(self):
        self.ollama.mode = 'mixed_history_observation'
        status, result = self.request('/api/explain', {**self.payload, 'historical_case_id': self.metadata['case_id']})
        self.assertEqual(status, 200); self.assertEqual(result['model_status'], 'failed')
        self.assertIn('one source', result['semantic_error'])
        self.assertEqual(result['rule_assessment']['base_score'], 1)
        self.assertEqual(len(result['report']['evidence']), 9)
        self.assertNotIn('semantic_review', result); self.assertNotIn('suggestion_file_b64', result)

    def test_invalid_selection_keeps_current_evidence_and_never_calls_model(self):
        wrong = save_case(self.database, report_bytes(sample='b'*64), synthetic=True)['case']['case_id']
        for case_id in (wrong, '0'*64, ['a'*64]):
            status, result = self.request('/api/explain', {**self.payload, 'historical_case_id': case_id})
            self.assertEqual(status, 200); self.assertEqual(result['model_status'], 'failed')
            self.assertEqual(result['rule_assessment']['base_score'], 1)
            self.assertEqual(len(result['report']['evidence']), 9)
            self.assertNotIn('semantic_review', result)
        self.assertEqual(self.ollama.requests, [])
