"""Readable handoff, literal hostile content and exact review/source binding."""
import base64
import copy
from html.parser import HTMLParser
import http.client
import json
from pathlib import Path
import re
import secrets
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

from artemis_v3.claim_review import issue_receipt, record_claim_review, review_template
from artemis_v3.historical import prepare_historical_source
from artemis_v3.reporting import prepare_export, render_report
from artemis_v3.review import ReviewError, record_review
from artemis_v3.semantic import explain
from artemis_v3.workbench import WorkbenchServer, investigate_payload
from test_v3_semantic import StubProvider, output

FIXTURES = Path(__file__).parent / 'fixtures'
HOSTILE = '<img src="https://outside.invalid/track" onerror="window.__report_xss=1"> ```\n[click](javascript:alert(1))\nhttps://outside.invalid/a'


def request(format='html'):
    return {'format': format, 'generation': None, 'receipt': None, 'claim_review_id': None,
            'claim_draft': None, 'score_review_id': None}


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.ids = []; self.hrefs = []; self.tags = []; self.attrs = []; self.text = []
        self.feed(text)
    def handle_starttag(self, tag, attrs):
        self.tags.append(tag); self.attrs.extend(attrs)
        for key, value in attrs:
            if key == 'id': self.ids.append(value)
            if key == 'href': self.hrefs.append(value)
    def handle_data(self, data):
        self.text.append(data)


class ReportingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.db = Path(temporary.name) / 'reviews.sqlite'
        self.key = secrets.token_bytes(32)
        self.payload = {'report': base64.b64encode((FIXTURES / 'cape_synthetic.json').read_bytes()).decode(),
                        'ruleset': base64.b64encode((FIXTURES / 'scoring_synthetic.json').read_bytes()).decode(), 'synthetic': True}
        self.result, self.report, self.catalog, self.packet = investigate_payload(self.payload)
        self.export = request()

    def prepare(self, request=None):
        return prepare_export(self.result, self.report, self.catalog, self.packet, request or self.export,
                              review_db=self.db, receipt_key=self.key)

    def add_model(self, value=None, historical=None):
        explanation, proposal = explain(self.report, StubProvider(value), catalog=self.catalog, historical=historical)
        generation = {'explanation': explanation, 'suggestion_file_b64': base64.b64encode(proposal).decode() if proposal else None}
        self.export.update(generation=generation, receipt=issue_receipt(self.key, generation))
        return generation

    def save_claims(self):
        generation = self.export['generation']
        claim_request = review_template(generation); claim_request['reviewer'] = 'synthetic reviewer'
        claim_request['items'][0].update(rating='unsupported', reason='The synthetic source does not establish this claim')
        record = record_claim_review(self.db, self.report, self.catalog, generation,
            self.export['receipt'], self.key, claim_request)
        self.export['claim_review_id'] = record['review_id']
        return record

    def save_score(self, decision='defer'):
        score_request = {'source_sha256': self.report.source_sha256, 'ruleset_sha256': self.catalog.source_sha256,
                         'delta': -1, 'cited_evidence': [self.report.evidence[0].evidence_id], 'rationale': 'Synthetic proposal',
                         'reviewer': 'synthetic reviewer', 'decision': decision, 'reason': 'Synthetic score decision',
                         'expected_previous_id': None}
        record = record_review(self.db, self.report, self.catalog, score_request, proposal_packet=self.packet)
        self.export['score_review_id'] = record['review_id']
        return record

    def test_report_only_and_no_model_are_explicit_and_do_not_create_database(self):
        result, report, catalog, packet = investigate_payload({'report': self.payload['report'], 'synthetic': True})
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            snapshot = prepare_export(result, report, catalog, packet, request(), review_db=self.db, receipt_key=self.key)
            for format in ('html', 'markdown'):
                rendered = render_report(snapshot, format, generated_at='synthetic-time')
                self.assertIn('未加载规则集，未计算规则分数', rendered)
                self.assertIn('本报告未附模型解释', rendered)
                self.assertIn('最终恶意性结论：尚未记录', rendered)
                self.assertIn('包含合成演示数据', rendered)
                self.assertNotIn('0 / 10', rendered)
        self.assertFalse(self.db.exists())

    def test_partial_draft_never_counts_as_saved_support(self):
        generation = self.add_model()
        draft = review_template(generation)
        draft['items'][0].update(rating='supported', reason='')  # Incomplete browser form may still be exported.
        self.export['claim_draft'] = draft
        snapshot = self.prepare()
        self.assertEqual(snapshot['claim_review_draft']['status'], 'unsaved')
        self.assertNotIn('claim_review', snapshot)
        for format in ('html', 'markdown'):
            rendered = render_report(snapshot, format)
            self.assertIn('未保存的核验草稿', rendered)
            self.assertIn('0 / 2', rendered)
            self.assertIn('仍有 2 条不支持、不确定或未核验', rendered)
        self.assertFalse(self.db.exists())

    def test_saved_judgments_and_new_draft_stay_separate_readonly(self):
        generation = self.add_model(); saved = self.save_claims(); score = self.save_score('reject')
        draft = review_template(generation)
        draft['items'][0].update(rating='supported', reason='Draft differs from saved judgment')
        draft['expected_previous_id'] = saved['review_id']
        self.export['claim_draft'] = draft
        before = self.db.read_bytes()
        snapshot = self.prepare()
        self.assertEqual(snapshot['claim_review']['items'][0]['rating'], 'unsupported')
        self.assertEqual(snapshot['claim_review_draft']['items'][0]['rating'], 'supported')
        text = render_report(snapshot, 'html')
        self.assertIn(saved['review_id'], text); self.assertIn(score['review_id'], text)
        self.assertIn('拒绝建议', text); self.assertIn('人工批准分数</dt><dd>未批准', text)
        self.assertIn('1 / 2', text); self.assertIn('仍有 2 条不支持、不确定或未核验', text)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertNotIn(self.export['receipt'], text)

    def test_historical_scope_and_all_internal_links_resolve(self):
        raw = (FIXTURES / 'semantic_eval/history_current.json').read_bytes()
        self.payload['report'] = base64.b64encode(raw).decode()
        self.result, self.report, self.catalog, self.packet = investigate_payload(self.payload)
        prior = (FIXTURES / 'semantic_eval/history_prior.json').read_bytes()
        historical = prepare_historical_source('history-test', prior, self.report, raw, synthetic=True)
        current = self.report.evidence[0].evidence_id; old = historical.report.evidence[0].evidence_id
        value = output(old); value['source_observations'][0]['text'] = '当前执行成功。'  # Deliberately unsupported attribution.
        value['hypotheses'][0]['evidence_refs'] = [current, old]
        self.add_model(value, historical); self.save_claims()
        snapshot = self.prepare()
        text = render_report(snapshot, 'html'); parsed = Document(text)
        self.assertIn('历史来源', text); self.assertIn('跨来源', text)
        self.assertIn('历史行为不能据此认定为当前行为', text)
        self.assertEqual(len(parsed.ids), len(set(parsed.ids)))
        self.assertTrue(parsed.hrefs)
        self.assertTrue(all(href.startswith('#') and href[1:] in parsed.ids for href in parsed.hrefs))
        md = render_report(snapshot, 'markdown')
        for anchor in re.findall(r'\]\(#([a-z0-9]+)\)', md):
            self.assertIn('### ' + anchor.upper() + '\n', md)

    def test_draft_base_must_match_selected_saved_revision_without_writing(self):
        generation = self.add_model()
        draft = review_template(generation)
        other_id = '00000000-0000-4000-8000-000000000001'
        draft['expected_previous_id'] = other_id
        self.export['claim_draft'] = draft
        with self.assertRaisesRegex(ReviewError, 'selected saved'): self.prepare()
        self.assertFalse(self.db.exists())
        saved = self.save_claims()
        before = self.db.read_bytes()
        for previous in (None, other_id):
            draft['expected_previous_id'] = previous
            with self.subTest(previous=previous), self.assertRaisesRegex(ReviewError, 'selected saved'):
                self.prepare()
        draft['expected_previous_id'] = saved['review_id']
        self.assertEqual(self.prepare()['claim_review_draft']['expected_previous_id'], saved['review_id'])
        self.assertEqual(self.db.read_bytes(), before)

    def test_hostile_content_is_literal_in_html_and_fenced_in_markdown(self):
        value = output(self.report.evidence[0].evidence_id)
        value['source_observations'][0]['text'] = HOSTILE
        value['hypotheses'][0]['verification'] = HOSTILE
        self.add_model(value)
        snapshot = self.prepare()
        parsed = Document(render_report(snapshot, 'html'))
        self.assertIn(HOSTILE, ''.join(parsed.text))
        self.assertFalse(set(parsed.tags) & {'img', 'script', 'iframe', 'form', 'object', 'embed'})
        self.assertTrue(all(not key.startswith('on') and key not in ('src', 'srcdoc') for key, _ in parsed.attrs))
        self.assertTrue(all(href.startswith('#') for href in parsed.hrefs))
        md = render_report(snapshot, 'markdown')
        self.assertIn('````text\n' + HOSTILE + '\n````', md)
        self.assertNotIn('<pre>', md)

    def test_display_bounds_disclose_omissions_and_keep_complete_source_untouched(self):
        raw = {'behavior': {'processes': [{'process_id': number, 'process_name': 'A'*6000, 'first_seen': 'invalid'} for number in range(25)]}}
        payload = {'report': base64.b64encode(json.dumps(raw).encode()).decode(), 'synthetic': True}
        result, report, catalog, packet = investigate_payload(payload)
        snapshot = prepare_export(result, report, catalog, packet, request(), receipt_key=self.key)
        original = copy.deepcopy(snapshot)
        with patch('artemis_v3.reporting.MAX_APPENDIX', 2):
            rendered = render_report(snapshot, 'html')
        self.assertIn('展示前 20 / 25 条', rendered)
        self.assertIn('2 / 20 条选用引用', rendered)
        self.assertIn('展示已截断', rendered)
        self.assertIn('字段未收入本报告', rendered)
        self.assertEqual(snapshot, original)
        with patch('artemis_v3.reporting.MAX_OUTPUT_BYTES', 5), self.assertRaises(ValueError):
            render_report(snapshot, 'html')

    def test_generation_receipt_and_claim_ids_cannot_be_mixed(self):
        self.add_model(); saved = self.save_claims()
        before = self.db.read_bytes()
        forged = copy.deepcopy(self.export); forged['generation']['explanation']['source_observations'][0]['text'] = 'Rewritten'
        with self.assertRaises(ReviewError): self.prepare(forged)
        other = output(self.report.evidence[0].evidence_id); other['source_observations'][0]['text'] = 'New generation'
        self.add_model(other)
        self.assertEqual(self.export['claim_review_id'], saved['review_id'])
        with self.assertRaisesRegex(ReviewError, 'generation'): self.prepare()
        self.assertEqual(self.db.read_bytes(), before)
        missing = request(); missing['claim_review_id'] = saved['review_id']
        with self.assertRaises(ReviewError): self.prepare(missing)

    def test_wrong_score_sources_rules_provenance_or_proposal_are_rejected(self):
        self.save_score()
        for change in ('source', 'rules', 'provenance', 'proposal'):
            with self.subTest(change=change):
                payload = copy.deepcopy(self.payload)
                if change == 'source': payload['report'] = base64.b64encode(base64.b64decode(payload['report']) + b' ').decode()
                if change == 'rules': payload['ruleset'] = base64.b64encode(base64.b64decode(payload['ruleset']) + b' ').decode()
                if change == 'provenance': payload['synthetic'] = False
                if change == 'proposal':
                    proposal = {'schema_version': 'artemis-proposal/1', 'report_sha256': self.report.source_sha256,
                                'ruleset_sha256': self.catalog.source_sha256, 'ruleset_version': self.catalog.version,
                                'proposed_delta': 0, 'cited_evidence': [self.report.evidence[0].evidence_id], 'rationale': 'Different'}
                    payload['proposal'] = base64.b64encode(json.dumps(proposal).encode()).decode()
                result, report, catalog, packet = investigate_payload(payload)
                with self.assertRaises(ReviewError):
                    prepare_export(result, report, catalog, packet, self.export, review_db=self.db, receipt_key=self.key)

    def test_approved_score_is_explicit_and_base_is_preserved(self):
        saved = self.save_score('approve')
        text = render_report(self.prepare(), 'html')
        self.assertIn('人工批准分数</dt><dd>0', text)
        self.assertIn('规则原始分数</dt><dd>1 / 10', text)
        self.assertIn('最终恶意性结论：尚未记录', text)
        self.assertEqual(saved['base_score'], 1)

    def test_critical_model_adjustment_remains_blocked_in_readable_report(self):
        rules = json.loads(base64.b64decode(self.payload['ruleset']))
        rules['rules'][0].update(points=8, critical=True)
        self.payload['ruleset'] = base64.b64encode(json.dumps(rules).encode()).decode()
        self.result, self.report, self.catalog, self.packet = investigate_payload(self.payload)
        ref = next(item for item in self.report.evidence if item.category == 'signature').evidence_id
        value = output(ref); value['adjustment'] = {'delta': -8, 'rationale': 'Synthetic downgrade', 'cited_evidence': [ref]}
        self.add_model(value)
        snapshot = self.prepare(); text = render_report(snapshot, 'html')
        self.assertIn('关键负向建议已阻止', text)
        self.assertIn('规则原始分数</dt><dd>8 / 10', text)
        self.assertIn('本报告未附评分复核决定', text)
        self.assertEqual(snapshot['semantic_review']['proposal_review']['adjustment_proposal']['applied_score'], 8)

    def test_unknown_export_fields_draft_generation_and_unsupported_formats_rejected(self):
        for change in ({'format': 'pdf'}, {'format': []}, {'review_body': {}}, {'generation': []}):
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare({**request(), **change})
        generated = self.add_model(); draft = review_template(generated); draft['generation_sha256'] = 'f'*64
        self.export['claim_draft'] = draft
        with self.assertRaises(ReviewError): self.prepare()
        self.assertFalse(self.db.exists())

    def test_invisible_controls_are_exposed_without_changing_snapshot(self):
        value = output(self.report.evidence[0].evidence_id)
        value['source_observations'][0]['text'] = 'prefix\u202eevil\x00\ud800'
        self.add_model(value)
        snapshot = self.prepare(); text = render_report(snapshot, 'html')
        self.assertIn('prefix\\u202eevil\\u0000\\ud800', text)
        self.assertEqual(snapshot['semantic_review']['source_observations'][0]['text'], value['source_observations'][0]['text'])


class ReportingHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.db = Path(self.temporary.name) / 'reviews.sqlite'
        class CountingProvider(StubProvider):
            calls = 0
            def generate(self, context):
                self.calls += 1
                return super().generate(context)
        self.provider = CountingProvider()
        self.server = WorkbenchServer(0, review_db=self.db, semantic_provider=self.provider)
        self.thread = Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True); self.thread.start()
        self.payload = {'report': base64.b64encode((FIXTURES / 'cape_synthetic.json').read_bytes()).decode(), 'synthetic': True}
    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(); self.temporary.cleanup()
    def post(self, path, payload, *, token=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        connection.request('POST', path, body=json.dumps(payload), headers={'Content-Type': 'application/json',
                           'X-Artemis-Token': self.server.token if token is None else token})
        response = connection.getresponse(); status, value = response.status, json.loads(response.read()); connection.close()
        return status, value

    def test_explicit_readonly_export_reuses_validated_explanation_without_generation(self):
        status, result = self.post('/api/explain', self.payload)
        self.assertEqual(status, 200); self.assertEqual(self.provider.calls, 1)
        export = {**request(), 'generation': {'explanation': result['semantic_review'], 'suggestion_file_b64': None}, 'receipt': result['claim_receipt']}
        for format, extension in (('html', 'html'), ('markdown', 'md')):
            status, artifact = self.post('/api/export', {**self.payload, 'export_request': {**export, 'format': format}})
            self.assertEqual(status, 200); self.assertTrue(artifact['filename'].endswith('.' + extension))
            self.assertIn('模型解释与逐条核验', artifact['content'])
        self.assertEqual(self.provider.calls, 1); self.assertFalse(self.db.exists())
        self.assertEqual(self.post('/api/export', {**self.payload, 'export_request': export}, token='wrong')[0], 403)
        export['generation']['explanation']['model'] = 'forged'
        self.assertEqual(self.post('/api/export', {**self.payload, 'export_request': export})[0], 400)
        self.assertFalse(self.db.exists())

    def test_no_store_or_model_required_for_source_report(self):
        self.server.review_db = None; self.server.semantic_provider = None
        status, artifact = self.post('/api/export', {**self.payload, 'export_request': request()})
        self.assertEqual(status, 200)
        self.assertIn('本报告未附模型解释', artifact['content'])
        self.assertEqual(self.provider.calls, 0)
        self.assertEqual(self.post('/api/export', {**self.payload, 'export_request': {}})[0], 400)


if __name__ == '__main__':
    unittest.main()
