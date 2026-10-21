"""Synthetic claim judgments: snapshot binding, durable revisions and HTTP flow."""
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
import http.client
import json
from pathlib import Path
import secrets
import sqlite3
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

from artemis_v3.cape import load_cape_report, parse_cape_report
from artemis_v3.claim_review import check_saved_inputs, issue_receipt, list_claim_reviews, record_claim_review, review_template
from artemis_v3.historical import prepare_historical_source
from artemis_v3.review import APPLICATION_ID, ReviewError, list_reviews, record_review
from artemis_v3.ruleset import RuleSet, load_ruleset
from artemis_v3.scoring import SignatureRule
from artemis_v3.semantic import explain
from artemis_v3.workbench import WorkbenchServer
from test_v3_semantic import StubProvider, output

FIXTURES = Path(__file__).parent / 'fixtures'


def generation(report, catalog=None, *, provider=None, historical=None):
    explanation, suggestion = explain(report, provider or StubProvider(), catalog=catalog, historical=historical)
    return {'explanation': explanation, 'suggestion_file_b64': base64.b64encode(suggestion).decode() if suggestion else None}


class ClaimReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.db = Path(temporary.name) / 'review.sqlite'
        self.report = load_cape_report(FIXTURES / 'cape_synthetic.json', synthetic=True)
        self.catalog = load_ruleset(FIXTURES / 'scoring_synthetic.json')
        self.key = secrets.token_bytes(32)
        self.generation = generation(self.report, self.catalog)
        self.receipt = issue_receipt(self.key, self.generation)
        self.request = review_template(self.generation)
        self.request['reviewer'] = 'synthetic analyst'
        self.request['items'][0].update(rating='unsupported', reason='Synthetic counterexample requires further evidence')

    def save(self, **changes):
        args = dict(database=self.db, report=self.report, catalog=self.catalog, generation=self.generation,
                    receipt=self.receipt, secret=self.key, request=self.request)
        args.update(changes)
        return record_claim_review(**args)

    def test_round_trip_default_unreviewed_and_source_snapshot(self):
        original = copy.deepcopy(self.generation)
        record = self.save()
        self.assertEqual(list_claim_reviews(self.db, self.report, self.catalog), [record])
        self.assertEqual(record['generation'], original)
        self.assertEqual(self.generation, original)
        self.assertEqual(record['summary']['counts'], {'supported': 0, 'unsupported': 1, 'uncertain': 0, 'unreviewed': 1})
        self.assertEqual(record['summary']['coverage'], 0.5)
        self.assertEqual(record['base_score'], 1)
        self.assertEqual(record['identity_kind'], 'self_declared_local')
        self.assertEqual(record['score_decision'], 'not_recorded_by_claim_review')
        self.assertEqual(record['verdict'], 'not_assessed')
        self.assertEqual(record['current_evidence'][0]['evidence_id'], record['items'][0]['evidence_refs'][0])
        self.assertEqual(list_reviews(self.db), [])
        self.assertNotIn('receipt', json.dumps(record))

    def test_receipt_covers_text_citations_scopes_metadata_and_suggestion(self):
        for mutate in (lambda g: g['explanation']['source_observations'][0].update(text='changed'),
                       lambda g: g['explanation']['source_observations'][0].update(evidence_refs=['invented']),
                       lambda g: g['explanation']['source_observations'][0].update(source_scope='historical'),
                       lambda g: g['explanation'].update(model='other'),
                       lambda g: g.update(suggestion_file_b64='e30=')):
            altered = copy.deepcopy(self.generation); mutate(altered)
            with self.assertRaisesRegex(ReviewError, 'receipt'):
                self.save(generation=altered)
        for receipt in (None, '', 'é'*64, '0'*64, [], {}):
            with self.subTest(receipt=receipt), self.assertRaises(ReviewError):
                self.save(receipt=receipt)
        with self.assertRaises(ReviewError):
            self.save(secret=secrets.token_bytes(32))
        self.assertFalse(self.db.exists())

    def test_report_rules_and_provenance_are_bound_before_write(self):
        changed = parse_cape_report((FIXTURES / 'cape_synthetic.json').read_bytes() + b' ', synthetic=True)
        real_label = load_cape_report(FIXTURES / 'cape_synthetic.json', synthetic=False)
        other_rules = RuleSet(self.catalog.version, self.catalog.rules, 'b'*64, True)
        for changes in ({'report': changed}, {'report': real_label}, {'catalog': None}, {'catalog': other_rules}):
            with self.subTest(changes=changes), self.assertRaises(ReviewError):
                self.save(**changes)
        self.assertFalse(self.db.exists())
        self.save()
        self.assertEqual(list_claim_reviews(self.db, changed, self.catalog), [])
        self.assertEqual(list_claim_reviews(self.db, real_label, self.catalog), [])
        self.assertEqual(list_claim_reviews(self.db, self.report, other_rules), [])

    def test_request_requires_exact_claim_set_ratings_reason_and_reviewer(self):
        bad = [dict(self.request, reviewer=' '), dict(self.request, reviewer='x'*101),
               dict(self.request, generation_sha256='f'*64), dict(self.request, unexpected=True),
               dict(self.request, expected_previous_id=[]), dict(self.request, items=[]),
               dict(self.request, items=self.request['items'][::-1]),
               dict(self.request, items=[self.request['items'][0]]*2)]
        for changes in ({'rating': 'approved'}, {'rating': []}, {'reason': ' '}, {'reason': 'x'*1001},
                        {'claim_id': 'invented'}, {'text': 'editable model prose'}):
            value = copy.deepcopy(self.request); value['items'][0].update(changes); bad.append(value)
        for request in bad:
            with self.subTest(request=request), self.assertRaises(ReviewError):
                self.save(request=request)
        self.assertFalse(self.db.exists())

    def test_revision_stale_and_concurrent_writes_never_overwrite(self):
        def attempt(_):
            try:
                return self.save()
            except ReviewError:
                return None
        with ThreadPoolExecutor(max_workers=2) as workers:
            writes = list(workers.map(attempt, range(2)))
        self.assertEqual(sum(item is not None for item in writes), 1)
        first = next(item for item in writes if item is not None)
        self.request['expected_previous_id'] = first['review_id']
        self.request['items'][0].update(rating='uncertain', reason='Revised synthetic assessment')
        second = self.save()
        self.assertEqual(second['revision'], 2)
        self.assertEqual(second['previous_review_id'], first['review_id'])
        with self.assertRaisesRegex(ReviewError, 'Stale'):
            self.save()
        self.assertEqual(list_claim_reviews(self.db, self.report, self.catalog), [second, first])

    def test_different_generation_does_not_reuse_ratings(self):
        first = self.save()
        altered_output = output(self.report.evidence[0].evidence_id)
        altered_output['source_observations'][0]['text'] = 'Different model statement'
        second_generation = generation(self.report, self.catalog, provider=StubProvider(altered_output))
        template = review_template(second_generation)
        self.assertNotEqual(template['generation_sha256'], first['generation_sha256'])
        self.assertTrue(all(item['rating'] == 'unreviewed' for item in template['items']))
        self.assertIsNone(template['expected_previous_id'])
        with self.assertRaisesRegex(ReviewError, 'different generation'):
            self.save(generation=second_generation, receipt=issue_receipt(self.key, second_generation))

    def test_reopening_rejects_changed_parser_view_or_score(self):
        record = self.save()
        check_saved_inputs(record, self.report, self.catalog)
        changed = copy.deepcopy(self.report)
        referenced = next(item for item in changed.evidence if item.evidence_id == record['current_evidence'][0]['evidence_id'])
        referenced.data['changed_by_new_parser'] = True
        with self.assertRaisesRegex(ReviewError, 'implementation'):
            check_saved_inputs(record, changed, self.catalog)
        with patch('artemis_v3.claim_review.assess_signatures') as assessment:
            assessment.return_value.base_score = 7
            with self.assertRaisesRegex(ReviewError, 'implementation'):
                check_saved_inputs(record, self.report, self.catalog)

    def test_report_only_supports_review_without_rules_or_provider(self):
        value = generation(self.report)
        request = review_template(value); request['reviewer'] = 'synthetic analyst'
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            record = self.save(catalog=None, generation=value, receipt=issue_receipt(self.key, value), request=request)
        self.assertIsNone(record['base_score'])
        self.assertEqual(record['summary']['reviewed'], 0)
        self.assertEqual(record['summary']['coverage'], 0)

    def test_historical_false_current_claim_can_be_explicitly_rejected(self):
        current_raw = (FIXTURES / 'semantic_eval/history_current.json').read_bytes()
        report = parse_cape_report(current_raw, synthetic=True)
        prior_raw = (FIXTURES / 'semantic_eval/history_prior.json').read_bytes()
        history = prepare_historical_source('synthetic-history', prior_raw, report, current_raw, synthetic=True)
        class HistoricalProvider:
            model = 'synthetic-history'
            def generate(self, context):
                current = context['evidence'][0]['evidence_id']; prior = context['historical_context']['evidence'][0]['evidence_id']
                value = output(prior)
                value['source_observations'][0]['text'] = '当前分析已确认成功注入。'  # Deliberately unsupported.
                value['hypotheses'][0]['evidence_refs'] = [current, prior]
                return {'output': value}
        value = generation(report, provider=HistoricalProvider(), historical=history)
        request = review_template(value); request['reviewer'] = 'synthetic analyst'
        request['items'][0].update(rating='unsupported', reason='历史来源不能证明当前执行成功')
        record = self.save(report=report, catalog=None, generation=value, receipt=issue_receipt(self.key, value), request=request)
        self.assertEqual(record['items'][0]['source_scope'], 'historical')
        self.assertEqual(record['items'][1]['source_scope'], 'mixed')
        self.assertEqual(record['summary']['by_source_scope']['historical']['unsupported'], 1)
        self.assertEqual(record['summary']['by_source_scope']['mixed']['unreviewed'], 1)
        self.assertTrue(record['generation']['explanation']['historical_context']['evidence'])

    def test_support_for_critical_adjustment_never_approves_it(self):
        critical = next(item for item in self.report.evidence if item.category == 'signature')
        catalog = RuleSet('critical-test', (SignatureRule('C', critical.data['name'], 8, True),), 'b'*64, True)
        value = output(critical.evidence_id)
        value['adjustment'] = {'delta': -8, 'rationale': 'Synthetic rationale', 'cited_evidence': [critical.evidence_id]}
        generated = generation(self.report, catalog, provider=StubProvider(value))
        request = review_template(generated); request['reviewer'] = 'synthetic analyst'
        request['items'][-1].update(rating='supported', reason='Human judgment is not approval')
        record = self.save(catalog=catalog, generation=generated, receipt=issue_receipt(self.key, generated), request=request)
        self.assertEqual(record['base_score'], 8)
        self.assertEqual(record['items'][-1]['section'], 'adjustment')
        proposal = record['generation']['explanation']['proposal_review']['adjustment_proposal']
        self.assertEqual(proposal['status'], 'blocked_critical_signal')
        self.assertEqual(proposal['applied_score'], 8)
        self.assertEqual(list_reviews(self.db), [])

    def make_v1_store(self):
        request = {'source_sha256': self.report.source_sha256, 'ruleset_sha256': self.catalog.source_sha256,
                   'delta': 0, 'cited_evidence': [self.report.evidence[0].evidence_id], 'rationale': 'Synthetic',
                   'reviewer': 'synthetic analyst', 'decision': 'defer', 'reason': 'Synthetic', 'expected_previous_id': None}
        original = record_review(self.db, self.report, self.catalog, request)
        with sqlite3.connect(self.db) as connection:
            connection.execute('DROP TABLE claim_reviews')
            connection.execute('PRAGMA user_version = 1')
        return original

    def test_v1_reads_do_not_migrate_and_explicit_write_keeps_score_history(self):
        original = self.make_v1_store()
        before = self.db.read_bytes()
        self.assertEqual(list_claim_reviews(self.db, self.report, self.catalog), [])
        self.assertEqual(self.db.read_bytes(), before)
        self.save()
        self.assertEqual(list_reviews(self.db), [original])
        with sqlite3.connect(self.db) as connection:
            self.assertEqual(connection.execute('PRAGMA user_version').fetchone()[0], 2)
            self.assertEqual(connection.execute('PRAGMA application_id').fetchone()[0], APPLICATION_ID)

    def test_failed_write_rolls_back_v1_migration(self):
        original = self.make_v1_store()
        connect = sqlite3.connect
        class FailingInsert(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if sql.startswith('INSERT INTO claim_reviews'):
                    raise sqlite3.OperationalError('Synthetic failure')
                return super().execute(sql, parameters)
        with patch('artemis_v3.claim_review.sqlite3.connect', side_effect=lambda *a, **k: connect(*a, **k, factory=FailingInsert)), self.assertRaises(ReviewError):
            self.save()
        self.assertEqual(list_reviews(self.db), [original])
        with connect(self.db) as connection:
            self.assertEqual(connection.execute('PRAGMA user_version').fetchone()[0], 1)
            self.assertFalse(connection.execute("SELECT name FROM sqlite_master WHERE name='claim_reviews'").fetchone())

    def test_corruption_limits_and_unrelated_database(self):
        self.assertEqual(list_claim_reviews(self.db, self.report, self.catalog), [])
        self.assertFalse(self.db.exists())
        for limit in (0, True, 101):
            with self.assertRaises(ReviewError):
                list_claim_reviews(self.db, self.report, self.catalog, limit=limit)
        with patch('artemis_v3.claim_review.MAX_GENERATION_BYTES', 2), self.assertRaises(ReviewError):
            self.save()
        with sqlite3.connect(self.db) as connection:
            connection.execute('CREATE TABLE unrelated (value TEXT)')
        before = self.db.read_bytes()
        with self.assertRaises(ReviewError):
            self.save()
        self.assertEqual(self.db.read_bytes(), before)
        self.db.unlink(); self.save()
        with sqlite3.connect(self.db) as connection:
            connection.execute("UPDATE claim_reviews SET body='{}'")
        with self.assertRaises(ReviewError):
            list_claim_reviews(self.db, self.report, self.catalog)


class ClaimReviewHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.db = Path(self.temporary.name) / 'reviews.sqlite'
        self.server = WorkbenchServer(0, review_db=self.db, semantic_provider=StubProvider())
        self.thread = Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True); self.thread.start()
        self.payload = {'report': base64.b64encode((FIXTURES / 'cape_synthetic.json').read_bytes()).decode(), 'synthetic': True}
    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(); self.temporary.cleanup()
    def request(self, path, payload, *, token=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        connection.request('POST', path, body=json.dumps(payload), headers={'Content-Type': 'application/json',
            'X-Artemis-Token': self.server.token if token is None else token})
        response = connection.getresponse(); status, value = response.status, json.loads(response.read()); connection.close()
        return status, value
    def get_save_payload(self):
        status, result = self.request('/api/explain', self.payload)
        self.assertEqual(status, 200)
        request = result['claim_template']; request['reviewer'] = 'synthetic analyst'
        request['items'][0].update(rating='unsupported', reason='Synthetic review')
        return {**self.payload, 'claim_request': request, 'claim_receipt': result['claim_receipt'],
                'generation': {'explanation': result['semantic_review'], 'suggestion_file_b64': result['suggestion_file_b64']}}

    def test_save_list_reopen_and_revise_after_key_rotation_without_model(self):
        payload = self.get_save_payload()
        self.assertFalse(self.db.exists())
        status, result = self.request('/api/claims/save', payload)
        self.assertEqual(status, 200); first = result['claim_review']
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.server = WorkbenchServer(0, review_db=self.db)  # Real restart, no model, a fresh receipt key.
        self.thread = Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True); self.thread.start()
        status, listed = self.request('/api/claims/list', self.payload)
        self.assertEqual(status, 200); self.assertEqual(listed['reviews'][0]['review_id'], first['review_id'])
        self.assertNotIn('generation', listed['reviews'][0])
        self.assertEqual(self.request('/api/claims/save', payload)[0], 400)
        status, opened = self.request('/api/claims/open', {**self.payload, 'claim_review_id': first['review_id']})
        self.assertEqual(status, 200); self.assertEqual(opened['semantic_review'], payload['generation']['explanation'])
        payload['claim_receipt'] = opened['claim_receipt']
        payload['claim_request']['expected_previous_id'] = first['review_id']
        status, revised = self.request('/api/claims/save', payload)
        self.assertEqual(status, 200); self.assertEqual(revised['claim_review']['revision'], 2)
        changed = {**self.payload, 'synthetic': False}
        self.assertEqual(self.request('/api/claims/list', changed)[1]['reviews'], [])
        self.assertEqual(self.request('/api/claims/open', {**changed, 'claim_review_id': first['review_id']})[0], 400)

    def test_disabled_store_invalid_snapshot_and_auth_never_write(self):
        payload = self.get_save_payload()
        self.assertEqual(self.request('/api/claims/save', payload, token='wrong')[0], 403)
        altered = copy.deepcopy(payload); altered['generation']['explanation']['model'] = 'forged'
        self.assertEqual(self.request('/api/claims/save', altered)[0], 400)
        self.assertEqual(self.request('/api/claims/save', {**payload, 'generation': []})[0], 400)
        self.assertEqual(self.request('/api/claims/open', {**self.payload, 'claim_review_id': ['wrong']})[0], 400)
        self.server.review_db = None
        for route in ('save', 'list', 'open'):
            self.assertEqual(self.request('/api/claims/' + route, payload)[0], 409)
        self.assertFalse(self.db.exists())


if __name__ == '__main__':
    unittest.main()
