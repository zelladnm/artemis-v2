"""Synthetic offline evaluation handoff, exact saved revisions and HTTP boundaries."""
import base64
import copy
from io import BytesIO
import http.client
import json
from pathlib import Path
import secrets
import shutil
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch
import zipfile

from artemis_v3.claim_review import explanation_claims, issue_receipt, list_claim_reviews, record_claim_review, review_template
from artemis_v3.evaluation import (EvaluationError, ReplayProvider, digest, encode, load_suite,
                                  run_suite, summarize_ratings)
from artemis_v3.evaluation_review import EvaluationReview
from artemis_v3.semantic import OllamaLocalProvider
from artemis_v3.workbench import WorkbenchServer

FIXTURES = Path(__file__).parent / 'fixtures/semantic_eval'


class EvaluationReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sources = self.root / 'sources'; shutil.copytree(FIXTURES, self.sources)
        self.suite = self.sources / 'historical_suite.json'
        self.out = self.root / 'run'
        run_suite(self.suite, self.out, replay_path=self.sources / 'historical_replay.json')
        self.path = self.out / 'run.json'; self.database = self.root / 'reviews.sqlite'
        self.run = json.loads(self.path.read_bytes())
        self.session = EvaluationReview(self.suite, self.path)
        self.key = secrets.token_bytes(32)

    def save(self, case_id='history_false_current', iteration=1, *, session=None, previous=None):
        session = session or self.session
        item = session.select({'case_id': case_id, 'iteration': iteration})
        generation = item['generation']; request = review_template(generation)
        request.update(reviewer='synthetic analyst', expected_previous_id=previous)
        index = next((index for index, claim in enumerate(explanation_claims(generation['explanation']))
                      if claim['source_scope'] == 'historical'), 0)
        request['items'][index].update(rating='unsupported', reason='The cited prior event is not a current observation')
        record = record_claim_review(self.database, item['report'], item['catalog'], generation,
                                    issue_receipt(self.key, generation), self.key, request)
        return {'case_id': case_id, 'iteration': iteration, 'review_id': record['review_id']}, record

    def export(self, selections=(), session=None):
        session = session or self.session
        return session.export({'run_sha256': session.run_sha256, 'reviewer': 'synthetic coordinator',
                               'selections': list(selections)}, self.database)

    def test_historical_source_open_has_exact_generation_and_no_model_call(self):
        with patch.object(OllamaLocalProvider, 'generate', side_effect=AssertionError('No model')):
            session = EvaluationReview(self.suite, self.path)
            row = next(item for item in self.run['attempts'] if item['explanation'].get('historical_context'))
            opened = session.open({'case_id': row['case_id'], 'iteration': row['iteration']})
        self.assertEqual(opened['generation']['explanation'], row['explanation'])
        self.assertTrue(opened['generation']['explanation']['historical_context']['evidence'])
        self.assertEqual(digest(base64.b64decode(opened['inputs']['report'])), row['explanation']['report_sha256'])
        self.assertFalse(session.inventory()['model_called'])
        self.assertFalse(self.database.exists())
        opened['generation']['explanation']['limitations'].append('browser edit')
        self.assertNotEqual(opened, session.open({'case_id': row['case_id'], 'iteration': row['iteration']}))

    def test_export_matches_cli_and_keeps_unselected_unreviewed(self):
        original = self.path.read_bytes(); selection, record = self.save()
        exported = self.export([selection])
        with zipfile.ZipFile(BytesIO(base64.b64decode(exported['content_b64']))) as bundle:
            self.assertEqual(set(bundle.namelist()), {'ratings.json', 'bindings.json', 'summary.json'})
            ratings_raw = bundle.read('ratings.json'); ratings = json.loads(ratings_raw)
            bindings = json.loads(bundle.read('bindings.json'))
            ratings_path = self.root / 'ratings.json'; ratings_path.write_bytes(ratings_raw)
            self.assertEqual(summarize_ratings(self.path, ratings_path), exported['summary'])
            self.assertEqual(json.loads(bundle.read('summary.json')), exported['summary'])
        self.assertEqual(sum(item['rating'] == 'unsupported' for item in ratings['items']), 1)
        self.assertTrue(all(item['rating'] == 'unreviewed' for item in ratings['items'] if item['case_id'] != selection['case_id']))
        self.assertEqual(bindings['selections'][0]['record_sha256'], digest(encode(record)))
        self.assertEqual(bindings['ratings_sha256'], digest(ratings_raw))
        self.assertEqual(bindings['selections'][0]['reviewer'], 'synthetic analyst')
        self.assertEqual(ratings['reviewer'], 'synthetic coordinator')
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(record['score_decision'], 'not_recorded_by_claim_review')
        self.assertEqual(exported['summary']['by_source_scope']['historical']['unsupported'], 1)

    def test_blank_export_reads_no_database_and_reports_no_support(self):
        result = self.export()
        self.assertFalse(self.database.exists())
        self.assertEqual(result['summary']['by_section']['source_observations']['coverage'], 0)
        self.assertIsNone(result['summary']['by_section']['source_observations']['supported_fraction_of_rated'])
        self.assertEqual(len(result['bindings']['unselected_attempts']), 5)

    def test_explicit_revision_is_preserved_after_later_revision(self):
        selection, first = self.save()
        later, second = self.save(previous=first['review_id'])
        self.assertEqual(self.export([selection])['bindings']['selections'][0]['revision'], 1)
        self.assertEqual(self.export([later])['bindings']['selections'][0]['revision'], 2)
        self.assertEqual(second['previous_review_id'], first['review_id'])

    def test_mismatched_review_output_missing_duplicate_and_invalid_ids_refused(self):
        selection, _ = self.save()
        other = next(key for key in self.session.attempts if key[0] != selection['case_id'])
        mutations = [[selection, selection], [{**selection, 'case_id': other[0]}],
                     [{**selection, 'review_id': 'bad'}], [{**selection, 'iteration': True}],
                     [{**selection, 'case_id': []}], [{**selection, 'path': '/tmp/untrusted'}]]
        for selections in mutations:
            with self.subTest(selections=selections), self.assertRaises(ValueError):
                self.export(selections)
        with self.assertRaises(EvaluationError):
            self.session.export({'run_sha256': '0'*64, 'reviewer': '', 'selections': []}, self.database)

    def test_run_source_prompt_context_scope_and_status_tampering_refused(self):
        original = copy.deepcopy(self.run)
        mutations = [lambda r: r.update(suite_sha256='0'*64), lambda r: r.pop('summary'),
                     lambda r: r.update(prompt_sha256='0'*64),
                     lambda r: r['implementation_sha256'].update(semantic='0'*64),
                     lambda r: r['attempts'][0].update(iteration=True),
                     lambda r: r['attempts'][0].update(status='rejected'),
                     lambda r: r['attempts'][0]['explanation'].update(context_sha256='0'*64),
                     lambda r: r['attempts'][0]['explanation']['source_observations'][0].update(source_scope='mixed'),
                     lambda r: r['summary'].update(accepted=0), lambda r: r['attempts'].pop(),
                     lambda r: r['summary'].update(critical_negative_blocked=999),
                     lambda r: r['summary']['by_context']['with_history'].update(failed=1),
                     lambda r: r['attempts'][0].update(base_score=0)]
        for mutation in mutations:
            value = copy.deepcopy(original); mutation(value); self.path.write_bytes(encode(value))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                EvaluationReview(self.suite, self.path)
        self.path.write_bytes(encode(original))
        case = self.run['cases'][0]; report = self.sources / case['report']
        report.write_bytes(report.read_bytes() + b' ')
        with self.assertRaisesRegex(EvaluationError, 'fingerprint'):
            EvaluationReview(self.suite, self.path)

    def test_loaded_snapshot_stays_fixed_when_files_change_after_startup(self):
        key = next(iter(self.session.attempts)); before = self.session.open(dict(zip(('case_id', 'iteration'), key)))
        self.path.write_bytes(b'changed')
        for file in self.sources.glob('*.json'):
            file.write_bytes(b'changed')
        self.assertEqual(self.session.open(dict(zip(('case_id', 'iteration'), key))), before)
        self.assertEqual(self.export()['bindings']['run_sha256'], digest(encode(self.run)))

    def test_failed_attempt_is_visible_and_cannot_receive_a_review(self):
        suite = self.sources / 'suite.json'; replay = self.sources / 'replay.json'
        value = json.loads(replay.read_bytes()); first_id = next(iter(value['outputs']))
        value['outputs'][first_id]['source_observations'][0]['evidence_refs'] = ['invented']
        replay.write_bytes(encode(value)); destination = self.root / 'rejected'
        run = run_suite(suite, destination, replay_path=replay)
        session = EvaluationReview(suite, destination / 'run.json')
        opened = session.open({'case_id': first_id, 'iteration': 1})
        self.assertIsNone(opened['generation']); self.assertEqual(opened['attempt']['status'], 'rejected')
        self.assertEqual(session.inventory()['attempts'][0]['status'], 'rejected')
        self.assertEqual(run['summary']['failed'], 1)
        with self.assertRaises(EvaluationError):
            self.export([{'case_id': first_id, 'iteration': 1, 'review_id': 'unused'}], session)

    def test_repeated_identical_outputs_require_explicit_per_attempt_selection(self):
        suite, _, _ = load_suite(self.suite)
        outputs = json.loads((self.sources / 'historical_replay.json').read_bytes())['outputs']
        case = suite['cases'][0]; suite['cases'] = [case]
        one = self.sources / 'one.json'; one.write_bytes(encode(suite))
        class PinnedFixture(ReplayProvider):
            expected_digest = 'c'*64
            def generate(self, context):
                return {**super().generate(context), 'model_digest': self.expected_digest}
        destination = self.root / 'repeated'
        run_suite(one, destination, provider=PinnedFixture('synthetic-pinned-fixture', outputs[case['case_id']]), repeat=2)
        session = EvaluationReview(one, destination / 'run.json')
        selection, _ = self.save(case['case_id'], session=session)
        result = self.export([selection], session)
        self.assertEqual(result['bindings']['unselected_attempts'], [{'case_id': case['case_id'], 'iteration': 2}])
        self.assertEqual(len(self.export([selection, {**selection, 'iteration': 2}], session)['bindings']['selections']), 2)

    def test_legacy_single_source_run_keeps_ratings_v1_contract(self):
        suite = self.sources / 'suite.json'; destination = self.root / 'single'
        run_suite(suite, destination, replay_path=self.sources / 'replay.json')
        session = EvaluationReview(suite, destination / 'run.json')
        selection, _ = self.save(next(iter(session.attempts))[0], session=session)
        result = self.export([selection], session)
        with zipfile.ZipFile(BytesIO(base64.b64decode(result['content_b64']))) as bundle:
            ratings = json.loads(bundle.read('ratings.json'))
        self.assertEqual(ratings['schema_version'], 'artemis-eval-ratings/1')
        self.assertTrue(all('source_scope' not in item for item in ratings['items']))
        self.assertEqual(result['summary']['schema_version'], 'artemis-eval-human-summary/1')

    def test_malformed_nested_input_and_unpinned_model_are_bounded_errors(self):
        mutations = [lambda r: r.update(summary=[]), lambda r: r.update(cases=None),
                     lambda r: r['attempts'][0]['explanation'].update(source_observations=[None]),
                     lambda r: r['attempts'][0].update(elapsed_ms=10**500),
                     lambda r: r.update(mode='local_model', requested_model_digest=None)]
        for mutation in mutations:
            value = copy.deepcopy(self.run); mutation(value); self.path.write_bytes(encode(value))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                EvaluationReview(self.suite, self.path)

    def test_generation_filter_finds_older_exact_output_after_twenty_other_generations(self):
        selection, first = self.save()
        item = self.session.select({key: selection[key] for key in ('case_id', 'iteration')})
        for index in range(21):
            generation = copy.deepcopy(item['generation'])
            generation['explanation']['model_response_sha256'] = f'{index:064x}'
            request = review_template(generation); request['reviewer'] = 'synthetic other output'
            record_claim_review(self.database, item['report'], item['catalog'], generation,
                                issue_receipt(self.key, generation), self.key, request)
        self.assertNotIn(first, list_claim_reviews(self.database, item['report'], item['catalog']))
        self.assertEqual(list_claim_reviews(self.database, item['report'], item['catalog'],
                         generation_sha256=first['generation_sha256']), [first])

    def test_http_open_save_export_and_origin_token_guard_without_model(self):
        server = WorkbenchServer(0, review_db=self.database, evaluation=self.session)
        thread = Thread(target=server.serve_forever, daemon=True); thread.start()
        self.addCleanup(server.server_close); self.addCleanup(thread.join); self.addCleanup(server.shutdown)
        def call(path, data=None, token=None):
            connection = http.client.HTTPConnection('127.0.0.1', server.server_port)
            headers = {'X-Artemis-Token': token if token is not None else server.token}
            if data is not None: headers['Content-Type'] = 'application/json'
            connection.request('GET' if data is None else 'POST', path, encode(data) if data is not None else None, headers)
            response = connection.getresponse(); body = json.loads(response.read()); connection.close()
            return response.status, body
        self.assertEqual(call('/api/evaluation', token='wrong')[0], 403)
        self.assertFalse(call('/api/config')[1]['model_enabled'])
        self.assertEqual(call('/api/evaluation')[1]['run_sha256'], self.session.run_sha256)
        selection = {'case_id': self.run['cases'][0]['case_id'], 'iteration': 1}
        status, opened = call('/api/evaluation/open', selection); self.assertEqual(status, 200)
        result = opened['result']; generation = {key: result[key] for key in ('suggestion_file_b64',)}
        generation['explanation'] = result['semantic_review']
        request = result['claim_template']; request['reviewer'] = '<img src=x> synthetic analyst'
        request['items'][0].update(rating='uncertain', reason='Synthetic HTTP evidence check')
        status, saved = call('/api/claims/save', {**opened['inputs'], 'generation': generation,
                            'claim_receipt': result['claim_receipt'], 'claim_request': request})
        self.assertEqual(status, 200); review = saved['claim_review']
        status, exported = call('/api/evaluation/export', {'run_sha256': self.session.run_sha256,
            'reviewer': 'synthetic coordinator', 'selections': [{**selection, 'review_id': review['review_id']}]})
        self.assertEqual(status, 200); self.assertTrue(exported['content_b64'])
        self.assertEqual(call('/api/evaluation/open', {**selection, 'report': 'client override'})[0], 400)
        status, history = call('/api/claims/list', {**opened['inputs'], 'claim_generation_sha256': review['generation_sha256']})
        self.assertEqual(status, 200); self.assertEqual(len(history['reviews']), 1)
        self.assertEqual(call('/api/claims/list', {**opened['inputs'], 'claim_generation_sha256': 'bad'})[0], 400)
        self.assertEqual(call('/api/explain', opened['inputs'])[0], 409)

    def test_evaluation_mode_requires_explicit_review_db_and_no_provider(self):
        with self.assertRaises(ValueError):
            WorkbenchServer(0, evaluation=self.session)
        with self.assertRaises(ValueError):
            WorkbenchServer(0, evaluation=self.session, review_db=self.database, semantic_provider=object())


if __name__ == '__main__':
    unittest.main()
