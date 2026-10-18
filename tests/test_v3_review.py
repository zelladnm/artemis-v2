"""Analyst decision persistence and CLI checks, only synthetic evidence."""
from concurrent.futures import ThreadPoolExecutor
import contextlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from artemis_v3.cape import load_cape_report
from artemis_v3.cli import main
from artemis_v3.review import ReviewError, list_reviews, load_review_request, record_review
from artemis_v3.ruleset import RuleSet, load_ruleset
from artemis_v3.scoring import SignatureRule

FIXTURES = Path(__file__).parent / 'fixtures'


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / 'reviews.sqlite'
        self.report = load_cape_report(FIXTURES / 'cape_synthetic.json', synthetic=True)
        self.catalog = load_ruleset(FIXTURES / 'scoring_synthetic.json')
        self.request = {
            'source_sha256': self.report.source_sha256, 'ruleset_sha256': self.catalog.source_sha256,
            'delta': -1, 'cited_evidence': [self.report.evidence[-1].evidence_id],
            'rationale': 'Synthetic contextual proposal', 'reviewer': 'test-analyst',
            'decision': 'approve', 'reason': 'Synthetic fixture reviewed', 'expected_previous_id': None}

    def test_round_trip_preserves_base_and_records_declared_identity(self):
        record = record_review(self.db, self.report, self.catalog, self.request)
        self.assertEqual(record['base_score'], 1)
        self.assertEqual(record['analyst_score'], 0)
        self.assertEqual(record['proposal']['applied_score'], 1)
        self.assertEqual(record['assessment']['base_score'], 1)
        self.assertEqual(record['identity_kind'], 'self_declared_local')
        self.assertEqual(record['verdict'], 'not_assessed')
        self.assertTrue(record['assessment']['synthetic'])
        self.assertEqual(list_reviews(self.db), [record])

    def test_reject_defer_and_revision_history(self):
        first = record_review(self.db, self.report, self.catalog, {**self.request, 'decision': 'defer'})
        second = record_review(self.db, self.report, self.catalog,
                               {**self.request, 'decision': 'reject', 'expected_previous_id': first['review_id']})
        self.assertIsNone(first['analyst_score'])
        self.assertIsNone(second['analyst_score'])
        self.assertEqual(second['revision'], 2)
        self.assertEqual(second['previous_review_id'], first['review_id'])
        self.assertEqual(list_reviews(self.db, proposal_sha256=first['proposal_sha256']), [second, first])

    def test_stale_write_cannot_overwrite_history(self):
        record = record_review(self.db, self.report, self.catalog, self.request)
        with self.assertRaises(ReviewError):
            record_review(self.db, self.report, self.catalog, self.request)
        self.assertEqual(list_reviews(self.db), [record])

    def test_changed_source_or_catalog_is_rejected_before_db_creation(self):
        for key in ('source_sha256', 'ruleset_sha256'):
            with self.subTest(key=key), self.assertRaises(ReviewError):
                record_review(self.db, self.report, self.catalog, {**self.request, key: 'b' * 64})
        self.assertFalse(self.db.exists())

    def test_critical_negative_cannot_be_approved(self):
        catalog = RuleSet('demo-critical/1', (SignatureRule('R', 'synthetic_behavior', 8, True),), 'b' * 64, True)
        request = {**self.request, 'ruleset_sha256': catalog.source_sha256, 'delta': -8}
        with self.assertRaises(ReviewError):
            record_review(self.db, self.report, catalog, request)
        self.assertFalse(self.db.exists())
        rejected = record_review(self.db, self.report, catalog, {**request, 'decision': 'reject'})
        self.assertEqual(rejected['proposal']['status'], 'blocked_critical_signal')
        self.assertEqual(rejected['base_score'], 8)
        self.assertIsNone(rejected['analyst_score'])

    def test_invalid_requests_citations_and_io(self):
        for change in ({'reviewer': ''}, {'decision': 'automatic'}, {'reason': ' '}, {'delta': True},
                       {'cited_evidence': ['unknown']}, {'cited_evidence': [[]]},
                       {'expected_previous_id': 1}, {'unknown': 'extra'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                record_review(self.db, self.report, self.catalog, {**self.request, **change})
        self.assertFalse(self.db.exists())
        with self.assertRaises(ReviewError):
            record_review(self.db / 'missing.sqlite', self.report, self.catalog, self.request)

    def test_concurrent_first_decisions_cannot_both_succeed(self):
        def write(_):
            try:
                return record_review(self.db, self.report, self.catalog, self.request)
            except ReviewError:
                return None
        with ThreadPoolExecutor(max_workers=2) as workers:
            records = list(workers.map(write, range(2)))
        self.assertEqual(sum(r is not None for r in records), 1)
        self.assertEqual(len(list_reviews(self.db)), 1)

    def test_corrupt_body_is_detected_and_unrelated_database_untouched(self):
        record_review(self.db, self.report, self.catalog, self.request)
        with sqlite3.connect(self.db) as connection:
            connection.execute("UPDATE reviews SET body='{}'")
        with self.assertRaises(ReviewError):
            list_reviews(self.db)
        other = Path(self.temp.name) / 'other.sqlite'
        with sqlite3.connect(other) as connection:
            connection.execute('CREATE TABLE unrelated (value TEXT)')
        with self.assertRaises(ReviewError):
            record_review(other, self.report, self.catalog, self.request)
        with sqlite3.connect(other) as connection:
            self.assertEqual(connection.execute('PRAGMA user_version').fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT name FROM sqlite_master').fetchall(), [('unrelated',)])

    def test_unrelated_version_one_database_is_rejected(self):
        with sqlite3.connect(self.db) as connection:
            connection.execute('PRAGMA user_version = 1')
        with self.assertRaises(ReviewError):
            record_review(self.db, self.report, self.catalog, self.request)
        with sqlite3.connect(self.db) as connection:
            self.assertEqual(connection.execute('PRAGMA application_id').fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT name FROM sqlite_master').fetchall(), [])

    def test_failed_insert_rolls_back_store_creation(self):
        original_connect = sqlite3.connect
        class FailingInsert(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if sql.startswith('INSERT INTO reviews'):
                    raise sqlite3.OperationalError('synthetic storage failure')
                return super().execute(sql, parameters)
        def connect(*args, **kwargs):
            return original_connect(*args, **kwargs, factory=FailingInsert)
        with patch('artemis_v3.review.sqlite3.connect', side_effect=connect), self.assertRaises(ReviewError):
            record_review(self.db, self.report, self.catalog, self.request)
        with original_connect(self.db) as connection:
            self.assertEqual(connection.execute('SELECT name FROM sqlite_master').fetchall(), [])
            self.assertEqual(connection.execute('PRAGMA user_version').fetchone()[0], 0)

    def test_history_markdown_escapes_untrusted_reviewer_and_reason(self):
        hostile = '<script>bad()</script>```'
        record_review(self.db, self.report, self.catalog,
                      {**self.request, 'reviewer': hostile, 'reason': hostile})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(['--review-history', str(self.db)]), 0)
        self.assertNotIn('<script>', output.getvalue())
        self.assertNotIn('```', output.getvalue())
        self.assertEqual(list_reviews(self.db)[0]['reason'], hostile)

    def test_history_read_is_readonly_and_bounded(self):
        with self.assertRaises(ReviewError):
            list_reviews(self.db)
        self.assertFalse(self.db.exists())
        record_review(self.db, self.report, self.catalog, self.request)
        for limit in (0, 1001, True):
            with self.assertRaises(ReviewError):
                list_reviews(self.db, limit=limit)
        self.assertEqual(len(list_reviews(self.db, limit=1)), 1)

    def test_request_json_limits_and_duplicate_keys(self):
        path = Path(self.temp.name) / 'request.json'
        path.write_text(json.dumps(self.request))
        self.assertEqual(load_review_request(path), self.request)
        with patch('artemis_v3.review.MAX_REQUEST_BYTES', 2), self.assertRaises(ReviewError):
            load_review_request(path)
        for raw in (b'{"x":1,"x":2}', b'\xff', b'{"x":NaN}', b'[]', b'[' * 2000 + b']' * 2000):
            path.write_bytes(raw)
            with self.assertRaises(ReviewError):
                load_review_request(path)

    def test_cli_template_write_history_round_trip_offline(self):
        args = ['--cape-report', str(FIXTURES / 'cape_synthetic.json'), '--synthetic',
                '--ruleset', str(FIXTURES / 'scoring_synthetic.json'), '--format', 'json']
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(args + ['--review-template']), 0)
        template = json.loads(output.getvalue())['review_request_template']
        self.assertEqual(template['source_sha256'], self.request['source_sha256'])
        self.assertEqual(template['reviewer'], '')
        request_path = Path(self.temp.name) / 'request.json'
        request_path.write_text(json.dumps(self.request))
        output = io.StringIO()
        with patch('socket.socket', side_effect=AssertionError('network')), contextlib.redirect_stdout(output):
            self.assertEqual(main(args + ['--review-request', str(request_path), '--review-db', str(self.db)]), 0)
        record = json.loads(output.getvalue())['analyst_review']
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(['--review-history', str(self.db), '--format', 'json']), 0)
        self.assertEqual(json.loads(output.getvalue())['reviews'], [record])

    def test_cli_rejects_ambiguous_write_options(self):
        cases = [['--review-db', str(self.db)], ['demo.example', '--review-template'],
                 ['--review-history', str(self.db), 'demo.example'],
                 ['--cape-report', str(FIXTURES / 'cape_synthetic.json'),
                  '--ruleset', str(FIXTURES / 'scoring_synthetic.json'), '--review-db', str(self.db)]]
        for args in cases:
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                main(args)
            self.assertEqual(caught.exception.code, 2)
        self.assertFalse(self.db.exists())


if __name__ == '__main__':
    unittest.main()
