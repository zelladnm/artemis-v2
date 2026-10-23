"""Synthetic recovery drills, committed WAL state, corruption and failure isolation."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stderr, redirect_stdout
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tempfile
from threading import Thread
import time
import unittest
from unittest.mock import patch

from artemis_v3 import case_store, claim_review, review, storage
from artemis_v3.cape import parse_cape_report
from artemis_v3.ruleset import parse_ruleset
from artemis_v3.workbench import WorkbenchServer
from test_v3_claim_review import generation

FIXTURES = Path(__file__).parent / 'fixtures'


class StorageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.case_db = self.root / 'cases.sqlite'; self.review_db = self.root / 'reviews.sqlite'
        self.raw = b'\xef\xbb\xbf' + (FIXTURES / 'cape_synthetic.json').read_bytes().replace(b'\n', b'\r\n')
        self.rules = (FIXTURES / 'scoring_synthetic.json').read_bytes()
        self.report = parse_cape_report(self.raw, synthetic=True); self.catalog = parse_ruleset(self.rules)
        self.case = case_store.save_case(self.case_db, self.raw, rules=self.rules, synthetic=True, title='Synthetic 原始来源')['case']

    def histories(self):
        request = {'source_sha256': self.report.source_sha256, 'ruleset_sha256': self.catalog.source_sha256,
                   'delta': -1, 'cited_evidence': [self.report.evidence[0].evidence_id], 'rationale': 'Synthetic proposal',
                   'reviewer': 'Synthetic analyst', 'decision': 'defer', 'reason': 'Synthetic reason', 'expected_previous_id': None}
        first = review.record_review(self.review_db, self.report, self.catalog, request)
        second = review.record_review(self.review_db, self.report, self.catalog,
            {**request, 'decision': 'reject', 'expected_previous_id': first['review_id']})
        value = generation(self.report, self.catalog); secret = secrets.token_bytes(32)
        receipt = claim_review.issue_receipt(secret, value)
        ratings = claim_review.review_template(value); ratings['reviewer'] = 'Synthetic analyst'
        original = claim_review.record_claim_review(self.review_db, self.report, self.catalog, value, receipt, secret, ratings)
        ratings['expected_previous_id'] = original['review_id']
        ratings['items'][0].update(rating='unsupported', reason='Synthetic counterexample')
        revised = claim_review.record_claim_review(self.review_db, self.report, self.catalog, value, receipt, secret, ratings)
        return [second, first], [revised, original]

    def no_temporary_files(self):
        self.assertEqual(list(self.root.glob('.artemis-snapshot-*')), [])

    def rejected_without_publication(self, kind, source):
        before = source.read_bytes(); destination = self.root / 'must-not-exist.sqlite'
        with self.assertRaises(storage.StorageError): storage.verify(kind, source)
        with self.assertRaises(storage.StorageError): storage.snapshot(kind, source, destination)
        self.assertFalse(destination.exists()); self.assertEqual(source.read_bytes(), before)
        self.no_temporary_files()

    def test_exact_sources_survive_backup_restore_without_source_changes_or_network(self):
        before = self.case_db.read_bytes()
        backup = self.root / 'backup.sqlite'; restored = self.root / 'restored.sqlite'
        with patch('socket.socket', side_effect=AssertionError('No network')):
            result = storage.snapshot('case', self.case_db, backup)
            storage.snapshot('case', backup, restored)
            self.assertEqual(storage.verify('case', restored)['records'], {'cases': 1})
            self.assertEqual(case_store.open_case(restored, self.case['case_id']), (self.case, self.raw, self.rules))
        self.assertEqual(result['snapshot_sha256'], hashlib.sha256(backup.read_bytes()).hexdigest())
        self.assertEqual(self.case_db.read_bytes(), before)
        if os.name == 'posix': self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.no_temporary_files()
        # This also catches leaked handles on Windows.
        backup.rename(self.root / 'renamed.sqlite'); restored.unlink()

    def test_all_saved_judgments_and_revisions_survive(self):
        scores, claims = self.histories(); before = self.review_db.read_bytes()
        target = self.root / 'restored-review.sqlite'
        result = storage.snapshot('review', self.review_db, target)
        self.assertEqual(result['records'], {'reviews': 2, 'claim_reviews': 2})
        self.assertEqual(review.list_reviews(target), scores)
        self.assertEqual(claim_review.list_claim_reviews(target, self.report, self.catalog), claims)
        self.assertEqual(self.review_db.read_bytes(), before)
        self.no_temporary_files(); self.review_db.rename(self.root / 'old-review.sqlite'); target.unlink()

    def test_schema_one_is_preserved_and_not_migrated(self):
        scores, _ = self.histories()
        with closing(sqlite3.connect(self.review_db)) as connection, connection:
            connection.execute('DROP TABLE claim_reviews'); connection.execute('PRAGMA user_version=1')
        before = self.review_db.read_bytes(); target = self.root / 'legacy.sqlite'
        result = storage.snapshot('review', self.review_db, target)
        self.assertEqual(result['schema_version'], 1); self.assertEqual(result['records'], {'reviews': 2})
        self.assertEqual(storage.verify('review', target)['schema_version'], 1)
        self.assertEqual(review.list_reviews(target), scores)
        self.assertEqual(claim_review.list_claim_reviews(target, self.report, self.catalog), [])
        self.assertEqual(self.review_db.read_bytes(), before)
        with closing(sqlite3.connect(target)) as connection:
            self.assertEqual(connection.execute('PRAGMA user_version').fetchone(), (1,))

    def test_wal_commits_included_uncommitted_changes_excluded_and_copy_standalone(self):
        with closing(sqlite3.connect(self.case_db)) as writer:
            self.assertEqual(writer.execute('PRAGMA journal_mode=WAL').fetchone(), ('wal',))
            writer.execute('PRAGMA wal_autocheckpoint=0')
            writer.execute('SELECT count(*) FROM cases').fetchone()  # Keep a WAL connection open across the other commit.
            other = case_store.save_case(self.case_db, self.raw + b' ', synthetic=True)['case']
            self.assertGreater(Path(str(self.case_db) + '-wal').stat().st_size, 0)
            writer.execute('BEGIN IMMEDIATE')
            writer.execute("UPDATE cases SET metadata='uncommitted invalid metadata'")
            target = self.root / 'wal-snapshot.sqlite'
            self.assertEqual(storage.snapshot('case', self.case_db, target)['records'], {'cases': 2})
            self.assertEqual(case_store.open_case(target, other['case_id'])[1], self.raw + b' ')
            self.assertEqual(case_store.open_case(target, self.case['case_id'])[1:], (self.raw, self.rules))
            with closing(sqlite3.connect(target)) as copied:
                self.assertEqual(copied.execute('PRAGMA journal_mode').fetchone(), ('delete',))
            for suffix in storage.SIDECARS: self.assertFalse(Path(str(target) + suffix).exists())
            writer.rollback()
            self.assertEqual(writer.execute('PRAGMA journal_mode').fetchone(), ('wal',))
        self.no_temporary_files()

    def test_case_metadata_and_original_byte_corruption_rejected(self):
        for number, sql in enumerate(("UPDATE cases SET metadata='{}'", "UPDATE cases SET report=CAST(report || ' ' AS BLOB)",
                                      "UPDATE cases SET ruleset=CAST(ruleset || ' ' AS BLOB)")):
            with self.subTest(sql=sql):
                source = self.root / f'corrupt-case-{number}.sqlite'
                storage.snapshot('case', self.case_db, source)
                with closing(sqlite3.connect(source)) as connection, connection:
                    connection.execute(sql)
                    self.assertEqual(connection.execute('PRAGMA integrity_check').fetchall(), [('ok',)])
                self.rejected_without_publication('case', source)

    def test_review_checksums_and_generation_integrity_rejected(self):
        self.histories()
        for table in ('reviews', 'claim_reviews'):
            with self.subTest(table=table):
                source = self.root / f'corrupt-{table}.sqlite'
                storage.snapshot('review', self.review_db, source)
                with closing(sqlite3.connect(source)) as connection, connection:
                    connection.execute(f"UPDATE {table} SET body='{{}}' WHERE revision=1")
                self.rejected_without_publication('review', source)

    def test_missing_earlier_revisions_rejected_even_when_survivor_checksums_match(self):
        self.histories()
        for table in ('reviews', 'claim_reviews'):
            with self.subTest(table=table):
                source = self.root / f'gap-{table}.sqlite'
                storage.snapshot('review', self.review_db, source)
                with closing(sqlite3.connect(source)) as connection, connection:
                    connection.execute(f'DELETE FROM {table} WHERE revision=1')
                self.rejected_without_publication('review', source)

    def test_cross_linked_revisions_rejected_with_matching_row_checksums(self):
        self.histories()
        for table in ('reviews', 'claim_reviews'):
            with self.subTest(table=table):
                source = self.root / f'cross-linked-{table}.sqlite'
                storage.snapshot('review', self.review_db, source)
                with closing(sqlite3.connect(source)) as connection, connection:
                    record = json.loads(connection.execute(f'SELECT body FROM {table} WHERE revision=2').fetchone()[0])
                    record['previous_review_id'] = '00000000-0000-0000-0000-000000000000'
                    connection.execute(f'UPDATE {table} SET previous_review_id=?, body=?, body_sha256=? WHERE revision=2',
                        (record['previous_review_id'], review._canonical(record), review._digest(record)))
                self.rejected_without_publication('review', source)

    def test_changed_proposal_or_generation_rejected_after_row_checksum_is_recomputed(self):
        self.histories()
        for table in ('reviews', 'claim_reviews'):
            with self.subTest(table=table):
                source = self.root / f'changed-snapshot-{table}.sqlite'
                storage.snapshot('review', self.review_db, source)
                with closing(sqlite3.connect(source)) as connection, connection:
                    record = json.loads(connection.execute(f'SELECT body FROM {table} WHERE revision=1').fetchone()[0])
                    if table == 'reviews':
                        record['proposal']['rationale'] = 'Different proposal, same stored identity'
                    else:
                        record['generation']['explanation']['source_observations'][0]['text'] = 'Different model output'
                    connection.execute(f'UPDATE {table} SET body=?, body_sha256=? WHERE revision=1',
                        (review._canonical(record), review._digest(record)))
                self.rejected_without_publication('review', source)

    def test_verification_reaches_records_outside_normal_history_pages(self):
        for number in range(101):
            case_store.save_case(self.case_db, self.raw + b' ' * (number + 1), synthetic=True)
        self.assertEqual(storage.verify('case', self.case_db)['records']['cases'], 102)
        with closing(sqlite3.connect(self.case_db)) as connection, connection:
            connection.execute("UPDATE cases SET report=x'7b7d' WHERE case_id=?", (self.case['case_id'],))
        self.assertEqual(len(case_store.list_cases(self.case_db, limit=100)), 100)
        self.rejected_without_publication('case', self.case_db)

    def test_schema_changes_and_wrong_store_kind_rejected(self):
        changes = ('PRAGMA user_version=99', 'PRAGMA application_id=0', 'DROP INDEX sample_lookup',
                   'CREATE TABLE unrelated (value TEXT)', 'CREATE VIEW extra AS SELECT case_id FROM cases',
                   'CREATE TRIGGER extra AFTER INSERT ON cases BEGIN SELECT 1; END')
        for number, sql in enumerate(changes):
            with self.subTest(sql=sql):
                source = self.root / f'schema-{number}.sqlite'
                storage.snapshot('case', self.case_db, source)
                with closing(sqlite3.connect(source)) as connection, connection: connection.execute(sql)
                self.rejected_without_publication('case', source)
        self.rejected_without_publication('review', self.case_db)

    def test_invalid_files_and_missing_paths_create_nothing(self):
        non_database = self.root / 'not-a-database'; non_database.write_bytes(b'not SQLite')
        for source in (non_database, self.root / 'missing.sqlite', self.root):
            with self.subTest(source=source), self.assertRaises(storage.StorageError):
                storage.snapshot('case', source, self.root / 'destination.sqlite')
        with self.assertRaises(storage.StorageError):
            storage.snapshot('case', self.case_db, self.root / 'missing-parent/destination.sqlite')
        self.assertFalse((self.root / 'missing.sqlite').exists()); self.no_temporary_files()

    def test_existing_paths_and_sidecars_are_never_replaced(self):
        before = self.case_db.read_bytes()
        with self.assertRaises(storage.StorageError): storage.snapshot('case', self.case_db, self.case_db)
        for suffix in ('', *storage.SIDECARS):
            target = self.root / ('occupied' + (suffix or '-main') + '.sqlite')
            occupied = Path(str(target) + suffix); occupied.write_bytes(b'must survive')
            with self.subTest(suffix=suffix), self.assertRaises(storage.StorageError):
                storage.snapshot('case', self.case_db, target)
            self.assertEqual(occupied.read_bytes(), b'must survive')
        directory = self.root / 'directory'; directory.mkdir()
        with self.assertRaises(storage.StorageError): storage.snapshot('case', self.case_db, directory)
        self.assertEqual(self.case_db.read_bytes(), before); self.no_temporary_files()

    def test_symlink_sources_and_destinations_are_rejected(self):
        link = self.root / 'link.sqlite'
        try: link.symlink_to(self.case_db)
        except OSError: self.skipTest('Symlink creation is unavailable on this host')
        with self.assertRaises(storage.StorageError): storage.verify('case', link)
        with self.assertRaises(storage.StorageError): storage.snapshot('case', self.case_db, link)
        link.unlink(); link.symlink_to(self.root / 'absent-target')
        with self.assertRaises(storage.StorageError): storage.snapshot('case', self.case_db, link)
        self.assertFalse((self.root / 'absent-target').exists()); self.no_temporary_files()

    def test_concurrent_publication_has_one_complete_winner(self):
        destination = self.root / 'contended.sqlite'
        def attempt(_):
            try: return storage.snapshot('case', self.case_db, destination)
            except storage.StorageError: return None
        with ThreadPoolExecutor(max_workers=2) as pool: results = list(pool.map(attempt, range(2)))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(storage.verify('case', destination)['records'], {'cases': 1})
        self.no_temporary_files()

    def test_racing_foreign_file_is_preserved_at_atomic_publication(self):
        target = self.root / 'race.sqlite'; link = os.link
        def competing_link(source, destination):
            Path(destination).write_bytes(b'other process owns this')
            link(source, destination)
        with patch('artemis_v3.storage.os.link', competing_link), self.assertRaises(storage.StorageError):
            storage.snapshot('case', self.case_db, target)
        self.assertEqual(target.read_bytes(), b'other process owns this'); self.no_temporary_files()

    def test_sync_or_unsupported_link_failures_do_not_publish(self):
        before = self.case_db.read_bytes()
        for operation in ('fsync', 'link'):
            target = self.root / f'failed-{operation}.sqlite'
            with self.subTest(operation=operation), patch('artemis_v3.storage.os.' + operation, side_effect=OSError('Injected failure')):
                with self.assertRaises(storage.StorageError): storage.snapshot('case', self.case_db, target)
            self.assertFalse(target.exists()); self.no_temporary_files()
        self.assertEqual(self.case_db.read_bytes(), before)

    def test_busy_source_fails_within_bound_without_publication(self):
        with closing(sqlite3.connect(self.case_db)) as writer:
            writer.execute('BEGIN EXCLUSIVE')
            started = time.monotonic()
            with self.assertRaises(storage.StorageError):
                storage.snapshot('case', self.case_db, self.root / 'locked.sqlite', timeout=0.05)
            self.assertLess(time.monotonic() - started, 2)
            writer.rollback()
        self.assertFalse((self.root / 'locked.sqlite').exists()); self.no_temporary_files()

    def test_backup_progress_deadline_cleans_partial_copy(self):
        large = json.loads(self.raw); large['synthetic_padding'] = 'x' * 1_200_000
        case_store.save_case(self.case_db, json.dumps(large).encode(), synthetic=True)
        connect = sqlite3.connect
        class SlowCopy(sqlite3.Connection):
            def backup(self, target, **kwargs):
                progress = kwargs['progress']
                def delayed(*status):
                    time.sleep(0.15)
                    progress(*status)
                return super().backup(target, **{**kwargs, 'progress': delayed})
        def slow_connect(*args, **kwargs): return connect(*args, **kwargs, factory=SlowCopy)
        with patch('artemis_v3.storage.sqlite3.connect', slow_connect), self.assertRaisesRegex(storage.StorageError, 'timed out'):
            storage.snapshot('case', self.case_db, self.root / 'timeout.sqlite', timeout=0.1)
        self.assertFalse((self.root / 'timeout.sqlite').exists()); self.no_temporary_files()
        self.assertEqual(storage.verify('case', self.case_db)['records'], {'cases': 2})

    def test_budgets_and_invalid_timeouts_fail_without_partial_result(self):
        self.histories()
        for setting, value, kind, source in (('MAX_DB_BYTES', 1, 'case', self.case_db),
                ('MAX_REVIEW_ROWS', 1, 'review', self.review_db), ('MAX_SCORE_RECORD_BYTES', 1, 'review', self.review_db)):
            with self.subTest(setting=setting), patch('artemis_v3.storage.' + setting, value):
                self.rejected_without_publication(kind, source)
        for timeout in (0, -1, float('inf'), float('nan'), 301, True):
            with self.subTest(timeout=timeout), self.assertRaises(storage.StorageError):
                storage.snapshot('case', self.case_db, self.root / 'invalid.sqlite', timeout=timeout)
        self.no_temporary_files()

    def test_cli_backup_restore_verify_and_no_overwrite_exit_code(self):
        backup = self.root / 'cli-backup.sqlite'; restored = self.root / 'cli-restored.sqlite'
        for action, source, target in (('backup', self.case_db, backup), ('restore', backup, restored), ('verify', restored, None)):
            args = [sys.executable, '-m', 'artemis_v3.storage', action, '--kind', 'case', '--source', str(source), '--json']
            if target: args += ['--destination', str(target)]
            result = subprocess.run(args, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(result.stdout); self.assertEqual(value['action'], action)
            self.assertEqual(value['records'], {'cases': 1})
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = storage.main(['restore', '--kind', 'case', '--source', str(backup), '--destination', str(restored)])
        self.assertEqual(code, 2); self.assertIn('refusing to overwrite', err.getvalue()); self.assertEqual(out.getvalue(), '')

    def test_restored_pair_reopens_in_workbench_and_resumes_claim_review_without_model(self):
        scores, claims = self.histories()
        case_backup = self.root / 'case-backup.sqlite'; review_backup = self.root / 'review-backup.sqlite'
        cases = self.root / 'restored-cases.sqlite'; reviews = self.root / 'restored-reviews.sqlite'
        storage.snapshot('case', self.case_db, case_backup); storage.snapshot('review', self.review_db, review_backup)
        storage.snapshot('case', case_backup, cases); storage.snapshot('review', review_backup, reviews)
        original_case, original_review = self.case_db.read_bytes(), self.review_db.read_bytes()
        server = WorkbenchServer(0, case_db=cases, review_db=reviews)
        thread = Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True); thread.start()
        def post(route, payload):
            connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
            try:
                connection.request('POST', route, json.dumps(payload), {'Content-Type': 'application/json', 'X-Artemis-Token': server.token})
                response = connection.getresponse(); body = json.loads(response.read())
                self.assertEqual(response.status, 200, body)
                return body
            finally: connection.close()
        try:
            opened = post('/api/cases/open', {'case_id': self.case['case_id']})
            self.assertEqual(base64.b64decode(opened['inputs']['report']), self.raw)
            restored = post('/api/claims/open', {**opened['inputs'], 'claim_review_id': claims[0]['review_id']})
            self.assertEqual(restored['claim_review'], claims[0]); self.assertEqual(review.list_reviews(reviews), scores)
            request = restored['claim_template']; request.update(reviewer='Synthetic recovery analyst', expected_previous_id=claims[0]['review_id'])
            saved = post('/api/claims/save', {**opened['inputs'], 'generation': claims[0]['generation'],
                'claim_receipt': restored['claim_receipt'], 'claim_request': request})['claim_review']
            self.assertEqual(saved['revision'], 3); self.assertEqual(saved['previous_review_id'], claims[0]['review_id'])
            self.assertEqual(saved['base_score'], claims[0]['base_score']); self.assertEqual(saved['verdict'], 'not_assessed')
            self.assertIsNone(server.semantic_provider)
        finally:
            server.shutdown(); server.server_close(); thread.join()
        self.assertEqual(self.case_db.read_bytes(), original_case); self.assertEqual(self.review_db.read_bytes(), original_review)
        self.assertEqual(storage.verify('review', reviews)['records'], {'reviews': 2, 'claim_reviews': 3})


if __name__ == '__main__':
    unittest.main()
