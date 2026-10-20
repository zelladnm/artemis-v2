"""Source archive identity, concurrency, corruption and loopback integration."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

from artemis_v3.case_store import CaseStoreError, list_cases, open_case, save_case
from artemis_v3.cape import parse_cape_report
from artemis_v3.workbench import WorkbenchServer

FIXTURES = Path(__file__).parent / 'fixtures'


def report_bytes(sample='A'*64, number=1):
    report = json.loads((FIXTURES / 'cape_synthetic.json').read_bytes())
    report['target'] = {'file': {'sha256': sample}}
    report['info']['id'] = number
    return json.dumps(report).encode()


class CaseStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / 'cases.sqlite'
        self.raw = report_bytes()
        self.rules = (FIXTURES / 'scoring_synthetic.json').read_bytes()

    def tearDown(self):
        self.temporary.cleanup()

    def save(self, **kwargs):
        return save_case(self.database, self.raw, rules=self.rules, synthetic=True, **kwargs)

    def test_exact_source_roundtrip_identity_types_and_idempotence(self):
        saved = self.save(title='Original title')
        metadata = saved['case']; report_hash = hashlib.sha256(self.raw).hexdigest()
        self.assertTrue(saved['created'])
        self.assertEqual(metadata['report_sha256'], report_hash)
        self.assertEqual(metadata['sample_sha256'], 'a'*64)
        self.assertEqual(metadata['sample_identity_kind'], 'report_asserted')
        self.assertNotEqual(metadata['sample_sha256'], report_hash)
        self.assertEqual(open_case(self.database, metadata['case_id']), (metadata, self.raw, self.rules))
        self.assertEqual(list_cases(self.database, kind='sample', sha256='A'*64), [metadata])
        self.assertEqual(list_cases(self.database, kind='report', sha256=report_hash), [metadata])
        self.assertEqual(list_cases(self.database, kind='sample', sha256=report_hash), [])
        duplicate = self.save(title='Must not overwrite')
        self.assertFalse(duplicate['created']); self.assertEqual(duplicate['case'], metadata)
        self.assertEqual(len(list_cases(self.database)), 1)

    def test_same_sample_retains_distinct_reports_rules_and_labels(self):
        first = self.save()['case']
        changed = save_case(self.database, report_bytes(number=2), rules=self.rules, synthetic=True)['case']
        rules = json.loads(self.rules); rules['version'] = 'synthetic-new/2'
        changed_rules = save_case(self.database, self.raw, rules=json.dumps(rules).encode(), synthetic=True)['case']
        changed_label = save_case(self.database, self.raw, rules=self.rules, synthetic=False)['case']
        matches = list_cases(self.database, kind='sample', sha256='a'*64)
        self.assertEqual(len({item['case_id'] for item in matches}), 4)
        self.assertEqual(matches[0]['case_id'], changed_label['case_id'])
        self.assertNotEqual(first['case_id'], changed['case_id'])
        self.assertNotEqual(first['case_id'], changed_rules['case_id'])
        self.assertEqual(list_cases(self.database, kind='sample', sha256='b'*64), [])

    def test_absent_invalid_or_nested_hashes_do_not_become_sample_identity(self):
        for sample in (None, 'short', 12, {'sha256': 'a'*64}):
            saved = save_case(self.database, report_bytes(sample), synthetic=True)['case']
            self.assertIsNone(saved['sample_sha256'])
            self.assertEqual(saved['sample_identity_kind'], 'absent_or_invalid')
        self.assertEqual(list_cases(self.database, kind='sample', sha256='a'*64), [])
        self.assertEqual(len(list_cases(self.database)), 4)

    def test_reads_do_not_create_and_inputs_are_validated_before_writes(self):
        self.assertEqual(list_cases(self.database), [])
        with self.assertRaises(CaseStoreError):
            open_case(self.database, 'a'*64)
        self.assertFalse(self.database.exists())
        for kwargs in ({'synthetic': 'yes'}, {'title': 'x'*101}, {'rules': b'{}'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                save_case(self.database, self.raw, **kwargs)
        self.assertFalse(self.database.exists())
        for kwargs in ({'kind': 'sample', 'sha256': 'prefix'}, {'kind': 'report'}, {'sha256': 'a'*64},
                       {'kind': 'filename', 'sha256': 'a'*64}, {'limit': True}, {'limit': 101}):
            with self.subTest(kwargs=kwargs), self.assertRaises(CaseStoreError):
                list_cases(self.database, **kwargs)

    def test_foreign_database_and_review_store_are_preserved(self):
        with sqlite3.connect(self.database) as db:
            db.execute('CREATE TABLE unrelated(value TEXT)'); db.execute("INSERT INTO unrelated VALUES ('keep')")
        for operation in (lambda: self.save(), lambda: list_cases(self.database), lambda: open_case(self.database, 'a'*64)):
            with self.assertRaises(CaseStoreError):
                operation()
        with sqlite3.connect(self.database) as db:
            self.assertEqual(db.execute('SELECT * FROM unrelated').fetchall(), [('keep',)])
            self.assertEqual(db.execute('PRAGMA application_id').fetchone()[0], 0)
        for application_id, version in ((0x41525433, 1), (0x41524333, 2)):
            with sqlite3.connect(self.database) as db:
                db.execute(f'PRAGMA application_id={application_id}'); db.execute(f'PRAGMA user_version={version}')
            with self.assertRaises(CaseStoreError):
                self.save()
            with sqlite3.connect(self.database) as db:
                self.assertEqual(db.execute('SELECT * FROM unrelated').fetchall(), [('keep',)])

    def test_source_and_metadata_corruption_are_refused(self):
        metadata = self.save()['case']
        with sqlite3.connect(self.database) as db:
            db.execute('UPDATE cases SET report=?', (report_bytes(number=9),))
        with self.assertRaises(CaseStoreError):
            open_case(self.database, metadata['case_id'])
        with self.assertRaises(CaseStoreError):
            self.save()
        with sqlite3.connect(self.database) as db:
            db.execute("UPDATE cases SET sample_sha256=?", ('b'*64,))
        with self.assertRaises(CaseStoreError):
            list_cases(self.database)

    def test_parser_coverage_changes_do_not_invalidate_exact_source_identity(self):
        metadata = self.save()['case']
        def updated_parser(*args, **kwargs):
            report = parse_cape_report(*args, **kwargs)
            report.warnings.append('Synthetic new parser coverage warning')
            return report
        with patch('artemis_v3.case_store.parse_cape_report', side_effect=updated_parser):
            opened, raw, rules = open_case(self.database, metadata['case_id'])
        self.assertEqual(opened, metadata)  # archival-time counts remain a snapshot
        self.assertEqual((raw, rules), (self.raw, self.rules))

    def test_payload_and_record_budgets_roll_back_without_overwriting(self):
        first = self.save()['case']
        with patch('artemis_v3.case_store.MAX_CASES', 1), self.assertRaises(CaseStoreError):
            save_case(self.database, report_bytes(number=2))
        with patch('artemis_v3.case_store.MAX_TOTAL_BYTES', len(self.raw)), self.assertRaises(CaseStoreError):
            save_case(self.database, report_bytes(number=2))
        self.assertEqual(list_cases(self.database), [first])
        self.assertFalse(self.save()['created'])

    def test_concurrent_duplicate_archival_creates_one_immutable_record(self):
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda _: self.save(), range(4)))
        self.assertEqual(sum(result['created'] for result in results), 1)
        self.assertEqual(len(list_cases(self.database)), 1)
        self.assertEqual(len({result['case']['created_at'] for result in results}), 1)


class CaseArchiveHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / 'cases.sqlite'
        class UncalledModel:
            model = 'never-auto-called'
            def generate(self, context):
                raise AssertionError('Archival must not call a model')
        self.server = WorkbenchServer(0, case_db=self.database, semantic_provider=UncalledModel())
        self.thread = Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True); self.thread.start()
        self.payload = {'report': base64.b64encode(report_bytes()).decode(),
                        'ruleset': base64.b64encode((FIXTURES / 'scoring_synthetic.json').read_bytes()).decode(), 'synthetic': True}

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(); self.temporary.cleanup()

    def request(self, path, payload=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        connection.request('GET' if payload is None else 'POST', path,
                           body=None if payload is None else json.dumps(payload),
                           headers={'X-Artemis-Token': self.server.token, 'Content-Type': 'application/json', **(headers or {})})
        response = connection.getresponse(); status, data = response.status, json.loads(response.read()); connection.close()
        return status, data

    def test_startup_config_and_investigation_make_no_archive_writes(self):
        self.assertTrue(self.request('/api/config')[1]['archive_enabled'])
        self.assertEqual(self.request('/api/cases')[1]['cases'], [])
        result = self.request('/api/analyze', self.payload)[1]
        self.assertEqual(result['source_identity']['sample_sha256'], 'a'*64)
        self.assertFalse(self.database.exists())

    def test_save_typed_lookup_and_reopen_recompute_without_model_or_proposal(self):
        status, saved = self.request('/api/cases/save', {**self.payload, 'archive_title': '<img synthetic>'})
        self.assertEqual(status, 200); self.assertTrue(saved['created'])
        status, search = self.request('/api/cases/search', {'kind': 'sample', 'sha256': 'A'*64})
        self.assertEqual(status, 200); self.assertEqual(search['match_kind'], 'exact_sample_sha256')
        self.assertEqual(len(search['cases']), 1)
        status, opened = self.request('/api/cases/open', {'case_id': saved['case']['case_id']})
        self.assertEqual(status, 200); self.assertEqual(opened['inputs'], self.payload)
        self.assertEqual(opened['result']['rule_assessment']['base_score'], 1)
        self.assertIsNone(opened['result']['proposal_review'])
        self.assertNotIn('semantic_review', opened['result'])
        self.assertEqual(opened['archived_case']['title'], '<img synthetic>')
        self.assertFalse(self.request('/api/cases/save', self.payload)[1]['created'])

    def test_routes_require_token_explicit_config_and_safe_ids(self):
        for path, payload in (('/api/cases', None), ('/api/cases/search', {'kind': 'sample', 'sha256': 'a'*64}),
                              ('/api/cases/open', {'case_id': 'a'*64}), ('/api/cases/save', self.payload)):
            self.assertEqual(self.request(path, payload, {'X-Artemis-Token': ''})[0], 403)
            self.assertEqual(self.request(path, payload, {'Origin': 'https://hostile.example'})[0], 403)
        for path, value in (('/api/cases/search', {'kind': 'sample', 'sha256': 'short'}),
                            ('/api/cases/open', {'case_id': '../../file'}),
                            ('/api/cases/open', {'case_id': 'a'*64, 'database': '/anywhere'})):
            self.assertEqual(self.request(path, value)[0], 400)
        self.assertFalse(self.database.exists())
        self.server.case_db = None
        for path, value in (('/api/cases', None), ('/api/cases/save', self.payload),
                            ('/api/cases/search', {'kind': 'sample', 'sha256': 'a'*64}), ('/api/cases/open', {'case_id': 'a'*64})):
            self.assertEqual(self.request(path, value)[0], 409)
        with self.assertRaises(ValueError):
            WorkbenchServer(0, review_db=self.database, case_db=self.database)
