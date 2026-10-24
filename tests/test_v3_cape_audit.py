"""Synthetic-only, offline CAPE compatibility profile tests."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from artemis_v3.cape_audit import PROFILE_VERSION, build_profile, main
from artemis_v3.cape import parse_cape_report


def raw_report():
    return json.dumps({
        'behavior': {
            'processes': [{'process_id': 12, 'parent_id': 0, 'calls': [
                {'api': 'CreateServiceW', 'timestamp': '2026-10-23 10:20:30', 'status': False}]}],
            'summary': {'created_services': ['SensitiveSvc'],
                        'executed_commands': ['SECRET command token'],
                        'keys': ['HKCU\\Private\\Value'], 'files': []}},
        'network': {'dns': [{'request': 'internal.private.example'}]},
    }).encode('utf-8')


class CapeAuditTests(unittest.TestCase):
    def test_profile_counts_and_coverage(self):
        report = parse_cape_report(raw_report())
        value = build_profile(report, cape_version='operator-declared-test')
        self.assertEqual(value['profile_version'], PROFILE_VERSION)
        self.assertTrue(value['accepted'])
        self.assertEqual(value['parser_schema'], report.schema_version)
        self.assertEqual(value['evidence_counts']['service_summary'], 1)
        self.assertEqual(value['evidence_counts']['command_summary'], 1)
        self.assertEqual(value['evidence_counts']['registry_summary'], 1)
        self.assertEqual(value['summary_field_coverage']['created_services'],
                         {'state': 'reported', 'record_count': 1})
        self.assertEqual(value['summary_field_coverage']['files'],
                         {'state': 'empty', 'record_count': 0})
        self.assertEqual(value['summary_field_coverage']['write_files'],
                         {'state': 'absent', 'record_count': 0})
        self.assertEqual(value['timeline_counts']['report_clock'], 1)
        self.assertEqual(value['operator_declared_cape_version'], 'operator-declared-test')

    def test_no_report_values_paths_hashes_or_ids_in_output(self):
        raw = raw_report()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'private-report.json'
            path.write_bytes(raw)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(['--report', str(path)])
        self.assertEqual(code, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result['operator_declared_cape_version'], None)
        for secret in ('SensitiveSvc', 'SECRET command token', 'HKCU', 'internal.private.example',
                       'private-report.json', 'source_sha256', 'evidence_id', 'source_pointer'):
            self.assertNotIn(secret, output.getvalue())

    def test_missing_fields_are_not_interpreted_as_empty(self):
        report = parse_cape_report(b'{"behavior":{}}')
        profile = build_profile(report)
        self.assertEqual(profile['summary_field_coverage']['files']['state'], 'absent')
        self.assertEqual(profile['parse_status'], 'partial')
        self.assertGreater(profile['warning_count'], 0)

    def test_rejected_input_reports_no_private_path_or_details(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(['--report', '/secret/private-location.json'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())['error_code'], 'report_not_accepted')
        self.assertNotIn('/secret/', output.getvalue())

    def test_no_network_execution_or_model_use(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'report.json'
            path.write_bytes(raw_report())
            with patch('socket.socket', side_effect=AssertionError('network forbidden')), \
                 patch('subprocess.Popen', side_effect=AssertionError('execution forbidden')), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['--report', str(path)]), 0)

    def test_bad_version_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            main(['--report', 'ignored', '--cape-version', '\x1bprivate'])
        self.assertEqual(caught.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
