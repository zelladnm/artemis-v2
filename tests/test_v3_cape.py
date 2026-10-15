"""Offline contract tests; all input is synthetic and no samples are executed."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from artemis_v3.cape import CapeReportError, load_cape_report, parse_cape_report
from artemis_v3.cli import main

FIXTURE = Path(__file__).parent / 'fixtures' / 'cape_synthetic.json'


def encode(value):
    return json.dumps(value).encode()


class CapeTests(unittest.TestCase):
    def test_evidence_resolves_to_original_source(self):
        raw = FIXTURE.read_bytes()
        original = json.loads(raw)
        result = parse_cape_report(raw, synthetic=True)
        self.assertEqual(result.source_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(result.warnings, [])
        self.assertEqual(len(result.evidence), 9)
        self.assertEqual(len(result.process_links), 1)
        self.assertEqual(result.process_links[0]['relation'], 'reported_parent')
        self.assertEqual(result.as_dict()['verdict'], 'not_assessed')
        for item in result.evidence:
            node = original
            for part in item.source_pointer.strip('/').split('/'):
                node = node[int(part)] if isinstance(node, list) else node[part]
            if item.category == 'file_summary':
                self.assertEqual(item.data['path'], node)
                self.assertIsNone(item.process_ref)
            else:
                self.assertEqual(item.data, node)
        self.assertEqual(result.as_dict(), parse_cape_report(raw, synthetic=True).as_dict())

    def test_process_file_activity_has_explicit_process_reference(self):
        raw = encode({'behavior': {'processes': [{'process_id': 5, 'parent_id': 0,
                      'file_activities': {'write_files': ['C:/Demo/readme.txt']}}]}})
        result = parse_cape_report(raw)
        activity = result.evidence[1]
        self.assertEqual(activity.category, 'process_file_activity')
        self.assertEqual(activity.process_ref, result.evidence[0].evidence_id)
        self.assertEqual(activity.source_pointer, '/behavior/processes/0/file_activities/write_files/0')

    def test_long_process_chain(self):
        raw = encode({'behavior': {'processes': [
            {'process_id': pid, 'parent_id': pid - 1} for pid in range(1, 5001)]}})
        result = parse_cape_report(raw)
        self.assertEqual(len(result.process_links), 4999)

    def test_missing_data_never_means_benign(self):
        result = parse_cape_report(b'{"behavior": {}}')
        self.assertEqual(result.as_dict()['status'], 'partial')
        self.assertEqual(result.evidence, [])
        self.assertTrue(result.warnings)
        self.assertIn('does not mean benign', result.as_markdown())

    def test_invalid_inputs(self):
        for raw in (b'[]', b'{}', b'null', b'not json', b'\xff',
                    b'{"behavior":null}', b'{"network":[]}',
                    b'{"signatures":null}', b'{"signatures":[1]}',
                    b'{"signatures":[],"signatures":[]}',
                    b'{"signatures":[],"value":NaN}',
                    b'{"signatures":[],"value":1e999}',
                    encode({'behavior': {'processes': [{'process_id': True}]}}),
                    encode({'behavior': {'processes': [{'process_id': 1, 'parent_id': '2'}]}}),
                    encode({'behavior': {'summary': {'files': [123]}}})):
            with self.subTest(raw=raw), self.assertRaises(CapeReportError):
                parse_cape_report(raw)

    def test_resource_limits(self):
        with patch('artemis_v3.cape.MAX_BYTES', 5), self.assertRaises(CapeReportError):
            load_cape_report(FIXTURE)
        with patch('artemis_v3.cape.MAX_NODES', 3), self.assertRaises(CapeReportError):
            parse_cape_report(FIXTURE.read_bytes())
        with patch('artemis_v3.cape.MAX_RECORDS', 1), self.assertRaises(CapeReportError):
            parse_cape_report(FIXTURE.read_bytes())
        for depth in (70, 2000):
            raw = b'{"signatures":[],"extra":' + b'[' * depth + b'0' + b']' * depth + b'}'
            with self.assertRaises(CapeReportError):
                parse_cape_report(raw)

    def test_ambiguous_and_cyclic_process_links(self):
        cases = [
            [(1, 2), (2, 1)], [(1, 1)], [(1, 0), (1, 0), (2, 1)], [(1, 999)],
            [(3, 1), (1, 2), (2, 1)]
        ]
        for pairs in cases:
            raw = encode({'behavior': {'processes': [
                {'process_id': pid, 'parent_id': ppid} for pid, ppid in pairs]}})
            with self.subTest(pairs=pairs):
                result = parse_cape_report(raw)
                self.assertEqual(result.process_links, [])
                self.assertTrue(result.warnings)

    def test_api_calls_are_explicitly_out_of_scope(self):
        result = parse_cape_report(encode({'behavior': {'processes': [
            {'process_id': 1, 'parent_id': 0, 'calls': [{'api': 'NtWriteVirtualMemory'}]}]}}))
        self.assertTrue(any('API calls' in w for w in result.warnings))
        self.assertNotIn('calls', result.evidence[0].data)
        self.assertEqual(result.as_dict()['verdict'], 'not_assessed')

    def test_report_content_is_never_executed_or_rendered_as_markup(self):
        payload = '<script>alert(1)</script>```[x](https://demo.example)\u001b[31m'
        raw = encode({'signatures': [{'description': payload, 'path': '/etc/passwd'}]})
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), \
             patch('subprocess.Popen', side_effect=AssertionError('execution forbidden')):
            result = parse_cape_report(raw)
        self.assertEqual(result.evidence[0].data['description'], payload)
        markdown = result.as_markdown()
        self.assertNotIn('<script>', markdown)
        self.assertNotIn('```', markdown)
        self.assertNotIn('\u001b', markdown)

    def test_cli_and_no_external_provider(self):
        output = io.StringIO()
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), \
             contextlib.redirect_stdout(output):
            code = main(['--cape-report', str(FIXTURE), '--synthetic', '--format', 'json'])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output.getvalue())['synthetic'])
        for args in (['--cape-report', str(FIXTURE), '--source', 'virustotal'],
                     ['demo.example', '--cape-report', str(FIXTURE)],
                     ['--synthetic', 'demo.example'], [],
                     ['--cape-report', '/nonexistent/report.json']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                main(args)
            self.assertEqual(caught.exception.code, 2)

    def test_regular_file_and_io_failure(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(CapeReportError):
            load_cape_report(directory)
        with patch('pathlib.Path.open', side_effect=PermissionError), self.assertRaises(CapeReportError):
            load_cape_report(FIXTURE)


if __name__ == '__main__':
    unittest.main()
