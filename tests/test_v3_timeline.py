"""Contract and chronology tests with synthetic API data only."""
import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from artemis_v3.cape import CapeReportError, parse_cape_report
from artemis_v3.cli import main
from artemis_v3.timeline import normalize_timestamp

FIXTURE = Path(__file__).parent / 'fixtures' / 'cape_timeline_synthetic.json'


def report_with_calls(calls):
    return json.dumps({'behavior': {'processes': [
        {'process_id': 1, 'parent_id': 0, 'calls': calls}]}}).encode()


class TimelineTests(unittest.TestCase):
    def test_separate_clocks_and_unknown_times(self):
        result = parse_cape_report(FIXTURE.read_bytes())
        timeline = result.as_dict()['timeline']
        self.assertEqual([x['normalized_time'] for x in timeline['utc']],
                         ['2026-01-01T04:00:00.000000+00:00', '2026-01-01T04:00:01.000000+00:00'])
        self.assertEqual([x['normalized_time'] for x in timeline['report_clock']],
                         ['2026-01-01T10:00:00.000000', '2026-01-01T10:00:01.000000',
                          '2026-01-01T10:00:02.000000'])
        self.assertEqual([x['time_status'] for x in timeline['undated']], ['invalid', 'missing'])
        self.assertIsNone(timeline['undated'][1]['timestamp_pointer'])
        self.assertEqual(result.as_dict()['status'], 'partial')
        self.assertEqual(result.as_dict()['verdict'], 'not_assessed')

    def test_raw_calls_and_pointers_are_lossless(self):
        raw = FIXTURE.read_bytes()
        original = json.loads(raw)
        result = parse_cape_report(raw)
        calls = [x for x in result.evidence if x.category == 'api_call']
        self.assertEqual(len(calls), 5)  # repeated=2 is not expanded into invented events
        for call in calls:
            node = original
            for part in call.source_pointer.strip('/').split('/'):
                node = node[int(part)] if isinstance(node, list) else node[part]
            self.assertEqual(call.data, node)
        self.assertFalse(calls[0].data['status'])
        self.assertEqual(calls[0].data['return'], '0xc0000008')
        self.assertNotEqual(calls[0].process_ref, calls[-1].process_ref)  # same PID, different source records
        self.assertEqual(result.process_links, [])
        self.assertEqual(result.as_dict(), parse_cape_report(raw).as_dict())

    def test_ties_preserve_numeric_source_order(self):
        result = parse_cape_report(report_with_calls([
            {'api': f'Demo{i}', 'timestamp': '2026-01-01 00:00:00'} for i in range(12)]))
        events = result.as_dict()['timeline']['report_clock']
        self.assertEqual([x['evidence_ref'].split('/calls/')[-1] for x in events],
                         [str(i) for i in range(12)])

    def test_invalid_calendar_zone_precision_and_type_are_undated(self):
        for value in ('2026-02-30 00:00:00', '2026-01-01', '2026-01-01T00:00:00+01:99',
                      '2026-01-01T00:00:00+24:00', '2026-01-01T00:00:00.1234567',
                      '0001-01-01T00:00:00+23:00', '2026-01-01T00:00:60Z',
                      '', 0, True, {}, [], '2026-01-01X00:00:00'):
            with self.subTest(value=value):
                self.assertEqual(normalize_timestamp(value), ('invalid', None))
        self.assertEqual(normalize_timestamp(None), ('missing', None))
        self.assertEqual(normalize_timestamp('2026-01-01 00:00:00.1'),
                         ('report_clock', '2026-01-01T00:00:00.100000'))

    def test_malformed_calls_fail_atomically(self):
        for calls in (None, {}, 'external.json', [1], [{}], [{'api': 1}], [{'api': ' '}],
                      [{'api': 'Demo', 'arguments': None}], [{'api': 'Demo', 'arguments': [1]}],
                      [{'api': 'Demo', 'repeated': True}], [{'api': 'Demo', 'repeated': -1}]):
            with self.subTest(calls=calls), self.assertRaises(CapeReportError):
                parse_cape_report(report_with_calls(calls))

    def test_api_records_use_shared_record_limit(self):
        with patch('artemis_v3.cape.MAX_RECORDS', 2), self.assertRaises(CapeReportError):
            parse_cape_report(report_with_calls([{'api': 'Demo'}, {'api': 'Demo'}]))

    def test_missing_calls_is_different_from_empty_calls(self):
        missing = parse_cape_report(b'{"behavior":{"processes":[{"process_id":1}]}}')
        empty = parse_cape_report(report_with_calls([]))
        self.assertTrue(any('/calls: absent' in x for x in missing.warnings))
        self.assertFalse(any('/calls: absent' in x for x in empty.warnings))

    def test_cli_offline_and_untrusted_arguments(self):
        output = io.StringIO()
        with patch('socket.socket', side_effect=AssertionError('network')), \
             patch('subprocess.Popen', side_effect=AssertionError('execute')), \
             contextlib.redirect_stdout(output):
            self.assertEqual(main(['--cape-report', str(FIXTURE), '--synthetic', '--format', 'json']), 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload['schema_version'], 'cape-evidence/2')
        self.assertTrue(payload['synthetic'])
        hostile = '<script>bad()</script>```\x1b[31m'
        result = parse_cape_report(report_with_calls([{'api': 'Demo',
            'arguments': [{'name': 'path', 'value': hostile}]}]))
        self.assertEqual(result.evidence[-1].data['arguments'][0]['value'], hostile)
        for unsafe in ('<script>', '```', '\x1b'):
            self.assertNotIn(unsafe, result.as_markdown())


if __name__ == '__main__':
    unittest.main()
