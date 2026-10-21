"""Offline VirusTotal transport and response contract regression tests."""
import io
import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request

from artemis_v3.engine import investigate
from artemis_v3.indicators import parse_indicator
from artemis_v3.providers import DemoProvider, ProviderError, VirusTotalProvider, _NoRedirect


def payload(identity='8.8.8.8', kind='ip_address'):
    return {'data': {'id': identity, 'type': kind, 'attributes': {
        'last_analysis_stats': {'malicious': 1, 'suspicious': 0, 'harmless': 2, 'undetected': 4},
        'last_analysis_date': 1700000000}}}


class VTContractTests(unittest.TestCase):
    def lookup(self, value, indicator='8.8.8.8'):
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        with patch('artemis_v3.providers.urlopen', return_value=io.BytesIO(raw)) as transport:
            result = VirusTotalProvider(api_key='synthetic-secret', timeout=3).lookup(parse_indicator(indicator))
        self.assertEqual(transport.call_args.kwargs['timeout'], 3)
        return result

    def test_valid_object_types_and_hash_aliases(self):
        cases = [('8.8.8.8', 'ip_address'), ('2001:4860:4860::8888', 'ip_address'),
                 ('example.edu', 'domain'), ('a' * 64, 'file'), ('b' * 32, 'file'), ('c' * 40, 'file')]
        for indicator, kind in cases:
            value = payload(indicator if kind != 'file' else 'a' * 64, kind)
            if len(indicator) in (32, 40):
                value['data']['attributes']['md5' if len(indicator) == 32 else 'sha1'] = indicator
            with self.subTest(indicator=indicator):
                evidence = self.lookup(value, indicator)[0]
                self.assertIn('malicious: 1', evidence.summary)
                self.assertIn('not a probability', evidence.summary)
                self.assertEqual(evidence.observed_at, '2023-11-14T22:13:20+00:00')

    def test_missing_counts_remain_unknown(self):
        value = payload()
        value['data']['attributes'] = {'last_analysis_stats': {'malicious': 0}}
        evidence = self.lookup(value)[0]
        self.assertIn('malicious: 0', evidence.summary)
        self.assertIn('suspicious: unknown', evidence.summary)
        self.assertIsNone(evidence.observed_at)
        value['data']['attributes']['last_analysis_stats'] = dict.fromkeys(
            ('malicious', 'suspicious', 'harmless', 'undetected'), 0)
        self.assertIn('malicious: 0', self.lookup(value)[0].summary)

    def test_malformed_nested_objects_and_counts(self):
        values = [None, [], {}, {'data': None}, {'data': []}, {'data': {}},
                  {'data': {'type': 'ip_address', 'attributes': []}}]
        for counts in (None, [], {}, {'other': 0}, {'malicious': True},
                       {'malicious': -1}, {'malicious': 1.5}, {'malicious': '0'},
                       {'malicious': 0, 'timeout': None}):
            value = payload()
            value['data']['attributes']['last_analysis_stats'] = counts
            values.append(value)
        for value in values:
            with self.subTest(value=value), self.assertRaises(ProviderError):
                self.lookup(value)

    def test_wrong_identity_or_type_is_rejected(self):
        values = [payload('1.1.1.1'), payload(kind='domain'), payload(None)]
        value = payload('a' * 64, 'file')
        for response, indicator in [(x, '8.8.8.8') for x in values] + [(value, 'b' * 32)]:
            with self.subTest(response=response), self.assertRaises(ProviderError):
                self.lookup(response, indicator)

    def test_bad_timestamp_is_not_silently_discarded(self):
        for ts in (None, True, -1, 1.5, '1700000000', 253402300800):
            value = payload()
            value['data']['attributes']['last_analysis_date'] = ts
            with self.subTest(ts=ts), self.assertRaises(ProviderError):
                self.lookup(value)

    def test_json_and_size_failures_are_safe(self):
        for raw in (b'not json synthetic-secret', b'\xff', b'{"data":{},"data":{}}',
                    b'{"data":NaN}', b'[' * 2000 + b']' * 2000):
            with self.subTest(raw=raw[:40]), self.assertRaises(ProviderError) as caught:
                self.lookup(raw)
            self.assertNotIn('synthetic-secret', str(caught.exception))
        with patch('artemis_v3.providers.MAX_VT_RESPONSE_BYTES', 5), self.assertRaises(ProviderError):
            self.lookup(payload())

    def test_http_and_network_failures_have_no_secret(self):
        for error in (HTTPError('url', 401, 'synthetic-secret', {}, None),
                      HTTPError('url', 429, 'synthetic-secret', {}, None),
                      HTTPError('url', 503, 'synthetic-secret', {}, None),
                      HTTPError('url', 302, 'synthetic-secret', {}, None),
                      URLError('synthetic-secret'), TimeoutError('synthetic-secret')):
            with patch('artemis_v3.providers.urlopen', side_effect=error), self.assertRaises(ProviderError) as caught:
                VirusTotalProvider(api_key='synthetic-secret').lookup(parse_indicator('8.8.8.8'))
            self.assertNotIn('synthetic-secret', str(caught.exception))
        with patch('artemis_v3.providers.urlopen', side_effect=HTTPError('url', 404, '', {}, None)):
            self.assertEqual(VirusTotalProvider(api_key='fake').lookup(parse_indicator('8.8.8.8')), [])

    def test_no_redirect_with_credential(self):
        request = Request('https://www.virustotal.com/api/v3/files/demo', headers={'x-apikey': 'fake'})
        self.assertIsNone(_NoRedirect().redirect_request(request, None, 302, '', {}, 'https://other.example'))

    def test_errors_become_failed_or_partial_investigations(self):
        vt = VirusTotalProvider(api_key='fake')
        with patch('artemis_v3.providers.urlopen', return_value=io.BytesIO(b'{"data":null}')):
            self.assertEqual(investigate('8.8.8.8', [vt]).status, 'failed')
        class LocalEvidence:
            name = 'local'
            def lookup(self, indicator):
                return DemoProvider().lookup(parse_indicator('demo.example'))
        with patch('artemis_v3.providers.urlopen', return_value=io.BytesIO(b'{"data":null}')):
            report = investigate('8.8.8.8', [LocalEvidence(), vt])
        self.assertEqual(report.status, 'partial')
        self.assertEqual(len(report.evidence), 1)

    def test_timeout_validation(self):
        for timeout in (True, None, '3', 0, -1, 61, float('nan'), float('inf')):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                VirusTotalProvider(api_key='fake', timeout=timeout)
