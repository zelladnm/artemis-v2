"""CAPE v2 evidence, local rule configuration and CLI integration contracts."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from artemis_v3.cape import load_cape_report, parse_cape_report
from artemis_v3.cli import main
from artemis_v3.ruleset import load_ruleset
from artemis_v3.scoring import SignatureRule, assess_signatures, propose_adjustment, validate_rules

FIXTURES = Path(__file__).parent / 'fixtures'


def config():
    return {'version': 'demo/1', 'synthetic': True, 'rules': [
        {'rule_id': 'DEMO', 'signature_name': 'synthetic_behavior', 'points': 1}]}


class ScoringIntegrationTests(unittest.TestCase):
    def load(self, value):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'rules.json'
            path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
            return load_ruleset(path)

    def test_rule_catalog_and_report_fingerprints(self):
        catalog = load_ruleset(FIXTURES / 'scoring_synthetic.json')
        self.assertEqual(catalog.source_sha256,
                         hashlib.sha256((FIXTURES / 'scoring_synthetic.json').read_bytes()).hexdigest())
        report = load_cape_report(FIXTURES / 'cape_synthetic.json', synthetic=True)
        self.assertEqual(report.schema_version, 'cape-evidence/3')
        result = assess_signatures(report, catalog.rules, version=catalog.version)
        self.assertEqual(result.base_score, 1)
        self.assertEqual(result.findings[0].evidence_refs,
                         (report.source_sha256 + '#/signatures/0',))
        self.assertTrue(result.synthetic)
        self.assertEqual(result.coverage_warnings, tuple(report.warnings))

    def test_api_only_report_is_not_inferred_as_injection(self):
        report = load_cape_report(FIXTURES / 'cape_timeline_synthetic.json', synthetic=True)
        rules = [SignatureRule('DEMO', 'NtWriteVirtualMemory', 10, True)]
        result = assess_signatures(report, rules, version='demo/1')
        self.assertEqual(result.base_score, 0)
        self.assertFalse(result.critical_signals_present)
        self.assertEqual(result.verdict, 'not_assessed')
        self.assertTrue(result.coverage_warnings)

    def test_installer_context_does_not_remove_critical_signal(self):
        raw = json.dumps({'behavior': {'summary': {'files': ['C:/Program Files/Demo/readme.txt']}},
                          'signatures': [{'name': 'demo.critical'}, {'name': 'demo.critical'}]}).encode()
        report = parse_cape_report(raw, synthetic=True)
        result = assess_signatures(report, [SignatureRule('R', 'demo.critical', 8, True)], version='demo/1')
        self.assertEqual(result.base_score, 8)
        self.assertEqual(len(result.findings[0].evidence_refs), 2)
        proposal = propose_adjustment(report, result, delta=-8,
                                      cited_evidence=[report.evidence[0].evidence_id], rationale='Installer context')
        self.assertEqual(proposal.status, 'blocked_critical_signal')
        self.assertEqual(proposal.applied_score, 8)

    def test_malformed_catalogs_rejected(self):
        values = [None, [], {}, b'{"version":"a","version":"b"}', b'{"v":NaN}', b'\xff']
        for change in ({'version': ' '}, {'synthetic': 'yes'}, {'rules': []}, {'unexpected': True},
                       {'rules': [{'rule_id': 'R', 'signature_name': 'x', 'points': True}]},
                       {'rules': [{'rule_id': 'R', 'signature_name': 'x', 'points': 1, 'critical': 'yes'}]},
                       {'rules': [{'rule_id': 'R', 'signature_name': 'x', 'points': 1, 'executable': 'bad'}]},
                       {'rules': [config()['rules'][0]] * 2}):
            values.append({**config(), **change})
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.load(value)

    def test_catalog_limits_and_bounded_iterables(self):
        with patch('artemis_v3.ruleset.MAX_RULESET_BYTES', 5), self.assertRaises(ValueError):
            self.load(config())
        import itertools
        with self.assertRaises(ValueError):
            validate_rules(itertools.repeat(SignatureRule('R', 'x', 1)), version='demo/1')
        report = load_cape_report(FIXTURES / 'cape_synthetic.json')
        assessment = assess_signatures(report, [], version='demo/1')
        for refs in ([[1]], [1], itertools.repeat('unknown')):
            with self.assertRaises(ValueError):
                propose_adjustment(report, assessment, delta=-1, cited_evidence=refs, rationale='demo')

    def test_cli_assessment_json_is_offline_and_preserves_timeline(self):
        output = io.StringIO()
        with patch('socket.socket', side_effect=AssertionError('network')), \
             patch('subprocess.Popen', side_effect=AssertionError('execution')), \
             contextlib.redirect_stdout(output):
            code = main(['--cape-report', str(FIXTURES / 'cape_synthetic.json'), '--synthetic',
                         '--ruleset', str(FIXTURES / 'scoring_synthetic.json'), '--format', 'json'])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(result['schema_version'], 'artemis-assessment/1')
        self.assertEqual(len(result['report']['timeline']['report_clock']), 2)
        self.assertEqual(result['rule_assessment']['base_score'], 1)
        self.assertTrue(result['rule_assessment']['review_required'])
        self.assertTrue(result['ruleset_synthetic'])
        self.assertEqual(result['rule_assessment']['verdict'], 'not_assessed')

    def test_cli_argument_errors(self):
        for args in (['demo.example', '--ruleset', 'bad'],
                     ['--cape-report', str(FIXTURES / 'cape_synthetic.json'), '--ruleset', '/missing/rules.json'],
                     ['--cape-report', str(FIXTURES / 'cape_synthetic.json'), '--ruleset',
                      str(FIXTURES / 'cape_synthetic.json')]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                main(args)
            self.assertEqual(caught.exception.code, 2)

    def test_markdown_retains_synthetic_label_and_escapes_rule_prose(self):
        output = io.StringIO()
        hostile = self.load({**config(), 'version': '<script>bad()</script>```'})
        with patch('artemis_v3.cli.load_ruleset', return_value=hostile), contextlib.redirect_stdout(output):
            main(['--cape-report', str(FIXTURES / 'cape_synthetic.json'),
                  '--ruleset', str(FIXTURES / 'scoring_synthetic.json')])
        self.assertIn('SYNTHETIC DEMO DATA', output.getvalue())
        self.assertIn('No malware verdict', output.getvalue())
        self.assertIn('ruleset_sha256', output.getvalue())
        self.assertNotIn('<script>', output.getvalue())
        self.assertNotIn('```', output.getvalue())


if __name__ == '__main__':
    unittest.main()
