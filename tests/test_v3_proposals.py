"""Offline, untrusted proposal contract and analyst review gate tests."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from artemis_v3.proposals import ProposalError, load_proposal
from artemis_v3.scoring import SignatureRule, assess_signatures


class ProposalTests(unittest.TestCase):
    def setUp(self):
        self.report = SimpleNamespace(
            source_sha256='a' * 64, synthetic=True, warnings=[],
            evidence=[SimpleNamespace(evidence_id='a' * 64 + '#/signatures/0',
                                      category='signature', data={'name': 'demo.signal'})],
        )
        self.ruleset = SimpleNamespace(source_sha256='b' * 64, version='demo/1')
        self.assessment = assess_signatures(
            self.report, [SignatureRule('DEMO', 'demo.signal', 7)], version='demo/1')
        self.payload = {
            'schema_version': 'artemis-proposal/1',
            'report_sha256': self.report.source_sha256,
            'ruleset_sha256': self.ruleset.source_sha256,
            'ruleset_version': self.ruleset.version,
            'proposed_delta': -3,
            'cited_evidence': [self.report.evidence[0].evidence_id],
            'rationale': 'Synthetic context warrants manual review',
        }

    def load(self, payload):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'proposal.json'
            raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode('utf-8')
            path.write_bytes(raw)
            return load_proposal(path, report=self.report, assessment=self.assessment,
                                 ruleset=self.ruleset)

    def test_valid_proposal_is_unapplied(self):
        result = self.load(self.payload)
        self.assertEqual(result['schema_version'], 'artemis-proposal-review/1')
        self.assertEqual(result['origin'], 'untrusted_local_json')
        self.assertEqual(result['adjustment_proposal']['proposed_score'], 4)
        self.assertEqual(result['adjustment_proposal']['applied_score'], 7)
        self.assertEqual(result['adjustment_proposal']['status'], 'awaiting_analyst_review')
        self.assertTrue(result['review_required'])
        self.assertEqual(result['analyst_decision'], 'not_recorded')
        self.assertEqual(self.assessment.base_score, 7)

    def test_critical_downgrade_is_blocked(self):
        self.assessment = assess_signatures(
            self.report, [SignatureRule('DEMO', 'demo.signal', 7, True)], version='demo/1')
        result = self.load(self.payload)
        self.assertEqual(result['adjustment_proposal']['status'], 'blocked_critical_signal')
        self.assertEqual(result['adjustment_proposal']['applied_score'], 7)

    def test_report_and_ruleset_binding(self):
        for field, value in (
            ('report_sha256', 'c' * 64), ('ruleset_sha256', 'd' * 64),
            ('ruleset_version', 'other'), ('schema_version', 'artemis-proposal/2'),
        ):
            with self.subTest(field=field), self.assertRaises(ProposalError):
                self.load({**self.payload, field: value})
        self.assessment = SimpleNamespace(**{**vars(self.assessment), 'ruleset_version': 'wrong'})
        with self.assertRaises(ProposalError):
            self.load(self.payload)

    def test_reject_untrusted_fields_and_malformed_json(self):
        invalid = [b'{"a":1,"a":2}', b'{"n":NaN}', b'\xff', b'[]', b'{}',
                   {**self.payload, 'verdict': 'benign'},
                   {k: v for k, v in self.payload.items() if k != 'rationale'},
                   {**self.payload, 'proposed_delta': True},
                   {**self.payload, 'proposed_delta': -11},
                   {**self.payload, 'rationale': ''},
                   {**self.payload, 'cited_evidence': 'not an array'},
                   {**self.payload, 'cited_evidence': ['fabricated']},
                   {**self.payload, 'cited_evidence': self.payload['cited_evidence'] * 2},
                   {**self.payload, 'cited_evidence': [1]},
                   {**self.payload, 'cited_evidence': []}]
        for value in invalid:
            with self.subTest(value=str(value)[:90]), self.assertRaises(ProposalError):
                self.load(value)

    def test_size_and_missing_file(self):
        with self.assertRaises(ProposalError):
            self.load(b' ' * (32 * 1024 + 1))
        with self.assertRaises(ProposalError):
            load_proposal('/nonexistent/does-not-exist.json', report=self.report,
                          assessment=self.assessment, ruleset=self.ruleset)

    def test_no_network_or_process_execution(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), \
             patch('subprocess.Popen', side_effect=AssertionError('execution forbidden')):
            result = self.load(self.payload)
        self.assertEqual(result['origin'], 'untrusted_local_json')


class ProposalCLITests(unittest.TestCase):
    def test_cli_with_synthetic_fixture(self):
        from artemis_v3.cape import load_cape_report
        from artemis_v3.cli import main
        from artemis_v3.ruleset import load_ruleset
        fixtures = Path(__file__).parent / 'fixtures'
        report_path = fixtures / 'cape_synthetic.json'
        rules_path = fixtures / 'scoring_synthetic.json'
        report = load_cape_report(report_path, synthetic=True)
        ruleset = load_ruleset(rules_path)
        evidence = next(item for item in report.evidence if item.category == 'signature')
        payload = {
            'schema_version': 'artemis-proposal/1',
            'report_sha256': report.source_sha256,
            'ruleset_sha256': ruleset.source_sha256,
            'ruleset_version': ruleset.version,
            'proposed_delta': -1,
            'cited_evidence': [evidence.evidence_id],
            'rationale': 'Untrusted synthetic suggestion',
        }
        with tempfile.TemporaryDirectory() as directory:
            proposal_path = Path(directory) / 'proposal.json'
            proposal_path.write_text(json.dumps(payload), encoding='utf-8')
            output = io.StringIO()
            with patch('socket.socket', side_effect=AssertionError('network forbidden')), \
                 patch('subprocess.Popen', side_effect=AssertionError('execution forbidden')), \
                 contextlib.redirect_stdout(output):
                code = main(['--cape-report', str(report_path), '--synthetic',
                             '--ruleset', str(rules_path), '--proposal-file', str(proposal_path),
                             '--format', 'json'])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertTrue(result['proposal_review']['review_required'])
        self.assertEqual(result['proposal_review']['adjustment_proposal']['applied_score'],
                         result['rule_assessment']['base_score'])
        self.assertEqual(result['proposal_review']['analyst_decision'], 'not_recorded')
        self.assertEqual(result['proposal_review']['proposal_sha256'],
                         hashlib.sha256(json.dumps(payload).encode()).hexdigest())

    def test_cli_proposal_requires_ruleset(self):
        from artemis_v3.cli import main
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            main(['--cape-report', 'anything.json', '--proposal-file', 'proposal.json'])
        self.assertEqual(caught.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
