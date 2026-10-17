"""Offline tests for analyst review gates and source citations."""
from dataclasses import dataclass
from types import SimpleNamespace
import unittest

from artemis_v3.scoring import SignatureRule, assess_signatures, propose_adjustment


@dataclass(frozen=True)
class Record:
    evidence_id: str
    category: str
    data: dict


def make_report(name):
    return SimpleNamespace(source_sha256="a" * 64, synthetic=True, warnings=[],
                           evidence=[Record("a" * 64 + "#/signatures/0", "signature", {"name": name})])


class ReviewGateTests(unittest.TestCase):
    def test_critical_signal_requires_human_review(self):
        source = make_report("test.signal_a")
        result = assess_signatures(source, [SignatureRule("R1", "test.signal_a", 7, True)], version="demo/1")
        proposed = propose_adjustment(source, result, delta=-6,
                                      cited_evidence=[source.evidence[0].evidence_id],
                                      rationale="Synthetic context review")
        self.assertEqual(proposed.status, "blocked_critical_signal")
        self.assertEqual(proposed.applied_score, 7)
        self.assertEqual(proposed.proposed_score, 1)

    def test_noncritical_proposal_is_not_applied(self):
        source = make_report("test.signal_b")
        result = assess_signatures(source, [SignatureRule("R2", "test.signal_b", 4)], version="demo/1")
        proposed = propose_adjustment(source, result, delta=-3,
                                      cited_evidence=[source.evidence[0].evidence_id], rationale="Review")
        self.assertEqual(proposed.status, "awaiting_analyst_review")
        self.assertEqual(proposed.applied_score, 4)

    def test_unknown_citation_is_rejected(self):
        source = make_report("test.signal_b")
        result = assess_signatures(source, [SignatureRule("R2", "test.signal_b", 4)], version="demo/1")
        for refs in ([], ["invented"], [source.evidence[0].evidence_id] * 2):
            with self.subTest(refs=refs), self.assertRaises(ValueError):
                propose_adjustment(source, result, delta=-2, cited_evidence=refs, rationale="Review")

    def test_cross_report_rejected(self):
        source = make_report("test.signal_b")
        result = assess_signatures(source, [SignatureRule("R2", "test.signal_b", 4)], version="demo/1")
        other = SimpleNamespace(source_sha256="b" * 64, evidence=source.evidence)
        with self.assertRaises(ValueError):
            propose_adjustment(other, result, delta=-2,
                               cited_evidence=[source.evidence[0].evidence_id], rationale="Review")


if __name__ == "__main__":
    unittest.main()
