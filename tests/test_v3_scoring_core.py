"""Offline regression checks for deterministic evidence scoring."""
from dataclasses import dataclass
from types import SimpleNamespace
import unittest

from artemis_v3.scoring import SignatureRule, assess_signatures


@dataclass(frozen=True)
class Record:
    evidence_id: str
    category: str
    data: dict


def make_report(*records, warnings=()):
    return SimpleNamespace(source_sha256="a" * 64, evidence=list(records),
                           warnings=list(warnings), synthetic=True)


def signature(index, name):
    return Record("a" * 64 + f"#/signatures/{index}", "signature", {"name": name})


RULES = (SignatureRule("R1", "test.signal_a", 7, True),
         SignatureRule("R2", "test.signal_b", 4))


class ScoringCoreTests(unittest.TestCase):
    def test_exact_match_and_capped_score(self):
        source = make_report(signature(0, "test.signal_a"), signature(1, "test.signal_b"))
        result = assess_signatures(source, RULES, version="demo/1")
        self.assertEqual(result.base_score, 10)
        self.assertEqual(result.findings[0].evidence_refs, (source.evidence[0].evidence_id,))
        self.assertEqual(result.verdict, "not_assessed")
        self.assertTrue(result.review_required)

    def test_duplicate_reports_do_not_inflate_score(self):
        source = make_report(signature(0, "test.signal_b"), signature(1, "test.signal_b"))
        result = assess_signatures(source, RULES, version="demo/1")
        self.assertEqual(result.base_score, 4)
        self.assertEqual(len(result.findings[0].evidence_refs), 2)

    def test_unknown_signals_do_not_imply_safety(self):
        source = make_report(signature(0, "unknown"), warnings=("coverage incomplete",))
        result = assess_signatures(source, RULES, version="demo/1")
        self.assertEqual(result.base_score, 0)
        self.assertEqual(result.verdict, "not_assessed")
        self.assertEqual(result.coverage_warnings, ("coverage incomplete",))

    def test_invalid_rule_definitions_rejected(self):
        invalid = [
            (SignatureRule("R", "x", True),),
            (SignatureRule("R", "x", -1),),
            (SignatureRule("R", "x", 1), SignatureRule("R", "y", 1)),
            (SignatureRule("R", "x", 1), SignatureRule("S", "x", 1)),
        ]
        for rules in invalid:
            with self.subTest(rules=rules), self.assertRaises(ValueError):
                assess_signatures(make_report(), rules, version="demo/1")


if __name__ == "__main__":
    unittest.main()
