"""Offline, auditable signature scoring research scaffold; never a verdict.

Rule definitions are analyst-controlled and require independent validation.
No heuristic is inferred from filenames, unsigned reports or model prose.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable
from itertools import islice


@dataclass(frozen=True)
class SignatureRule:
    rule_id: str
    signature_name: str
    points: int
    critical: bool = False


@dataclass(frozen=True)
class RuleFinding:
    rule_id: str
    signature_name: str
    points: int
    critical: bool
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class RuleAssessment:
    source_sha256: str
    ruleset_version: str
    base_score: int
    critical_signals_present: bool
    findings: tuple[RuleFinding, ...]
    coverage_warnings: tuple[str, ...]
    synthetic: bool
    verdict: str = "not_assessed"
    review_required: bool = True

    def as_dict(self) -> dict:
        result = asdict(self)
        result["score_meaning"] = "Uncalibrated rule points (0-10); not a probability or verdict"
        result["evidence_warning"] = "Signature records are source assertions, not independently verified behavior"
        return result


@dataclass(frozen=True)
class AdjustmentProposal:
    source_sha256: str
    proposed_delta: int
    proposed_score: int
    applied_score: int
    cited_evidence: tuple[str, ...]
    rationale: str
    status: str
    blocked_reason: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


def validate_rules(rules: Iterable[SignatureRule], *, version: str) -> tuple[SignatureRule, ...]:
    """Validate a bounded analyst-controlled rule catalog."""
    if not isinstance(version, str) or not 0 < len(version.strip()) <= 100:
        raise ValueError("Ruleset version is required (maximum 100 characters)")
    rules = tuple(islice(rules, 129))
    if len(rules) > 128:
        raise ValueError("Too many signature rules")
    ids, names = set(), set()
    for rule in rules:
        if not isinstance(rule, SignatureRule):
            raise ValueError("Expected SignatureRule definitions")
        if (not isinstance(rule.rule_id, str) or not 0 < len(rule.rule_id.strip()) <= 100 or
                not isinstance(rule.signature_name, str) or not 0 < len(rule.signature_name.strip()) <= 200 or
                type(rule.points) is not int or not 1 <= rule.points <= 10 or
                type(rule.critical) is not bool):
            raise ValueError("Invalid signature rule fields")
        if rule.rule_id in ids or rule.signature_name in names:
            raise ValueError("Duplicate rule ID or signature name")
        ids.add(rule.rule_id)
        names.add(rule.signature_name)
    return rules


def assess_signatures(report, rules: Iterable[SignatureRule], *, version: str) -> RuleAssessment:
    """Match exact signature names; count each rule once, retaining every source pointer."""
    rules = validate_rules(rules, version=version)
    matched = {rule.signature_name: [] for rule in rules}
    for item in report.evidence:
        if item.category != "signature" or not isinstance(item.data, dict):
            continue
        name = item.data.get("name")
        if isinstance(name, str) and name in matched:
            matched[name].append(item.evidence_id)
    findings = tuple(RuleFinding(rule.rule_id, rule.signature_name, rule.points,
                                 rule.critical, tuple(dict.fromkeys(matched[rule.signature_name])))
                     for rule in rules if matched[rule.signature_name])
    return RuleAssessment(source_sha256=report.source_sha256,
                          ruleset_version=version,
                          base_score=min(10, sum(item.points for item in findings)),
                          critical_signals_present=any(item.critical for item in findings),
                          findings=findings, coverage_warnings=tuple(report.warnings),
                          synthetic=report.synthetic)


def propose_adjustment(report, assessment: RuleAssessment, *, delta: int,
                       cited_evidence: Iterable[str], rationale: str) -> AdjustmentProposal:
    """Record a proposal without changing the deterministic score.

    Critical evidence blocks negative proposals; all others await an analyst.
    """
    if assessment.source_sha256 != report.source_sha256:
        raise ValueError("Assessment and evidence source differ")
    if type(delta) is not int or not -10 <= delta <= 10:
        raise ValueError("Adjustment must be an integer between -10 and 10")
    if not isinstance(rationale, str) or not 1 <= len(rationale.strip()) <= 500:
        raise ValueError("A concise rationale is required")
    refs = tuple(islice(cited_evidence, 33))
    available = {item.evidence_id for item in report.evidence}
    if (not refs or len(refs) > 32 or any(not isinstance(ref, str) for ref in refs) or
            len(set(refs)) != len(refs) or not set(refs) <= available):
        raise ValueError("Proposal must cite 1-32 distinct evidence IDs from the same report")
    blocked = assessment.critical_signals_present and delta < 0
    return AdjustmentProposal(source_sha256=report.source_sha256, proposed_delta=delta,
                              proposed_score=max(0, min(10, assessment.base_score + delta)),
                              applied_score=assessment.base_score,
                              cited_evidence=refs, rationale=rationale.strip(),
                              status="blocked_critical_signal" if blocked else "awaiting_analyst_review",
                              blocked_reason="Critical rule evidence cannot be automatically downgraded" if blocked else None)
