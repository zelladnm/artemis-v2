"""Bounded, offline intake of untrusted AI/analyst adjustment suggestions.

This module never runs a model, authenticates a reviewer, or changes a score.
The original report, ruleset, and deterministic assessment are authoritative
for *identity checks only*; their contents are still unverified source claims.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .scoring import propose_adjustment

MAX_PROPOSAL_BYTES = 32 * 1024
_FIELDS = frozenset({
    'schema_version', 'report_sha256', 'ruleset_sha256', 'ruleset_version',
    'proposed_delta', 'cited_evidence', 'rationale',
})


class ProposalError(ValueError):
    """Untrusted proposal failed a bounded contract or provenance check."""


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProposalError('Duplicate proposal JSON key')
        result[key] = value
    return result


def _reject_constant(value):
    raise ProposalError('Non-finite proposal number')


def load_proposal(path: str | Path, *, report, assessment, ruleset) -> dict:
    """Validate a proposal against the exact current report and ruleset.

    Return an *unapplied* review packet. All JSON fields are untrusted, even
    when source hashes match: a digest is not a signature or authentication.
    """
    path = Path(path)
    if not path.is_file():
        raise ProposalError('Proposal must be a regular local JSON file')
    try:
        with path.open('rb') as source:
            raw = source.read(MAX_PROPOSAL_BYTES + 1)
    except OSError as exc:
        raise ProposalError('Cannot read proposal file') from exc
    return parse_proposal(raw, report=report, assessment=assessment, ruleset=ruleset)


def parse_proposal(raw: bytes, *, report, assessment, ruleset) -> dict:
    """Validate in-memory report suggestions without reading any supplied path."""
    if not isinstance(raw, bytes):
        raise ProposalError('Expected proposal JSON bytes')
    if len(raw) > MAX_PROPOSAL_BYTES:
        raise ProposalError('Proposal exceeds 32 KiB limit')
    try:
        proposal = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_unique_pairs,
                              parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProposalError('Invalid proposal JSON') from exc
    if not isinstance(proposal, dict) or set(proposal) != _FIELDS:
        raise ProposalError('Proposal requires exactly the documented fields')
    if proposal['schema_version'] != 'artemis-proposal/1':
        raise ProposalError('Unsupported proposal schema')
    if (type(proposal['report_sha256']) is not str or
            proposal['report_sha256'] != report.source_sha256 or
            assessment.source_sha256 != report.source_sha256):
        raise ProposalError('Proposal report digest does not match assessment')
    if (type(proposal['ruleset_sha256']) is not str or
            proposal['ruleset_sha256'] != ruleset.source_sha256 or
            type(proposal['ruleset_version']) is not str or
            proposal['ruleset_version'] != ruleset.version or
            assessment.ruleset_version != ruleset.version):
        raise ProposalError('Proposal ruleset identity does not match assessment')
    if type(proposal['cited_evidence']) is not list:
        raise ProposalError('Proposal citations must be an array')
    try:
        adjustment = propose_adjustment(
            report, assessment,
            delta=proposal['proposed_delta'],
            cited_evidence=proposal['cited_evidence'],
            rationale=proposal['rationale'],
        )
    except (TypeError, ValueError) as exc:
        raise ProposalError('Proposal contains invalid adjustment, rationale, or citations') from exc
    return {
        'schema_version': 'artemis-proposal-review/1',
        'origin': 'untrusted_local_json',
        'proposal_sha256': hashlib.sha256(raw).hexdigest(),
        'ruleset_sha256': ruleset.source_sha256,
        'adjustment_proposal': adjustment.as_dict(),
        'review_required': True,
        'analyst_decision': 'not_recorded',
        'trust_notice': 'No model output is a verdict; no score is applied or reviewer authenticated.',
    }
