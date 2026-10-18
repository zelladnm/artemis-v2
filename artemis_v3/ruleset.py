"""Explicit local, bounded JSON configuration for the scoring research scaffold."""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from .scoring import SignatureRule, validate_rules

MAX_RULESET_BYTES = 64 * 1024


@dataclass(frozen=True)
class RuleSet:
    version: str
    rules: tuple[SignatureRule, ...]
    source_sha256: str
    synthetic: bool


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate ruleset JSON key')
        result[key] = value
    return result


def _constant(value):
    raise ValueError('Invalid ruleset JSON number')


def load_ruleset(path: str | Path) -> RuleSet:
    """No downloaded, report-supplied, or model-generated rules are auto-loaded."""
    path = Path(path)
    if not path.is_file():
        raise ValueError('Ruleset must be a regular local file')
    try:
        with path.open('rb') as source:
            raw = source.read(MAX_RULESET_BYTES + 1)
    except OSError as exc:
        raise ValueError('Cannot read ruleset') from exc
    return parse_ruleset(raw)


def parse_ruleset(raw: bytes) -> RuleSet:
    """Parse explicitly supplied catalog bytes without temporary files."""
    if not isinstance(raw, bytes):
        raise ValueError('Expected ruleset JSON bytes')
    if len(raw) > MAX_RULESET_BYTES:
        raise ValueError('Ruleset exceeds the 64 KiB limit')
    try:
        root = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, RecursionError) as exc:
        raise ValueError('Invalid ruleset JSON') from exc
    if not isinstance(root, dict) or set(root) != {'version', 'rules', 'synthetic'}:
        raise ValueError('Ruleset requires exactly version, rules and synthetic')
    if type(root['synthetic']) is not bool or not isinstance(root['rules'], list):
        raise ValueError('Invalid ruleset label or rules array')
    if not 1 <= len(root['rules']) <= 128:
        raise ValueError('Ruleset requires 1-128 rules')
    rules = []
    required = {'rule_id', 'signature_name', 'points'}
    for row in root['rules']:
        if not isinstance(row, dict) or not required <= set(row) or set(row) - required - {'critical'}:
            raise ValueError('Rule requires rule_id, signature_name, points and optional critical')
        rules.append(SignatureRule(**row))
    return RuleSet(root['version'], validate_rules(rules, version=root['version']),
                   hashlib.sha256(raw).hexdigest(), root['synthetic'])
