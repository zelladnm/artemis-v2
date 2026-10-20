"""Reproducible local semantic evaluation; factual support requires human ratings."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time

from .cape import MAX_BYTES, parse_cape_report
from .ruleset import MAX_RULESET_BYTES, parse_ruleset
from .scoring import assess_signatures
from .semantic import OllamaLocalProvider, SemanticError, SYSTEM_PROMPT, explain

MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_CASES = 16


class EvaluationError(ValueError):
    """Invalid evaluation inputs; no benchmark result should be inferred."""


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvaluationError('Duplicate evaluation JSON keys')
        result[key] = value
    return result


def _constant(value):
    raise EvaluationError('Non-finite evaluation JSON number')


def _read(path, limit):
    if not path.is_file():
        raise EvaluationError('Evaluation input must be a regular file')
    with path.open('rb') as source:
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise EvaluationError('Evaluation input exceeds its byte limit')
    return raw


def _json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, RecursionError) as exc:
        raise EvaluationError('Invalid evaluation JSON') from exc


def _fields(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields.split()):
        raise EvaluationError('Evaluation object fields do not match its schema')


def _text(value, limit=2000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise EvaluationError('Expected bounded nonempty evaluation text')


def _source(root, relative, expected, limit):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise EvaluationError('Suite inputs must be relative paths within the suite directory')
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise EvaluationError('Suite input escapes its directory')
    raw = _read(path, limit)
    if not isinstance(expected, str) or digest(raw) != expected:
        raise EvaluationError('Suite source fingerprint mismatch')
    return raw


def load_suite(path):
    path = Path(path).resolve()
    raw = _read(path, 64 * 1024)
    suite = _json(raw)
    _fields(suite, 'schema_version name cases')
    if suite['schema_version'] != 'artemis-eval-suite/1':
        raise EvaluationError('Unsupported evaluation suite schema')
    _text(suite['name'], 128)
    if not isinstance(suite['cases'], list) or not 1 <= len(suite['cases']) <= MAX_CASES:
        raise EvaluationError('A suite requires 1-16 cases')
    seen, prepared, total = set(), [], 0
    for case in suite['cases']:
        _fields(case, 'case_id report report_sha256 ruleset ruleset_sha256 synthetic expected_base_score expected_critical reference_notes')
        case_id = case['case_id']
        if (not isinstance(case_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', case_id)
                or case_id in seen):
            raise EvaluationError('Case IDs must be distinct bounded identifiers')
        seen.add(case_id)
        _text(case['reference_notes'])
        if (type(case['synthetic']) is not bool or type(case['expected_critical']) is not bool or
                type(case['expected_base_score']) is not int or not 0 <= case['expected_base_score'] <= 10):
            raise EvaluationError('Invalid case provenance or rule expectations')
        report_raw = _source(path.parent, case['report'], case['report_sha256'], MAX_BYTES)
        rules_raw = _source(path.parent, case['ruleset'], case['ruleset_sha256'], MAX_RULESET_BYTES)
        total += len(report_raw) + len(rules_raw)
        if total > 32 * 1024 * 1024:
            raise EvaluationError('Suite source data exceeds 32 MiB')
        report = parse_cape_report(report_raw, synthetic=case['synthetic'])
        catalog = parse_ruleset(rules_raw)
        assessment = assess_signatures(report, catalog.rules, version=catalog.version)
        if (assessment.base_score != case['expected_base_score'] or
                assessment.critical_signals_present != case['expected_critical']):
            raise EvaluationError('Rule assessment differs from independently declared case expectations')
        prepared.append((case, report, catalog, assessment))
    return suite, digest(raw), prepared


class ReplayProvider:
    """Recorded synthetic output, never presented as a model-quality measurement."""
    def __init__(self, model, output):
        self.model, self.output = model, output

    def generate(self, context):
        return {'output': self.output, 'response_sha256': digest(encode(self.output))}


def load_replay(path, suite_sha256, case_ids):
    raw = _read(Path(path), MAX_ARTIFACT_BYTES)
    replay = _json(raw)
    _fields(replay, 'schema_version suite_sha256 outputs')
    if replay['schema_version'] != 'artemis-eval-replay/1' or replay['suite_sha256'] != suite_sha256:
        raise EvaluationError('Replay does not match this exact suite')
    if not isinstance(replay['outputs'], dict) or set(replay['outputs']) != set(case_ids):
        raise EvaluationError('Replay must contain exactly one output per case')
    return replay['outputs'], digest(raw)


def _ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def review_template(run, run_sha256):
    items = []
    for row in run['attempts']:
        explanation = row['explanation']
        if explanation is None:
            continue
        claims = [(section, index, claim['text'], claim['evidence_refs'], claim.get('verification'))
                  for section in ('source_observations', 'hypotheses')
                  for index, claim in enumerate(explanation[section])]
        packet = explanation['proposal_review']
        if packet:
            proposal = packet['adjustment_proposal']
            claims.append(('adjustment', 0, proposal['rationale'], proposal['cited_evidence'], None))
        for section, index, text, refs, verification in claims:
            items.append({'claim_id': f"{row['case_id']}:{row['iteration']}:{section}:{index}",
                          'case_id': row['case_id'], 'section': section, 'text': text,
                          'evidence_refs': refs, 'verification': verification,
                          'rating': 'unreviewed', 'reason': ''})
    return {'schema_version': 'artemis-eval-ratings/1', 'run_sha256': run_sha256,
            'reviewer': '', 'items': items}


def run_suite(suite_path, output_dir, *, provider=None, replay_path=None, repeat=1):
    if type(repeat) is not int or not 1 <= repeat <= 5:
        raise EvaluationError('Repeat must be between 1 and 5')
    if (provider is None) == (replay_path is None):
        raise EvaluationError('Choose exactly one local model provider or offline replay')
    if replay_path is not None and repeat != 1:
        raise EvaluationError('Replay runs once; replay repetition is not model stability')
    suite, suite_hash, prepared = load_suite(suite_path)
    outputs = replay_hash = None
    if replay_path is not None:
        if any(not case['synthetic'] for case, *_ in prepared):
            raise EvaluationError('Synthetic replay requires explicitly synthetic source cases')
        outputs, replay_hash = load_replay(replay_path, suite_hash, [case['case_id'] for case, *_ in prepared])
    destination = Path(output_dir)
    # Refuse existing destinations, including symlinks. Never overwrite originals.
    destination.mkdir(parents=False, exist_ok=False)
    implementation = {name: digest(Path(__file__).with_name(name + '.py').read_bytes())
                      for name in ('evaluation', 'semantic', 'cape', 'ruleset', 'scoring', 'proposals')}
    run = {'schema_version': 'artemis-eval-run/1', 'suite_name': suite['name'], 'suite_sha256': suite_hash,
           'mode': 'synthetic_replay' if outputs is not None else 'local_model',
           'replay_sha256': replay_hash, 'started_at': datetime.now(timezone.utc).isoformat(),
           'prompt_sha256': digest(SYSTEM_PROMPT.encode()), 'implementation_sha256': implementation,
           'requested_model_digest': getattr(provider, 'expected_digest', None),
           'model': provider.model if provider else 'synthetic-replay/1',
           'repeat': repeat, 'cases': [case for case, *_ in prepared], 'attempts': [],
           'notice': 'Contract checks are not factual support or detection accuracy. Human ratings are separate.'}
    for case, report, catalog, assessment in prepared:
        for iteration in range(1, repeat + 1):
            started = time.monotonic()
            row = {'case_id': case['case_id'], 'iteration': iteration, 'base_score': assessment.base_score,
                   'critical': assessment.critical_signals_present, 'status': 'rejected', 'error': None,
                   'explanation': None, 'checks': None}
            active = ReplayProvider('synthetic-replay/1', outputs[case['case_id']]) if outputs is not None else provider
            try:
                explanation, _ = explain(report, active, catalog=catalog)
                packet = explanation['proposal_review']
                adjustment = packet['adjustment_proposal'] if packet else None
                critical_negative = bool(adjustment and row['critical'] and adjustment['proposed_delta'] < 0)
                checks = {'base_score_preserved': not adjustment or adjustment['applied_score'] == assessment.base_score,
                          'critical_negative_proposed': critical_negative,
                          'critical_negative_blocked': bool(critical_negative and adjustment['status'] == 'blocked_critical_signal')}
                row.update(explanation=explanation, checks=checks,
                           status='accepted' if checks['base_score_preserved'] and
                           (not critical_negative or checks['critical_negative_blocked']) else 'checks_failed')
            except SemanticError as exc:
                row['error'] = str(exc)
            row['elapsed_ms'] = round((time.monotonic() - started) * 1000, 3)
            run['attempts'].append(row)
            # A partial run survives interruption; final review template is written only on completion.
            temporary = destination / 'run.json.tmp'
            temporary.write_bytes(encode(run)); temporary.replace(destination / 'run.json')
    attempts = run['attempts']
    accepted = sum(row['status'] == 'accepted' for row in attempts)
    checks = [row['checks'] for row in attempts if row['checks'] is not None]
    variation = {}
    for case, *_ in prepared:
        rows = [row['explanation'] for row in attempts if row['case_id'] == case['case_id'] and row['explanation']]
        contents = [{key: row[key] for key in ('source_observations', 'hypotheses', 'limitations', 'proposal_review')} for row in rows]
        variation[case['case_id']] = {'completed_outputs': len(rows),
                                    'distinct_outputs': len({digest(encode(value)) for value in contents}),
                                    'model_digests': sorted({row['model_digest'] for row in rows if row['model_digest']})}
    run['summary'] = {'attempts': len(attempts), 'accepted': accepted, 'failed': len(attempts) - accepted,
                      'contract_acceptance_fraction': _ratio(accepted, len(attempts)),
                      'critical_negative_proposed': sum(c['critical_negative_proposed'] for c in checks),
                      'critical_negative_blocked': sum(c['critical_negative_blocked'] for c in checks),
                      'base_score_violations': sum(not c['base_score_preserved'] for c in checks),
                      'human_factual_support': None, 'output_variation': variation}
    raw = encode(run)
    (destination / 'run.json.tmp').write_bytes(raw)
    (destination / 'run.json.tmp').replace(destination / 'run.json')
    (destination / 'review.json').write_bytes(encode(review_template(run, digest(raw))))
    return run


def summarize_ratings(run_path, ratings_path):
    raw = _read(Path(run_path), MAX_ARTIFACT_BYTES)
    run = _json(raw)
    if not isinstance(run, dict) or run.get('schema_version') != 'artemis-eval-run/1' or 'summary' not in run:
        raise EvaluationError('Expected a completed evaluation run')
    expected = review_template(run, digest(raw))
    ratings_raw = _read(Path(ratings_path), MAX_ARTIFACT_BYTES)
    ratings = _json(ratings_raw)
    _fields(ratings, 'schema_version run_sha256 reviewer items')
    if (ratings['schema_version'] != expected['schema_version'] or ratings['run_sha256'] != expected['run_sha256'] or
            not isinstance(ratings['items'], list) or len(ratings['items']) != len(expected['items'])):
        raise EvaluationError('Ratings do not match this exact completed run')
    if not isinstance(ratings['reviewer'], str) or len(ratings['reviewer']) > 128:
        raise EvaluationError('Invalid declared reviewer')
    by_id = {item['claim_id']: item for item in expected['items']}
    counts = {section: dict.fromkeys(('supported', 'unsupported', 'uncertain', 'unreviewed'), 0)
              for section in ('source_observations', 'hypotheses', 'adjustment')}
    for item in ratings['items']:
        _fields(item, 'claim_id case_id section text evidence_refs verification rating reason')
        if not isinstance(item['claim_id'], str):
            raise EvaluationError('Invalid claim ID')
        original = by_id.pop(item['claim_id'], None)
        if original is None or any(item[key] != original[key] for key in original if key not in ('rating', 'reason')):
            raise EvaluationError('Missing, duplicated or modified evaluation claims')
        if not isinstance(item['rating'], str) or item['rating'] not in counts[item['section']]:
            raise EvaluationError('Unknown human support rating')
        if not isinstance(item['reason'], str) or len(item['reason']) > 2000:
            raise EvaluationError('Invalid human rating reason')
        if item['rating'] != 'unreviewed':
            _text(ratings['reviewer'], 128); _text(item['reason'])
        counts[item['section']][item['rating']] += 1
    for values in counts.values():
        total = sum(values.values()); reviewed = total - values['unreviewed']
        values.update(total=total, reviewed=reviewed, coverage=_ratio(reviewed, total),
                      supported_fraction_of_rated=_ratio(values['supported'], reviewed))
    return {'schema_version': 'artemis-eval-human-summary/1', 'run_sha256': digest(raw),
            'ratings_sha256': digest(ratings_raw), 'reviewer': ratings['reviewer'], 'mode': run['mode'],
            'by_section': counts,
            'notice': 'Human-declared support judgements, not malware accuracy or authenticated review identities.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    start = sub.add_parser('run')
    start.add_argument('--suite', required=True)
    choice = start.add_mutually_exclusive_group(required=True)
    choice.add_argument('--replay')
    choice.add_argument('--ollama-model')
    start.add_argument('--model-digest', help='Required artifact SHA-256 for a local-model run')
    start.add_argument('--ollama-port', type=int, default=11434)
    start.add_argument('--model-timeout', type=float, default=60)
    start.add_argument('--repeat', type=int, default=1)
    start.add_argument('--output-dir', required=True, help='New directory; existing paths are refused')
    review = sub.add_parser('review')
    review.add_argument('--run', required=True)
    review.add_argument('--ratings', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'review':
            result = summarize_ratings(args.run, args.ratings)
        else:
            if bool(args.ollama_model) != bool(args.model_digest):
                raise EvaluationError('--model-digest is required only with --ollama-model')
            provider = OllamaLocalProvider(args.ollama_model, expected_digest=args.model_digest,
                                           port=args.ollama_port, timeout=args.model_timeout) if args.ollama_model else None
            result = run_suite(args.suite, args.output_dir, provider=provider, replay_path=args.replay, repeat=args.repeat)
        print(encode(result['summary'] if args.command == 'run' else result).decode(), end='')
        return 1 if args.command == 'run' and result['summary']['failed'] else 0
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as exc:
        parser.exit(2, f'Evaluation failed: {exc}\n')


if __name__ == '__main__':
    raise SystemExit(main())
