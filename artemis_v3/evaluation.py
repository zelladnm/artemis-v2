"""Reproducible local semantic evaluation; factual support requires human ratings."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time

from .cape import MAX_BYTES, parse_cape_report
from .case_store import source_identity
from .historical import prepare_historical_source
from .ruleset import MAX_RULESET_BYTES, parse_ruleset
from .scoring import assess_signatures
from .semantic import OllamaLocalProvider, SemanticError, SYSTEM_PROMPT, build_explanation_context, explain

MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_CASES = 16
MAX_SUITE_SOURCE_BYTES = 32 * 1024 * 1024


class EvaluationError(ValueError):
    """Invalid evaluation inputs; no benchmark result should be inferred."""


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def implementation_fingerprints():
    return {name: digest(Path(__file__).with_name(name + '.py').read_bytes())
            for name in ('evaluation', 'semantic', 'cape', 'ruleset', 'scoring', 'proposals', 'historical', 'case_store')}


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


def _case_identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value):
        raise EvaluationError('Case IDs must be bounded identifiers')


def _context_preview(report, catalog, historical):
    try:
        context, _ = build_explanation_context(report, catalog, historical=historical)
    except SemanticError as exc:
        return {'ready': False, 'model_called': False, 'error': str(exc)}, None
    current_ids = [item['evidence_id'] for item in context['evidence']]
    history = context.get('historical_context')
    return {'ready': True, 'model_called': False, 'error': None,
            'current_evidence_ids': current_ids,
            'current_omitted': len(report.evidence) - len(current_ids),
            'historical_evidence_ids': [item['evidence_id'] for item in history['evidence']] if history else [],
            'historical_omitted': history['omitted_evidence_count'] if history else 0}, context


def _source_profile(report, raw):
    return {**source_identity(raw), 'synthetic': report.synthetic, 'schema_version': report.schema_version,
            'evidence_count': len(report.evidence), 'category_counts': dict(Counter(item.category for item in report.evidence)),
            'coverage_warning_count': len(report.warnings), 'coverage_warnings': report.warnings[:32]}


def prepare_suite(report_path, ruleset_path, output_dir, *, case_id, name='Local CAPE evaluation draft',
                  historical_path=None, synthetic=False):
    """Copy explicit local sources into a draft; never infer human expectations."""
    _case_identifier(case_id); _text(name, 128)
    if type(synthetic) is not bool:
        raise EvaluationError('Source synthetic provenance must be boolean')
    report_raw = _read(Path(report_path), MAX_BYTES)
    rules_raw = _read(Path(ruleset_path), MAX_RULESET_BYTES)
    historical_raw = _read(Path(historical_path), MAX_BYTES) if historical_path is not None else b''
    if len(report_raw) + len(rules_raw) + len(historical_raw) > MAX_SUITE_SOURCE_BYTES:
        raise EvaluationError('Suite source data exceeds 32 MiB')
    report = parse_cape_report(report_raw, synthetic=synthetic)
    catalog = parse_ruleset(rules_raw)
    historical = (prepare_historical_source('evaluation-source:' + digest(historical_raw), historical_raw,
                                           report, report_raw, synthetic=synthetic)
                  if historical_path is not None else None)
    assessment = assess_signatures(report, catalog.rules, version=catalog.version)
    preview, context = _context_preview(report, catalog, historical)
    sources = {'sources/report.json': report_raw, 'sources/ruleset.json': rules_raw}
    history = None
    if historical is not None:
        sources['sources/historical-report.json'] = historical_raw
        history = {'report': 'sources/historical-report.json', 'report_sha256': digest(historical_raw),
                   'synthetic': synthetic}
    case = {'case_id': case_id, 'report': 'sources/report.json', 'report_sha256': digest(report_raw),
            'ruleset': 'sources/ruleset.json', 'ruleset_sha256': catalog.source_sha256, 'synthetic': synthetic,
            'expected_base_score': None, 'expected_critical': None, 'reference_notes': '', 'historical': history}
    suite = {'schema_version': 'artemis-eval-suite/2', 'name': name, 'cases': [case]}
    preparation = {'schema_version': 'artemis-eval-preparation/1', 'status': 'draft', 'model_called': False,
                   'draft_suite_sha256': digest(encode(suite)), 'case_id': case_id,
                   'implementation_sha256': implementation_fingerprints(),
                   'current_source': _source_profile(report, report_raw),
                   'historical_source': _source_profile(historical.report, historical_raw) if historical else None,
                   'ruleset': {'sha256': catalog.source_sha256, 'version': catalog.version, 'synthetic': catalog.synthetic},
                   'observed_rule_result': {'base_score': assessment.base_score,
                       'critical_signals_present': assessment.critical_signals_present,
                       'matched_rules': [{'rule_id': finding.rule_id, 'points': finding.points, 'critical': finding.critical,
                                          'representative_evidence_id': finding.evidence_refs[0]} for finding in assessment.findings]},
                   'context_preflight': preview,
                   'environment_to_record': {'cape_version': None, 'processor_version': None, 'guest_os': None},
                   'required_analyst_fields': ['expected_base_score', 'expected_critical', 'reference_notes'],
                   'notice': 'Observed rule output is not independent ground truth. Fill expectations and reference notes before running. Source files are exact copies, not anonymized; no model was contacted.'}
    files = {**sources, 'preparation.json': encode(preparation), 'suite.json': encode(suite)}
    if context is not None:
        snapshot = encode(context)
        files['model-context.json'] = snapshot
        preview['snapshot'] = {'path': 'model-context.json', 'file_sha256': digest(snapshot)}
        files['preparation.json'] = encode(preparation)
    if len(files['preparation.json']) > MAX_ARTIFACT_BYTES:
        raise EvaluationError('Preparation artifact exceeds its byte limit')
    destination = Path(output_dir)
    # Exclusive creation preserves existing files/directories, including symlinks.
    # A failed/interrupted write may leave an incomplete draft; never auto-overwrite it.
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    (destination / 'sources').mkdir(mode=0o700)
    for relative, raw in files.items():
        with (destination / relative).open('xb') as target:
            target.write(raw)
    return preparation


def check_suite(suite_path):
    """Validate annotated source contracts and production context without a model."""
    suite, suite_hash, prepared = load_suite(suite_path)
    cases = []
    for case, report, catalog, assessment, historical in prepared:
        preview, _ = _context_preview(report, catalog, historical)
        cases.append({'case_id': case['case_id'], 'report_sha256': report.source_sha256,
                      'historical_report_sha256': historical.report.source_sha256 if historical else None,
                      'base_score': assessment.base_score, 'critical': assessment.critical_signals_present,
                      'synthetic': report.synthetic, 'ruleset_synthetic': catalog.synthetic,
                      'current_evidence_count': len(report.evidence),
                      'current_coverage_warning_count': len(report.warnings), 'current_coverage_warnings': report.warnings[:32],
                      'historical_evidence_count': len(historical.report.evidence) if historical else 0,
                      'historical_coverage_warning_count': len(historical.report.warnings) if historical else 0,
                      'historical_coverage_warnings': historical.report.warnings[:32] if historical else [],
                      'context_preflight': preview})
    return {'schema_version': 'artemis-eval-preflight/1', 'suite_sha256': suite_hash,
            'implementation_sha256': implementation_fingerprints(),
            'ready': all(case['context_preflight']['ready'] for case in cases), 'model_called': False,
            'cases': cases, 'notice': 'Source and context contracts only; no model or factual-support validation.'}


def load_suite(path):
    path = Path(path).resolve()
    raw = _read(path, 64 * 1024)
    suite = _json(raw)
    _fields(suite, 'schema_version name cases')
    if suite['schema_version'] not in ('artemis-eval-suite/1', 'artemis-eval-suite/2'):
        raise EvaluationError('Unsupported evaluation suite schema')
    _text(suite['name'], 128)
    if not isinstance(suite['cases'], list) or not 1 <= len(suite['cases']) <= MAX_CASES:
        raise EvaluationError('A suite requires 1-16 cases')
    seen, prepared, total = set(), [], 0
    for case in suite['cases']:
        fields = 'case_id report report_sha256 ruleset ruleset_sha256 synthetic expected_base_score expected_critical reference_notes'
        _fields(case, fields + (' historical' if suite['schema_version'] == 'artemis-eval-suite/2' else ''))
        case_id = case['case_id']
        _case_identifier(case_id)
        if case_id in seen:
            raise EvaluationError('Case IDs must be distinct bounded identifiers')
        seen.add(case_id)
        if case['expected_base_score'] is None or case['expected_critical'] is None or case['reference_notes'] == '':
            raise EvaluationError('Draft suite: fill analyst expected_base_score, expected_critical and reference_notes before running')
        _text(case['reference_notes'])
        if (type(case['synthetic']) is not bool or type(case['expected_critical']) is not bool or
                type(case['expected_base_score']) is not int or not 0 <= case['expected_base_score'] <= 10):
            raise EvaluationError('Invalid case provenance or rule expectations')
        report_raw = _source(path.parent, case['report'], case['report_sha256'], MAX_BYTES)
        rules_raw = _source(path.parent, case['ruleset'], case['ruleset_sha256'], MAX_RULESET_BYTES)
        historical_raw = b''
        source = case.get('historical')
        if source is not None:
            _fields(source, 'report report_sha256 synthetic')
            if type(source['synthetic']) is not bool:
                raise EvaluationError('Historical source provenance must be boolean')
            historical_raw = _source(path.parent, source['report'], source['report_sha256'], MAX_BYTES)
        total += len(report_raw) + len(rules_raw) + len(historical_raw)
        if total > MAX_SUITE_SOURCE_BYTES:
            raise EvaluationError('Suite source data exceeds 32 MiB')
        report = parse_cape_report(report_raw, synthetic=case['synthetic'])
        catalog = parse_ruleset(rules_raw)
        historical = (prepare_historical_source('evaluation-source:' + digest(historical_raw), historical_raw,
                                               report, report_raw, synthetic=source['synthetic'])
                      if source is not None else None)
        assessment = assess_signatures(report, catalog.rules, version=catalog.version)
        if (assessment.base_score != case['expected_base_score'] or
                assessment.critical_signals_present != case['expected_critical']):
            raise EvaluationError('Rule assessment differs from independently declared case expectations')
        prepared.append((case, report, catalog, assessment, historical))
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
    attributed = run['schema_version'] == 'artemis-eval-run/2'
    items = []
    for row in run['attempts']:
        explanation = row['explanation']
        if explanation is None:
            continue
        claims = [(section, index, claim['text'], claim['evidence_refs'], claim.get('verification'),
                   claim.get('source_scope', 'current'))
                  for section in ('source_observations', 'hypotheses')
                  for index, claim in enumerate(explanation[section])]
        packet = explanation['proposal_review']
        if packet:
            proposal = packet['adjustment_proposal']
            claims.append(('adjustment', 0, proposal['rationale'], proposal['cited_evidence'], None, 'current'))
        for section, index, text, refs, verification, scope in claims:
            item = {'claim_id': f"{row['case_id']}:{row['iteration']}:{section}:{index}",
                    'case_id': row['case_id'], 'section': section, 'text': text,
                    'evidence_refs': refs, 'verification': verification,
                    'rating': 'unreviewed', 'reason': ''}
            if attributed:
                item['source_scope'] = scope
            items.append(item)
    return {'schema_version': 'artemis-eval-ratings/2' if attributed else 'artemis-eval-ratings/1', 'run_sha256': run_sha256,
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
        if any(not case['synthetic'] or (historical is not None and not historical.report.synthetic)
               for case, _, _, _, historical in prepared):
            raise EvaluationError('Synthetic replay requires explicitly synthetic source cases')
        outputs, replay_hash = load_replay(replay_path, suite_hash, [case['case_id'] for case, *_ in prepared])
    destination = Path(output_dir)
    # Refuse existing destinations, including symlinks. Never overwrite originals.
    destination.mkdir(parents=False, exist_ok=False)
    implementation = implementation_fingerprints()
    attributed = suite['schema_version'] == 'artemis-eval-suite/2'
    run = {'schema_version': 'artemis-eval-run/2' if attributed else 'artemis-eval-run/1', 'suite_name': suite['name'], 'suite_sha256': suite_hash,
           'mode': 'synthetic_replay' if outputs is not None else 'local_model',
           'replay_sha256': replay_hash, 'started_at': datetime.now(timezone.utc).isoformat(),
           'prompt_sha256': digest(SYSTEM_PROMPT.encode()), 'implementation_sha256': implementation,
           'requested_model_digest': getattr(provider, 'expected_digest', None),
           'model': provider.model if provider else 'synthetic-replay/1',
           'repeat': repeat, 'cases': [case for case, *_ in prepared], 'attempts': [],
           'notice': 'Contract checks are not factual support or detection accuracy. Human ratings are separate.'}
    for case, report, catalog, assessment, historical in prepared:
        for iteration in range(1, repeat + 1):
            started = time.monotonic()
            row = {'case_id': case['case_id'], 'iteration': iteration, 'base_score': assessment.base_score,
                   'critical': assessment.critical_signals_present, 'status': 'rejected', 'error': None,
                   'explanation': None, 'checks': None}
            active = ReplayProvider('synthetic-replay/1', outputs[case['case_id']]) if outputs is not None else provider
            try:
                explanation, _ = explain(report, active, catalog=catalog, historical=historical)
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
    if attributed:
        historical_ids = {case['case_id'] for case, _, _, _, historical in prepared if historical is not None}
        run['summary']['by_context'] = {}
        for label, historical_mode in (('current_only', False), ('with_history', True)):
            rows = [row for row in attempts if (row['case_id'] in historical_ids) == historical_mode]
            passed = sum(row['status'] == 'accepted' for row in rows)
            run['summary']['by_context'][label] = {'attempts': len(rows), 'accepted': passed,
                                                  'failed': len(rows) - passed,
                                                  'contract_acceptance_fraction': _ratio(passed, len(rows))}
    raw = encode(run)
    (destination / 'run.json.tmp').write_bytes(raw)
    (destination / 'run.json.tmp').replace(destination / 'run.json')
    (destination / 'review.json').write_bytes(encode(review_template(run, digest(raw))))
    return run


def summarize_ratings(run_path, ratings_path):
    raw = _read(Path(run_path), MAX_ARTIFACT_BYTES)
    run = _json(raw)
    if (not isinstance(run, dict) or run.get('schema_version') not in ('artemis-eval-run/1', 'artemis-eval-run/2')
            or 'summary' not in run):
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
    attributed = run['schema_version'] == 'artemis-eval-run/2'
    scopes = {scope: dict.fromkeys(('supported', 'unsupported', 'uncertain', 'unreviewed'), 0)
              for scope in ('current', 'historical', 'mixed')}
    for item in ratings['items']:
        _fields(item, 'claim_id case_id section text evidence_refs verification rating reason' + (' source_scope' if attributed else ''))
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
        if attributed:
            scopes[item['source_scope']][item['rating']] += 1
    for values in (*counts.values(), *scopes.values()):
        total = sum(values.values()); reviewed = total - values['unreviewed']
        values.update(total=total, reviewed=reviewed, coverage=_ratio(reviewed, total),
                      supported_fraction_of_rated=_ratio(values['supported'], reviewed))
    result = {'schema_version': 'artemis-eval-human-summary/2' if attributed else 'artemis-eval-human-summary/1', 'run_sha256': digest(raw),
            'ratings_sha256': digest(ratings_raw), 'reviewer': ratings['reviewer'], 'mode': run['mode'],
            'by_section': counts,
            'notice': 'Human-declared support judgements, not malware accuracy or authenticated review identities.'}
    if attributed:
        result['by_source_scope'] = scopes
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    prepare = sub.add_parser('prepare', help='Copy local sources into a draft; analyst expectations remain blank')
    prepare.add_argument('--report', required=True)
    prepare.add_argument('--ruleset', required=True)
    prepare.add_argument('--historical-report')
    prepare.add_argument('--case-id', required=True)
    prepare.add_argument('--name', default='Local CAPE evaluation draft')
    prepare.add_argument('--synthetic', action='store_true', help='Explicitly label both reports synthetic; default is non-synthetic')
    prepare.add_argument('--output-dir', required=True, help='New directory; sources are copied without anonymization')
    check = sub.add_parser('check', help='Check annotated suite sources and context without contacting a model')
    check.add_argument('--suite', required=True)
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
        elif args.command == 'prepare':
            result = prepare_suite(args.report, args.ruleset, args.output_dir, case_id=args.case_id, name=args.name,
                                   historical_path=args.historical_report, synthetic=args.synthetic)
        elif args.command == 'check':
            result = check_suite(args.suite)
        else:
            if bool(args.ollama_model) != bool(args.model_digest):
                raise EvaluationError('--model-digest is required only with --ollama-model')
            provider = OllamaLocalProvider(args.ollama_model, expected_digest=args.model_digest,
                                           port=args.ollama_port, timeout=args.model_timeout) if args.ollama_model else None
            result = run_suite(args.suite, args.output_dir, provider=provider, replay_path=args.replay, repeat=args.repeat)
        print(encode(result['summary'] if args.command == 'run' else result).decode(), end='')
        return 1 if ((args.command == 'run' and result['summary']['failed']) or
                     (args.command == 'check' and not result['ready'])) else 0
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as exc:
        parser.exit(2, f'Evaluation failed: {exc}\n')


if __name__ == '__main__':
    raise SystemExit(main())
