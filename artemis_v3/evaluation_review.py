"""Offline, source-checked handoff from a fixed evaluation to human claim review."""
import base64
import copy
from io import BytesIO
import math
from pathlib import Path
import re
import zipfile

from .claim_review import check_saved_inputs, list_claim_reviews, review_template as claim_template
from .evaluation import (MAX_ARTIFACT_BYTES, EvaluationError, _fields, _json, _read, _source,
                         digest, encode, implementation_fingerprints, load_suite,
                         review_template, summarize_attempts, summarize_rating_bytes)
from .cape import MAX_BYTES
from .ruleset import MAX_RULESET_BYTES
from .review import _canonical
from .semantic import SYSTEM_PROMPT, explain


class _RecordedOutput:
    """Validate recorded text through production contracts without a model call."""
    def __init__(self, explanation):
        self.model = explanation['model']
        if any(not isinstance(explanation[key], list) or len(explanation[key]) > 8 or
               any(not isinstance(claim, dict) for claim in explanation[key])
               for key in ('source_observations', 'hypotheses')):
            raise EvaluationError('Invalid recorded claim entries')
        output = {key: [{field: value for field, value in claim.items() if field != 'source_scope'}
                        for claim in explanation[key]] for key in ('source_observations', 'hypotheses')}
        output['limitations'] = explanation['limitations']
        packet = explanation['proposal_review']
        proposal = packet['adjustment_proposal'] if packet else None
        output['adjustment'] = ({'delta': proposal['proposed_delta'], 'rationale': proposal['rationale'],
                                 'cited_evidence': proposal['cited_evidence']} if proposal else None)
        self.generated = {'output': output, 'model_digest': explanation['model_digest'],
                          'model_metadata_sha256': explanation['model_metadata_sha256'],
                          'response_sha256': explanation['model_response_sha256']}

    def generate(self, context):
        return self.generated


class EvaluationReview:
    """One immutable, bounded run/source snapshot; browser requests contain IDs only."""
    def __init__(self, suite_path, run_path):
        try:
            self._load(suite_path, run_path)
        except (KeyError, TypeError, RecursionError) as exc:
            raise EvaluationError('Invalid evaluation review input') from exc

    def _load(self, suite_path, run_path):
        self.raw = _read(Path(run_path), MAX_ARTIFACT_BYTES)
        self.run = run = _json(self.raw)
        _fields(run, 'schema_version suite_name suite_sha256 mode replay_sha256 started_at prompt_sha256 implementation_sha256 requested_model_digest model repeat cases attempts notice summary')
        suite, suite_sha, prepared = load_suite(suite_path)
        version = '2' if suite['schema_version'].endswith('/2') else '1'
        if (not isinstance(run, dict) or run.get('schema_version') != 'artemis-eval-run/' + version or
                not isinstance(run['summary'], dict) or run['suite_name'] != suite['name'] or
                run.get('suite_sha256') != suite_sha or _canonical(run.get('cases')) != _canonical(suite['cases'])):
            raise EvaluationError('Expected a completed run bound to this exact suite')
        if (run.get('implementation_sha256') != implementation_fingerprints() or
                run.get('prompt_sha256') != digest(SYSTEM_PROMPT.encode())):
            raise EvaluationError('Evaluation implementation or prompt differs; use the matching checkout')
        repeat = run.get('repeat')
        if (type(repeat) is not int or not 1 <= repeat <= 5 or
                run.get('mode') not in ('synthetic_replay', 'local_model') or
                (run['mode'] == 'synthetic_replay' and repeat != 1)):
            raise EvaluationError('Invalid evaluation mode or repeat count')
        if (not isinstance(run['model'], str) or not run['model'] or len(run['model']) > 128 or
                (run['mode'] == 'local_model' and (not isinstance(run['requested_model_digest'], str) or
                 not re.fullmatch('[a-f0-9]{64}', run['requested_model_digest']))) or
                (run['mode'] == 'synthetic_replay' and (run['model'] != 'synthetic-replay/1' or
                 any(not case['synthetic'] or (historical is not None and not historical.report.synthetic)
                     for case, _, _, _, historical in prepared)))):
            raise EvaluationError('Invalid model artifact or replay provenance')
        if not isinstance(run.get('attempts'), list) or len(run['attempts']) != len(prepared) * repeat:
            raise EvaluationError('Incomplete evaluation attempts')
        self.run_sha256 = digest(self.raw)
        self.attempts = {}
        root = Path(suite_path).resolve().parent
        rows = iter(run['attempts'])
        for case, report, catalog, assessment, historical in prepared:
            source = _source(root, case['report'], case['report_sha256'], MAX_BYTES)
            rules = _source(root, case['ruleset'], case['ruleset_sha256'], MAX_RULESET_BYTES)
            inputs = {'report': base64.b64encode(source).decode(), 'ruleset': base64.b64encode(rules).decode(),
                      'synthetic': case['synthetic']}
            for iteration in range(1, repeat + 1):
                row = next(rows)
                _fields(row, 'case_id iteration base_score critical status error explanation checks elapsed_ms')
                if (row['case_id'] != case['case_id'] or type(row['iteration']) is not int or row['iteration'] != iteration or
                        type(row['base_score']) is not int or row['base_score'] != assessment.base_score or
                        row['critical'] is not assessment.critical_signals_present or
                        type(row['elapsed_ms']) not in (int, float) or not 0 <= row['elapsed_ms'] <= 86_400_000 or
                        not math.isfinite(row['elapsed_ms'])):
                    raise EvaluationError('Evaluation attempt identity, rule score or timing mismatch')
                generation = None
                if row['status'] == 'rejected':
                    if (row['explanation'] is not None or row['checks'] is not None or
                            not isinstance(row['error'], str) or not row['error'] or len(row['error']) > 2000):
                        raise EvaluationError('Invalid rejected evaluation attempt')
                else:
                    saved = row['explanation']
                    if (not isinstance(saved, dict) or saved['model'] != run['model'] or
                            saved['evidence_selection'] != 'automatic' or row['error'] is not None):
                        raise EvaluationError('Invalid recorded explanation metadata')
                    if run['mode'] == 'local_model' and saved['model_digest'] != run['requested_model_digest']:
                        raise EvaluationError('Recorded model digest differs from the requested artifact')
                    rebuilt, suggestion = explain(report, _RecordedOutput(saved), catalog=catalog, historical=historical)
                    if _canonical(rebuilt) != _canonical(saved):
                        raise EvaluationError('Recorded explanation differs from the current source/context contracts')
                    proposal = saved['proposal_review']['adjustment_proposal'] if saved['proposal_review'] else None
                    negative = bool(proposal and row['critical'] and proposal['proposed_delta'] < 0)
                    checks = {'base_score_preserved': not proposal or proposal['applied_score'] == assessment.base_score,
                              'critical_negative_proposed': negative,
                              'critical_negative_blocked': bool(negative and proposal['status'] == 'blocked_critical_signal')}
                    status = 'accepted' if checks['base_score_preserved'] and (not negative or checks['critical_negative_blocked']) else 'checks_failed'
                    if row['status'] != status or row['checks'] != checks:
                        raise EvaluationError('Recorded technical status/checks are inconsistent')
                    generation = {'explanation': saved, 'suggestion_file_b64': base64.b64encode(suggestion).decode() if suggestion else None}
                    claim_template(generation)  # enforce the persistent snapshot size budget too
                self.attempts[(case['case_id'], iteration)] = {
                    'row': row, 'report': report, 'catalog': catalog, 'inputs': inputs,
                    'generation': generation, 'reference_notes': case['reference_notes']}
        if _canonical(run['summary']) != _canonical(summarize_attempts(run)):
            raise EvaluationError('Evaluation summary does not match its attempts')

    def select(self, request):
        _fields(request, 'case_id iteration')
        if not isinstance(request['case_id'], str) or type(request['iteration']) is not int:
            raise EvaluationError('Select a case ID and integer iteration')
        item = self.attempts.get((request['case_id'], request['iteration']))
        if item is None:
            raise EvaluationError('Evaluation attempt was not found')
        return item

    def inventory(self):
        return {'run_sha256': self.run_sha256, 'suite_name': self.run['suite_name'], 'mode': self.run['mode'],
                'attempts': [{key: item['row'][key] for key in ('case_id', 'iteration', 'status', 'error')}
                             for item in self.attempts.values()], 'model_called': False}

    def open(self, request):
        item = self.select(request)
        return copy.deepcopy({'inputs': item['inputs'], 'generation': item['generation'],
                              'attempt': item['row'], 'reference_notes': item['reference_notes']})

    def export(self, request, review_db):
        _fields(request, 'run_sha256 reviewer selections')
        if request['run_sha256'] != self.run_sha256:
            raise EvaluationError('Review selections belong to a different run')
        if not isinstance(request['selections'], list) or len(request['selections']) > len(self.attempts):
            raise EvaluationError('Select at most one saved review per evaluation attempt')
        ratings = review_template(self.run, self.run_sha256)
        ratings['reviewer'] = request['reviewer']
        by_id = {item['claim_id']: item for item in ratings['items']}
        bindings, seen = [], set()
        for selection in request['selections']:
            _fields(selection, 'case_id iteration review_id')
            key = (selection['case_id'], selection['iteration'])
            item = self.select({key: selection[key] for key in ('case_id', 'iteration')})
            if key in seen or item['generation'] is None:
                raise EvaluationError('Duplicate or failed attempt cannot receive a saved review')
            seen.add(key)
            records = list_claim_reviews(review_db, item['report'], item['catalog'], review_id=selection['review_id'])
            if not records or _canonical(records[0]['generation']) != _canonical(item['generation']):
                raise EvaluationError('Saved review does not match this exact evaluation output')
            record = records[0]
            check_saved_inputs(record, item['report'], item['catalog'])
            for claim in record['items']:
                target = by_id[f"{selection['case_id']}:{selection['iteration']}:{claim['claim_id']}"]
                target.update(rating=claim['rating'], reason=claim['reason'])
            bindings.append({**selection, 'revision': record['revision'], 'reviewer': record['reviewer'],
                             'generation_sha256': record['generation_sha256'], 'reviewed_at': record['reviewed_at'],
                             'record_sha256': digest(encode(record))})
        raw = encode(ratings)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise EvaluationError('Ratings exceed the evaluation artifact budget')
        summary = summarize_rating_bytes(self.raw, raw)
        provenance = {'schema_version': 'artemis-eval-review-bindings/1', 'run_sha256': self.run_sha256,
                      'ratings_sha256': digest(raw), 'selections': bindings,
                      'unselected_attempts': [{'case_id': key[0], 'iteration': key[1]} for key in self.attempts if key not in seen],
                      'notice': 'Explicit saved revisions only. Unselected claims remain unreviewed. Hashes are not authentication.'}
        stream = BytesIO()
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
            for name, content in (('ratings.json', raw), ('bindings.json', encode(provenance)), ('summary.json', encode(summary))):
                bundle.writestr(name, content)
        return {'filename': 'artemis-evaluation-review.zip', 'mime_type': 'application/zip',
                'content_b64': base64.b64encode(stream.getvalue()).decode(), 'summary': summary, 'bindings': provenance}
