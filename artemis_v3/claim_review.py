"""Human support judgments for one exact, server-issued explanation snapshot.

The per-process receipt protects the HTTP round trip, not human identity or truth.
Persisted checksums detect accidental corruption, not a malicious database owner.
"""
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
from uuid import uuid4

from .review import ReviewError, _canonical, _constant, _digest, _pairs, _schema
from .scoring import assess_signatures

MAX_GENERATION_BYTES = 128 * 1024
MAX_RECORD_BYTES = 256 * 1024
RATINGS = ('supported', 'unsupported', 'uncertain', 'unreviewed')
SECTIONS = ('source_observations', 'hypotheses', 'adjustment')
SCOPES = ('current', 'historical', 'mixed')


def _generation_bytes(generation):
    if not isinstance(generation, dict) or set(generation) != {'explanation', 'suggestion_file_b64'}:
        raise ReviewError('Expected the exact server-issued generation snapshot')
    try:
        raw = _canonical(generation).encode()
    except (ValueError, TypeError, RecursionError) as exc:
        raise ReviewError('Invalid generation snapshot') from exc
    if len(raw) > MAX_GENERATION_BYTES:
        raise ReviewError('Generation snapshot exceeds 128 KiB')
    return raw


def issue_receipt(secret, generation):
    """Only call for a newly validated explanation or an integrity-checked record."""
    return hmac.new(secret, b'artemis-claim-review/1\0' + _generation_bytes(generation), hashlib.sha256).hexdigest()


def _verify_receipt(secret, generation, receipt):
    if (not isinstance(receipt, str) or not re.fullmatch('[a-f0-9]{64}', receipt) or
            not hmac.compare_digest(receipt, issue_receipt(secret, generation))):
        raise ReviewError('Explanation receipt is invalid or expired; reopen a saved review or generate again')


def _binding(report_sha256, ruleset_sha256, synthetic):
    return _digest({'report_sha256': report_sha256, 'ruleset_sha256': ruleset_sha256, 'synthetic': synthetic})


def input_binding(report, catalog):
    return _binding(report.source_sha256, catalog.source_sha256 if catalog else None, report.synthetic)


def check_generation_inputs(generation, report, catalog):
    explanation = generation['explanation']
    if (explanation['report_sha256'] != report.source_sha256 or
            explanation['ruleset_sha256'] != (catalog.source_sha256 if catalog else None) or
            explanation['synthetic'] is not report.synthetic):
        raise ReviewError('Explanation belongs to different report bytes, rules or synthetic provenance')


def check_saved_inputs(record, report, catalog):
    """Do not reissue a receipt if a parser/scorer upgrade changes the saved view."""
    check_generation_inputs(record['generation'], report, catalog)
    refs = {ref for item in record['items'] for ref in item['evidence_refs']}
    current = [asdict(item) for item in report.evidence if item.evidence_id in refs]
    assessment = assess_signatures(report, catalog.rules, version=catalog.version) if catalog else None
    if (_digest(current) != _digest(record['current_evidence']) or
            (assessment.base_score if assessment else None) != record['base_score']):
        raise ReviewError('Saved evidence or rule score differs from the current implementation; preserve the saved snapshot and generate again')


def _claims(explanation):
    items = []
    for section in SECTIONS[:2]:
        for index, claim in enumerate(explanation[section]):
            items.append({'claim_id': f'{section}:{index}', 'section': section, 'text': claim['text'],
                          'evidence_refs': claim['evidence_refs'], 'verification': claim.get('verification'),
                          'source_scope': claim.get('source_scope', 'current')})
    packet = explanation['proposal_review']
    if packet:
        proposal = packet['adjustment_proposal']
        items.append({'claim_id': 'adjustment:0', 'section': 'adjustment', 'text': proposal['rationale'],
                      'evidence_refs': proposal['cited_evidence'], 'verification': None, 'source_scope': 'current'})
    return items


def review_template(generation):
    return {'generation_sha256': hashlib.sha256(_generation_bytes(generation)).hexdigest(),
            'reviewer': '', 'expected_previous_id': None,
            'items': [{'claim_id': item['claim_id'], 'rating': 'unreviewed', 'reason': ''}
                      for item in _claims(generation['explanation'])]}


def _review_items(generation, request):
    fields = {'generation_sha256', 'reviewer', 'expected_previous_id', 'items'}
    if not isinstance(request, dict) or set(request) != fields:
        raise ReviewError('Claim review fields do not match the documented schema')
    if request['generation_sha256'] != review_template(generation)['generation_sha256']:
        raise ReviewError('Claim review belongs to a different generation')
    reviewer = request['reviewer']
    if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 100:
        raise ReviewError('Claim reviewer must contain 1-100 characters')
    if request['expected_previous_id'] is not None:
        _review_id(request['expected_previous_id'])
    claims = _claims(generation['explanation'])
    ratings = request['items']
    if not claims or not isinstance(ratings, list) or len(ratings) != len(claims):
        raise ReviewError('Review must include every claim from this generation exactly once')
    items = []
    for claim, rating in zip(claims, ratings):
        if (not isinstance(rating, dict) or set(rating) != {'claim_id', 'rating', 'reason'} or
                rating['claim_id'] != claim['claim_id'] or rating['rating'] not in RATINGS):
            raise ReviewError('Missing, reordered or modified claim ratings')
        reason = rating['reason']
        if (not isinstance(reason, str) or len(reason) > 1000 or
                (rating['rating'] != 'unreviewed' and not reason.strip())):
            raise ReviewError('Each rated claim needs a reason within 1000 characters')
        items.append({**claim, 'rating': rating['rating'], 'reason': reason.strip()})
    return items


def summarize(items):
    counts = dict.fromkeys(RATINGS, 0)
    sections = {key: dict.fromkeys(RATINGS, 0) for key in SECTIONS}
    scopes = {key: dict.fromkeys(RATINGS, 0) for key in SCOPES}
    for item in items:
        counts[item['rating']] += 1
        sections[item['section']][item['rating']] += 1
        scopes[item['source_scope']][item['rating']] += 1
    total = len(items)
    reviewed = total - counts['unreviewed']
    return {'counts': counts, 'total': total, 'reviewed': reviewed,
            'coverage': reviewed / total if total else None,
            'by_section': sections, 'by_source_scope': scopes}


def _review_id(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}', value):
        raise ReviewError('Invalid claim review ID')


def _decode_row(row):
    review_id, generation_id, binding, revision, previous, body, checksum = row
    if not isinstance(body, str) or len(body.encode()) > MAX_RECORD_BYTES:
        raise ReviewError('Stored claim review exceeds its size limit')
    try:
        record = json.loads(body, object_pairs_hook=_pairs, parse_constant=_constant)
        explanation = record['generation']['explanation']
        request = {'generation_sha256': record['generation_sha256'], 'reviewer': record['reviewer'],
                   'expected_previous_id': record['previous_review_id'],
                   'items': [{key: item[key] for key in ('claim_id', 'rating', 'reason')} for item in record['items']]}
        if (record['schema_version'] != 'artemis-claim-review/1' or _digest(record) != checksum or
                record['review_id'] != review_id or record['generation_sha256'] != generation_id or
                record['input_sha256'] != binding or record['revision'] != revision or
                record['previous_review_id'] != previous or
                _binding(explanation['report_sha256'], explanation['ruleset_sha256'], explanation['synthetic']) != binding or
                _review_items(record['generation'], request) != record['items'] or summarize(record['items']) != record['summary']):
            raise ReviewError('Stored claim review integrity check failed')
        return record
    except (KeyError, TypeError, ValueError, RecursionError) as exc:
        raise ReviewError('Stored claim review is invalid or has failed integrity checks') from exc


def record_claim_review(database, report, catalog, generation, receipt, secret, request):
    """Append human judgments; never call a model or approve/change a score."""
    _verify_receipt(secret, generation, receipt)
    check_generation_inputs(generation, report, catalog)
    items = _review_items(generation, request)
    generation_id = request['generation_sha256']
    binding = input_binding(report, catalog)
    assessment = assess_signatures(report, catalog.rules, version=catalog.version) if catalog else None
    refs = {ref for item in items for ref in item['evidence_refs']}
    record = {'schema_version': 'artemis-claim-review/1', 'review_id': str(uuid4()),
              'generation_sha256': generation_id, 'input_sha256': binding,
              'reviewed_at': datetime.now(timezone.utc).isoformat(),
              'reviewer': request['reviewer'].strip(), 'identity_kind': 'self_declared_local',
              'generation': generation, 'items': items, 'summary': summarize(items),
              'current_evidence': [asdict(item) for item in report.evidence if item.evidence_id in refs],
              'base_score': assessment.base_score if assessment else None,
              'verdict': 'not_assessed', 'score_decision': 'not_recorded_by_claim_review'}
    connection = None
    try:
        connection = sqlite3.connect(str(database), timeout=5)
        connection.execute('BEGIN IMMEDIATE')
        _schema(connection, create=True)
        previous = connection.execute('SELECT * FROM claim_reviews WHERE generation_sha256=? ORDER BY revision DESC LIMIT 1',
                                      (generation_id,)).fetchone()
        prior = _decode_row(previous) if previous else None
        previous_id = prior['review_id'] if prior else None
        if previous_id != request['expected_previous_id']:
            raise ReviewError('Stale claim review: reload the latest saved review before revising')
        record.update(revision=prior['revision'] + 1 if prior else 1, previous_review_id=previous_id)
        body = _canonical(record)
        if len(body.encode()) > MAX_RECORD_BYTES:
            raise ReviewError('Claim review exceeds 256 KiB')
        connection.execute('INSERT INTO claim_reviews VALUES (?, ?, ?, ?, ?, ?, ?)',
                           (record['review_id'], generation_id, binding, record['revision'], previous_id, body, _digest(record)))
        connection.commit()
        return json.loads(body)
    except sqlite3.Error as exc:
        raise ReviewError('Cannot write Artemis claim review store') from exc
    finally:
        if connection is not None:
            connection.close()


def list_claim_reviews(database, report, catalog, *, review_id=None, limit=20):
    """Read only records bound to these exact current inputs, newest first."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ReviewError('Claim history limit must be between 1 and 100')
    if review_id is not None:
        _review_id(review_id)
    if not Path(database).exists():
        return []
    connection = None
    try:
        connection = sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True, timeout=5)
        if _schema(connection, create=False) == 1:
            return []
        query = 'SELECT * FROM claim_reviews WHERE input_sha256=?'
        params = [input_binding(report, catalog)]
        if review_id is not None:
            query += ' AND review_id=?'
            params.append(review_id)
        query += ' ORDER BY rowid DESC LIMIT ?'
        return [_decode_row(row) for row in connection.execute(query, [*params, limit])]
    except sqlite3.Error as exc:
        raise ReviewError('Cannot read Artemis claim review store') from exc
    finally:
        if connection is not None:
            connection.close()
