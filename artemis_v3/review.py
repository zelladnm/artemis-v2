"""Local analyst review history. Declared identities are not authenticated identities."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

from .scoring import assess_signatures, propose_adjustment

MAX_REQUEST_BYTES = 32 * 1024
APPLICATION_ID = 0x41525433  # ART3; avoid writing into unrelated SQLite stores


class ReviewError(ValueError):
    """Invalid, stale, or unreadable review state."""


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _digest(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReviewError('Duplicate review JSON key')
        result[key] = value
    return result


def _constant(value):
    raise ReviewError('Invalid review JSON number')


def load_review_request(path):
    path = Path(path)
    if not path.is_file():
        raise ReviewError('Review request must be a regular local file')
    try:
        with path.open('rb') as source:
            raw = source.read(MAX_REQUEST_BYTES + 1)
    except OSError as exc:
        raise ReviewError('Cannot read review request') from exc
    if len(raw) > MAX_REQUEST_BYTES:
        raise ReviewError('Review request exceeds the 32 KiB limit')
    try:
        result = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, RecursionError) as exc:
        raise ReviewError('Invalid review request JSON') from exc
    _validate_request(result)
    return result


def _validate_request(request):
    fields = {'source_sha256', 'ruleset_sha256', 'delta', 'cited_evidence',
              'rationale', 'reviewer', 'decision', 'reason', 'expected_previous_id'}
    if not isinstance(request, dict) or set(request) != fields:
        raise ReviewError('Review request fields do not match the documented schema')
    for key, maximum in (('reviewer', 100), ('reason', 1000), ('rationale', 500)):
        value = request[key]
        if not isinstance(value, str) or not 1 <= len(value.strip()) <= maximum:
            raise ReviewError(f'Review {key} must be nonempty text within {maximum} characters')
    if request['decision'] not in ('approve', 'reject', 'defer'):
        raise ReviewError('Review decision must be approve, reject or defer')
    if request['expected_previous_id'] is not None and not isinstance(request['expected_previous_id'], str):
        raise ReviewError('Expected previous review ID must be a string or null')
    for key in ('source_sha256', 'ruleset_sha256'):
        value = request[key]
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ReviewError(f'Invalid review {key}')
    if type(request['delta']) is not int or not -10 <= request['delta'] <= 10:
        raise ReviewError('Review delta must be an integer between -10 and 10')
    refs = request['cited_evidence']
    if (not isinstance(refs, list) or not 1 <= len(refs) <= 32 or
            any(not isinstance(ref, str) for ref in refs) or len(set(refs)) != len(refs)):
        raise ReviewError('Review requires 1-32 distinct evidence references')


def _schema(connection, *, create):
    version = connection.execute('PRAGMA user_version').fetchone()[0]
    application_id = connection.execute('PRAGMA application_id').fetchone()[0]
    if version == 0 and application_id == 0 and create:
        if connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone():
            raise ReviewError('Database is not an Artemis review store')
        connection.execute('''CREATE TABLE reviews (
            review_id TEXT PRIMARY KEY, proposal_sha256 TEXT NOT NULL,
            revision INTEGER NOT NULL, previous_review_id TEXT,
            body TEXT NOT NULL, body_sha256 TEXT NOT NULL,
            UNIQUE(proposal_sha256, revision))''')
        connection.execute(f'PRAGMA application_id = {APPLICATION_ID}')
        connection.execute('PRAGMA user_version = 1')
        version, application_id = 1, APPLICATION_ID
    if version not in (1, 2) or application_id != APPLICATION_ID:
        raise ReviewError('Unsupported Artemis review store version')
    if version == 1 and create:
        # Additive, transactional upgrade on an explicit write, never on a read.
        connection.execute('''CREATE TABLE claim_reviews (
            review_id TEXT PRIMARY KEY, generation_sha256 TEXT NOT NULL,
            input_sha256 TEXT NOT NULL, revision INTEGER NOT NULL, previous_review_id TEXT,
            body TEXT NOT NULL, body_sha256 TEXT NOT NULL,
            UNIQUE(generation_sha256, revision))''')
        connection.execute('CREATE INDEX claim_reviews_input ON claim_reviews(input_sha256)')
        connection.execute('PRAGMA user_version = 2')
        version = 2
    return version


def _decode_row(row):
    review_id, proposal_id, revision, previous, body, checksum = row
    try:
        record = json.loads(body, object_pairs_hook=_pairs, parse_constant=_constant)
        actual_checksum = _digest(record)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ReviewError('Stored review is invalid') from exc
    if (not isinstance(record, dict) or actual_checksum != checksum or
            record.get('review_id') != review_id or record.get('proposal_sha256') != proposal_id or
            record.get('revision') != revision or record.get('previous_review_id') != previous):
        raise ReviewError('Stored review integrity check failed')
    return record


def record_review(database, report, catalog, request, *, proposal_packet=None):
    """Recompute score/proposal, then append a decision atomically without overwrites.

    expected_previous_id guards against stale decisions per proposal. Approving a
    critical negative proposal is refused; explicit analyst scores remain separate
    from the deterministic base and are never a malware verdict.
    """
    _validate_request(request)
    if request['source_sha256'] != report.source_sha256 or request['ruleset_sha256'] != catalog.source_sha256:
        raise ReviewError('Review source or ruleset fingerprint differs from current inputs')
    assessment = assess_signatures(report, catalog.rules, version=catalog.version)
    proposal = propose_adjustment(report, assessment, delta=request['delta'],
                                  cited_evidence=request['cited_evidence'], rationale=request['rationale'])
    if request['decision'] == 'approve' and proposal.status == 'blocked_critical_signal':
        raise ReviewError('Critical negative proposals cannot be approved by this workflow')
    if proposal_packet is not None:
        if (_digest(proposal_packet.get('adjustment_proposal')) != _digest(proposal.as_dict()) or
                proposal_packet.get('ruleset_sha256') != catalog.source_sha256):
            raise ReviewError('Review decision differs from the imported proposal')
    assessment_data = assessment.as_dict()
    proposal_data = proposal.as_dict()
    proposal_id = _digest({'assessment': assessment_data, 'proposal': proposal_data,
                           'ruleset_sha256': catalog.source_sha256, 'ruleset_synthetic': catalog.synthetic})
    connection = None
    try:
        connection = sqlite3.connect(str(database), timeout=5)
        connection.execute('BEGIN IMMEDIATE')
        _schema(connection, create=True)
        previous = connection.execute('SELECT * FROM reviews WHERE proposal_sha256=? ORDER BY revision DESC LIMIT 1',
                                      (proposal_id,)).fetchone()
        prior_record = _decode_row(previous) if previous else None
        previous_id = prior_record['review_id'] if prior_record else None
        if previous_id != request['expected_previous_id']:
            raise ReviewError('Stale review: reload latest history and specify expected_previous_id')
        record = {
            'schema_version': 'artemis-review/1', 'review_id': str(uuid4()),
            'proposal_sha256': proposal_id, 'revision': previous[2] + 1 if previous else 1,
            'previous_review_id': previous_id,
            'reviewed_at': datetime.now(timezone.utc).isoformat(),
            'reviewer': request['reviewer'].strip(), 'identity_kind': 'self_declared_local',
            'decision': request['decision'], 'reason': request['reason'].strip(),
            'source_sha256': report.source_sha256, 'ruleset_sha256': catalog.source_sha256,
            'ruleset_synthetic': catalog.synthetic, 'assessment': assessment_data,
            'external_proposal_sha256': proposal_packet['proposal_sha256'] if proposal_packet else None,
            'proposal': proposal_data,
            'base_score': assessment.base_score,
            'analyst_score': proposal.proposed_score if request['decision'] == 'approve' else None,
            'verdict': 'not_assessed',
        }
        connection.execute('INSERT INTO reviews VALUES (?, ?, ?, ?, ?, ?)',
                           (record['review_id'], proposal_id, record['revision'], previous_id,
                            _canonical(record), _digest(record)))
        connection.commit()
        # Return the same JSON types that will be read from disk (tuples -> lists).
        return json.loads(_canonical(record))
    except sqlite3.Error as exc:
        raise ReviewError('Cannot write Artemis review store') from exc
    finally:
        if connection is not None:
            connection.close()  # rolls back uncommitted work, including failed schema creation


def list_reviews(database, *, proposal_sha256=None, review_id=None, limit=100):
    """Read newest records first without creating/modifying a database."""
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ReviewError('Review history limit must be between 1 and 1000')
    connection = None
    try:
        connection = sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True, timeout=5)
        _schema(connection, create=False)
        query = 'SELECT * FROM reviews WHERE 1=1'
        params = []
        if proposal_sha256 is not None:
            query += ' AND proposal_sha256=?'
            params.append(proposal_sha256)
        if review_id is not None:
            if not isinstance(review_id, str) or not 1 <= len(review_id) <= 100:
                raise ReviewError('Invalid review ID')
            query += ' AND review_id=?'
            params.append(review_id)
        query += ' ORDER BY rowid DESC LIMIT ?'
        params.append(limit)
        return [_decode_row(row) for row in connection.execute(query, params)]
    except sqlite3.Error as exc:
        raise ReviewError('Cannot read Artemis review store') from exc
    finally:
        if connection is not None:
            connection.close()
