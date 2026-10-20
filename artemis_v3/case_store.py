"""Explicit local source archive. Exact sample hashes remain report assertions."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from .cape import MAX_BYTES, parse_cape_report
from .ruleset import MAX_RULESET_BYTES, parse_ruleset

APPLICATION_ID = 0x41524333  # ARC3; separate from the analyst review store
MAX_CASES = 1000
MAX_TOTAL_BYTES = 128 * 1024 * 1024


class CaseStoreError(ValueError):
    """Invalid archive input or inconsistent local archive."""


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'))


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _sha(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', value):
        raise CaseStoreError('Expected a complete SHA-256 value, not a prefix or filename')
    return value.lower()


def source_identity(raw):
    """Extract only the target SHA-256 from already validated CAPE source bytes."""
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise CaseStoreError('Expected bounded CAPE source bytes')
    root = json.loads(raw.decode('utf-8-sig'))
    target = root.get('target') if isinstance(root, dict) else None
    file = target.get('file') if isinstance(target, dict) else None
    value = file.get('sha256') if isinstance(file, dict) else None
    try:
        sample = _sha(value)
    except CaseStoreError:
        sample = None
    return {'report_sha256': _hash(raw), 'sample_sha256': sample,
            'sample_hash_pointer': '/target/file/sha256' if sample else None,
            'sample_identity_kind': 'report_asserted' if sample else 'absent_or_invalid',
            'notice': 'Report fingerprint and reported sample hash are distinct; no sample bytes were verified.'}


def _case_id(report_sha256, ruleset_sha256, synthetic):
    return _hash(_json([report_sha256, ruleset_sha256, synthetic]).encode())


def _prepare(raw, rules, synthetic, title):
    if type(synthetic) is not bool:
        raise CaseStoreError('Archive synthetic label must be boolean')
    if not isinstance(title, str) or len(title) > 100:
        raise CaseStoreError('Archive title must contain at most 100 characters')
    report = parse_cape_report(raw, synthetic=synthetic)
    catalog = parse_ruleset(rules) if rules is not None else None
    identity = source_identity(raw)
    rules_hash = catalog.source_sha256 if catalog else None
    return {'schema_version': 'artemis-case/1', 'case_id': _case_id(report.source_sha256, rules_hash, synthetic),
            **identity, 'ruleset_sha256': rules_hash, 'ruleset_version': catalog.version if catalog else None,
            'ruleset_synthetic': catalog.synthetic if catalog else False, 'synthetic': synthetic,
            'title': title.strip() or 'Report ' + report.source_sha256[:12],
            'evidence_count': len(report.evidence), 'coverage_warning_count': len(report.warnings)}


def _schema(connection, create=False):
    app = connection.execute('PRAGMA application_id').fetchone()[0]
    version = connection.execute('PRAGMA user_version').fetchone()[0]
    if app == 0 and version == 0 and create:
        if connection.execute("SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchone():
            raise CaseStoreError('Database is not an Artemis case archive')
        connection.execute('''CREATE TABLE cases (
            case_id TEXT PRIMARY KEY, report_sha256 TEXT NOT NULL, ruleset_sha256 TEXT,
            synthetic INTEGER NOT NULL, sample_sha256 TEXT, created_at TEXT NOT NULL,
            metadata TEXT NOT NULL, metadata_sha256 TEXT NOT NULL,
            report BLOB NOT NULL, ruleset BLOB)''')
        connection.execute('CREATE INDEX sample_lookup ON cases(sample_sha256)')
        connection.execute('CREATE INDEX report_lookup ON cases(report_sha256)')
        connection.execute(f'PRAGMA application_id={APPLICATION_ID}')
        connection.execute('PRAGMA user_version=1')
    elif app != APPLICATION_ID or version != 1:
        raise CaseStoreError('Unsupported Artemis case archive')


_COLUMNS = '''case_id, report_sha256, ruleset_sha256, synthetic, sample_sha256, created_at,
    CASE WHEN length(metadata)<=16384 THEN metadata ELSE NULL END, metadata_sha256,
    length(report), length(ruleset)'''


def _metadata(row):
    case_id, report_hash, rules_hash, synthetic, sample_hash, created, body, checksum, report_size, rules_size = row
    try:
        value = json.loads(body)
        if (not isinstance(value, dict) or _hash(_json(value).encode()) != checksum or
                value.get('schema_version') != 'artemis-case/1' or synthetic not in (0, 1) or
                type(value.get('synthetic')) is not bool or
                any(value.get(key) != expected for key, expected in {
                    'case_id': case_id, 'report_sha256': report_hash, 'ruleset_sha256': rules_hash,
                    'synthetic': bool(synthetic), 'sample_sha256': sample_hash, 'created_at': created}.items()) or
                case_id != _case_id(report_hash, rules_hash, bool(synthetic)) or
                not 0 < report_size <= MAX_BYTES or
                (rules_size is not None and not 0 < rules_size <= MAX_RULESET_BYTES)):
            raise CaseStoreError('Archive metadata integrity check failed')
        return value
    except (TypeError, ValueError, RecursionError) as exc:
        raise CaseStoreError('Archive metadata integrity check failed') from exc


def save_case(database, raw, *, rules=None, synthetic=False, title=''):
    """Store exact source bytes once per report/ruleset/provenance tuple."""
    value = _prepare(raw, rules, synthetic, title)  # all inputs validated before DB creation
    connection = None
    try:
        connection = sqlite3.connect(str(database), timeout=5)
        connection.execute('BEGIN IMMEDIATE')
        _schema(connection, create=True)
        prior = connection.execute(f'SELECT {_COLUMNS} FROM cases WHERE case_id=?', (value['case_id'],)).fetchone()
        if prior:
            metadata = _metadata(prior)
            stored = connection.execute('SELECT report, ruleset FROM cases WHERE case_id=?', (value['case_id'],)).fetchone()
            if stored != (raw, rules):
                raise CaseStoreError('Archived source bytes differ from their identity')
            connection.commit()
            return {'created': False, 'case': metadata}
        count, size = connection.execute('SELECT count(*), coalesce(sum(length(report)+coalesce(length(ruleset),0)),0) FROM cases').fetchone()
        if count >= MAX_CASES or size + len(raw) + len(rules or b'') > MAX_TOTAL_BYTES:
            raise CaseStoreError('Case archive reached its record or 128 MiB source-payload budget')
        value['created_at'] = datetime.now(timezone.utc).isoformat()
        body = _json(value)
        connection.execute('INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?)',
                           (value['case_id'], value['report_sha256'], value['ruleset_sha256'], synthetic,
                            value['sample_sha256'], value['created_at'], body, _hash(body.encode()), raw, rules))
        connection.commit()
        return {'created': True, 'case': value}
    except sqlite3.Error as exc:
        raise CaseStoreError('Cannot write Artemis case archive') from exc
    finally:
        if connection is not None:
            connection.close()


def list_cases(database, *, kind=None, sha256=None, limit=50):
    """Newest metadata first; exact typed hash lookup only, no similarity inference."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise CaseStoreError('Case list limit must be between 1 and 100')
    if (kind is None) != (sha256 is None) or kind not in (None, 'sample', 'report'):
        raise CaseStoreError('Choose sample or report hash lookup explicitly')
    normalized = _sha(sha256) if kind else None
    path = Path(database).resolve()
    if not path.exists():
        return []
    connection = None
    try:
        connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5)
        connection.execute('BEGIN')
        _schema(connection)
        query = f'SELECT {_COLUMNS} FROM cases'
        params = []
        if kind:
            query += ' WHERE ' + ('sample_sha256' if kind == 'sample' else 'report_sha256') + '=?'
            params.append(normalized)
        query += ' ORDER BY rowid DESC LIMIT ?'; params.append(limit)
        return [_metadata(row) for row in connection.execute(query, params)]
    except sqlite3.Error as exc:
        raise CaseStoreError('Cannot read Artemis case archive') from exc
    finally:
        if connection is not None:
            connection.close()


def open_case(database, case_id):
    case_id = _sha(case_id)
    connection = None
    try:
        connection = sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True, timeout=5)
        connection.execute('BEGIN')
        _schema(connection)
        row = connection.execute(f'SELECT {_COLUMNS} FROM cases WHERE case_id=?', (case_id,)).fetchone()
        if row is None:
            raise CaseStoreError('Archived case was not found')
        value = _metadata(row)
        raw, rules = connection.execute('SELECT report, ruleset FROM cases WHERE case_id=?', (case_id,)).fetchone()
        prepared = _prepare(raw, rules, value['synthetic'], value['title'])
        # Parser coverage/counts can evolve; exact source identities must remain stable.
        identity_fields = ('case_id', 'report_sha256', 'ruleset_sha256', 'synthetic', 'ruleset_synthetic',
                           'sample_sha256', 'sample_hash_pointer', 'sample_identity_kind', 'ruleset_version')
        if any(prepared[key] != value.get(key) for key in identity_fields):
            raise CaseStoreError('Archived source integrity check failed')
        return value, raw, rules
    except sqlite3.Error as exc:
        raise CaseStoreError('Cannot open Artemis case archive') from exc
    finally:
        if connection is not None:
            connection.close()
