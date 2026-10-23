"""Bounded, no-overwrite snapshots and full-record checks for local Artemis stores.

No sample execution, model invocation, network I/O or source schema migration.
Backups/restores publish a verified standalone database only at a new path.
"""
import argparse
from contextlib import contextmanager, closing
from functools import lru_cache
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
import time

from . import case_store, claim_review, review

KINDS = {'case': (case_store.APPLICATION_ID, (1,)), 'review': (review.APPLICATION_ID, (1, 2))}
MAX_DB_BYTES = 512 * 1024 * 1024
MAX_REVIEW_ROWS = 10_000  # per table; no list/history truncation
MAX_SCORE_RECORD_BYTES = 32 * 1024 * 1024
SIDECARS = ('-wal', '-shm', '-journal')


class StorageError(ValueError):
    """Invalid storage input, incomplete history, corrupt data or failed snapshot."""


class _Deadline:
    def __init__(self, timeout):
        if type(timeout) not in (float, int) or not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise StorageError('Timeout must be greater than zero and at most 300 seconds')
        self.end = time.monotonic() + timeout

    def expired(self):
        return time.monotonic() >= self.end

    def check(self):
        if self.expired():
            raise StorageError('Storage operation timed out; no partial database is published')


@contextmanager
def _operation(kind, timeout):
    if kind not in KINDS:
        raise StorageError('Unknown Artemis store kind')
    deadline = _Deadline(timeout)
    try:
        yield deadline
    except StorageError:
        raise
    except (sqlite3.Error, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        deadline.check()
        raise StorageError('Cannot read, validate or copy the Artemis database') from exc


def _existing_file(path):
    path = Path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise StorageError('Source must be a regular database file, not a symlink or device')
    if path.stat().st_size > MAX_DB_BYTES:
        raise StorageError('Database exceeds the 512 MiB recovery budget')
    return path.resolve(strict=True)


@contextmanager
def _readonly(path, deadline):
    # A connection context manager alone does not close its file handles.
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=0.1)) as connection:
        connection.execute('PRAGMA query_only=ON')
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.set_progress_handler(lambda: int(deadline.expired()), 1000)
        connection.execute('BEGIN')  # one consistent view across schema, rows and backup
        yield connection


def _schema_objects(connection):
    return [(kind, name, table, ' '.join(sql.split()).lower()) for kind, name, table, sql in
            connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type,name")]


@lru_cache(maxsize=3)
def _expected_schema(kind, version):
    # Reuse the application's actual DDL; storage does not maintain another schema.
    with closing(sqlite3.connect(':memory:')) as connection:
        (case_store._schema if kind == 'case' else review._schema)(connection, create=True)
        if kind == 'review' and version == 1:
            connection.execute('DROP TABLE claim_reviews')
        return _schema_objects(connection)


def _shape(connection, kind, deadline):
    deadline.check()
    application = connection.execute('PRAGMA application_id').fetchone()[0]
    version = connection.execute('PRAGMA user_version').fetchone()[0]
    if application != KINDS[kind][0] or version not in KINDS[kind][1]:
        raise StorageError(f'Not a supported Artemis {kind} database')
    if _schema_objects(connection) != _expected_schema(kind, version):
        raise StorageError('Database tables, indexes or constraints differ from the supported schema')
    page_size = connection.execute('PRAGMA page_size').fetchone()[0]
    pages = connection.execute('PRAGMA page_count').fetchone()[0]
    if page_size * pages > MAX_DB_BYTES:
        raise StorageError('Database exceeds the 512 MiB recovery budget')
    return {'kind': kind, 'schema_version': version, 'application_id': application}, page_size


def _check_cases(connection, deadline):
    count, size = connection.execute('SELECT count(*),coalesce(sum(length(report)+coalesce(length(ruleset),0)),0) FROM cases').fetchone()
    if count > case_store.MAX_CASES or size > case_store.MAX_TOTAL_BYTES:
        raise StorageError('Archive exceeds its record or source-payload budget')
    for row in connection.execute(f'SELECT {case_store._COLUMNS} FROM cases ORDER BY rowid'):
        deadline.check()
        value = case_store._metadata(row)
        raw, rules = connection.execute('SELECT report,ruleset FROM cases WHERE case_id=?', (value['case_id'],)).fetchone()
        case_store._check_sources(value, raw, rules)
    return count


def _check_history(connection, table, deadline):
    # Table/column names are fixed by this module, never supplied by source data.
    claim = table == 'claim_reviews'
    identity = 'generation_sha256' if claim else 'proposal_sha256'
    count = connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
    if count > MAX_REVIEW_ROWS:
        raise StorageError('Review table exceeds the 10,000-record recovery budget')
    limit = claim_review.MAX_RECORD_BYTES if claim else MAX_SCORE_RECORD_BYTES
    if connection.execute(f'SELECT 1 FROM {table} WHERE typeof(body)!=\'text\' OR length(CAST(body AS BLOB))>? LIMIT 1', (limit,)).fetchone():
        raise StorageError('Stored review body exceeds its recovery limit or is not text')
    previous_group = previous_id = None
    previous_revision = 0
    for row in connection.execute(f'SELECT * FROM {table} ORDER BY {identity},revision'):
        deadline.check()
        record = (claim_review._decode_row if claim else review._decode_row)(row)
        group = record[identity]
        if not isinstance(group, str) or not isinstance(record['review_id'], str):
            raise StorageError('Invalid review identity')
        if group != previous_group:
            previous_group, previous_id, previous_revision = group, None, 0
        if (type(record['revision']) is not int or record['revision'] != previous_revision + 1 or
                record['previous_review_id'] != previous_id):
            raise StorageError('Review revision history is missing, reordered or cross-linked')
        if not claim:
            proposal_id = review._digest({key: record[key] for key in
                ('assessment', 'proposal', 'ruleset_sha256', 'ruleset_synthetic')})
            if record.get('schema_version') != 'artemis-review/1' or proposal_id != group:
                raise StorageError('Score review proposal identity is inconsistent')
        previous_id, previous_revision = record['review_id'], record['revision']
    return count


def _validate(connection, kind, deadline):
    result, _ = _shape(connection, kind, deadline)
    if connection.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
        raise StorageError('SQLite integrity check failed')
    counts = {'cases': _check_cases(connection, deadline)} if kind == 'case' else {
        'reviews': _check_history(connection, 'reviews', deadline)}
    if kind == 'review' and result['schema_version'] == 2:
        counts['claim_reviews'] = _check_history(connection, 'claim_reviews', deadline)
    deadline.check()
    checks = ['sqlite_integrity', 'record_integrity']
    if kind == 'review': checks.append('revision_chains')
    return {**result, 'records': counts, 'checks': checks}


def verify(kind, source, *, timeout=30):
    """Check every stored row in one read transaction; no migrations or repairs."""
    with _operation(kind, timeout) as deadline:
        with _readonly(_existing_file(source), deadline) as connection:
            return _validate(connection, kind, deadline)


def _new_destination(path):
    path = Path(path).absolute()
    destination = path.parent.resolve(strict=True) / path.name
    if not destination.parent.is_dir():
        raise StorageError('Destination parent must already be a directory')
    _check_destination(destination)
    return destination


def _check_destination(path):
    if any(os.path.lexists(str(path) + suffix) for suffix in ('', *SIDECARS)):
        raise StorageError('Destination or SQLite sidecar already exists; refusing to overwrite')


def _sync_directory(parent):
    try:
        fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return True
    except OSError:
        return False  # Windows and some filesystems do not support directory fsync.


def snapshot(kind, source, destination, *, timeout=30):
    """Backup or restore a verified snapshot at a new path. Never replace a store."""
    with _operation(kind, timeout) as deadline:
        source = _existing_file(source)
        destination = _new_destination(destination)
        temporary = None
        result = None
        try:
            with _readonly(source, deadline) as input_db:
                _, page_size = _shape(input_db, kind, deadline)
                fd, name = tempfile.mkstemp(prefix='.artemis-snapshot-', suffix='.sqlite', dir=destination.parent)
                temporary = Path(name)
                os.close(fd)
                os.chmod(temporary, 0o600)

                def progress(status, remaining, total):
                    deadline.check()
                    if total * page_size > MAX_DB_BYTES:
                        raise StorageError('Database exceeds the 512 MiB recovery budget')

                with closing(sqlite3.connect(temporary, timeout=0.1)) as output_db:
                    output_db.set_progress_handler(lambda: int(deadline.expired()), 1000)
                    input_db.backup(output_db, pages=256, progress=progress, sleep=0.05)
                    # Only the private copy changes journal mode; all committed WAL
                    # records are retained and the published file has no sidecar dependency.
                    if output_db.execute('PRAGMA journal_mode=DELETE').fetchone() != ('delete',):
                        raise StorageError('Cannot make the snapshot a standalone database')
            with _readonly(temporary, deadline) as checked:
                metadata = _validate(checked, kind, deadline)
            digest = hashlib.sha256()
            with temporary.open('r+b') as handle:  # Windows file sync needs a writable handle.
                for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                    deadline.check()
                    digest.update(chunk)
                os.fsync(handle.fileno())
            deadline.check()
            _check_destination(destination)
            # Atomic and exclusive on supported local filesystems; no rename/copy
            # fallback that could overwrite a competing file or expose a partial DB.
            os.link(temporary, destination)
            result = {**metadata, 'destination': str(destination), 'bytes': temporary.stat().st_size,
                      'snapshot_sha256': digest.hexdigest(), 'directory_synced': _sync_directory(destination.parent)}
            return result
        finally:
            if temporary is not None:
                leftovers = []
                for suffix in ('', *SIDECARS):
                    try:
                        Path(str(temporary) + suffix).unlink()
                    except FileNotFoundError:
                        pass
                    except OSError:
                        leftovers.append(str(temporary) + suffix)
                if leftovers:
                    if result is not None:
                        result['cleanup_warning'] = leftovers
                    else:
                        raise StorageError('Could not remove private temporary files: ' + ', '.join(leftovers))


def main(argv=None):
    parser = argparse.ArgumentParser(description='Verify, back up or restore a local Artemis SQLite store')
    parser.add_argument('action', choices=('verify', 'backup', 'restore'))
    parser.add_argument('--kind', choices=tuple(KINDS), required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--timeout', type=float, default=30, help='Cooperative SQLite deadline, 0 < seconds <= 300 (default 30)')
    parser.add_argument('--json', action='store_true', help='Print counts and snapshot fingerprint as JSON')
    args = parser.parse_args(argv)
    if (args.action == 'verify') != (args.destination is None):
        parser.error('verify takes no --destination; backup/restore require --destination')
    try:
        result = (verify(args.kind, args.source, timeout=args.timeout) if args.action == 'verify' else
                  snapshot(args.kind, args.source, args.destination, timeout=args.timeout))
    except StorageError as exc:
        print(f'Artemis storage: {exc}', file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({'action': args.action, **result}, ensure_ascii=True))
    else:
        print(f"{args.action}: {result['kind']} schema {result['schema_version']}; records {result['records']}" +
              (f"; {result['bytes']} bytes at {result['destination']}; SHA-256 {result['snapshot_sha256']}" if 'destination' in result else ''))
        if result.get('directory_synced') is False:
            print('Directory sync is unavailable; filesystem crash durability is not confirmed.', file=sys.stderr)
        if result.get('cleanup_warning'):
            print('Snapshot is complete; remove private temporary files: ' + ', '.join(result['cleanup_warning']), file=sys.stderr)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
