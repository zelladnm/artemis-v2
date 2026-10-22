"""Consistent, no-clobber backups for the two opt-in Artemis SQLite stores.

Only database files are handled. No sample execution, model invocation, or network I/O.
"""
import argparse
import os
from pathlib import Path
import sqlite3
import sys
import tempfile


KINDS = {
    'case': (0x41524333, (1,), ('cases',)),
    'review': (0x41525433, (1, 2), ('reviews',)),
}


class StorageError(ValueError):
    """Invalid storage source, destination, or database integrity."""


def _existing_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise StorageError('Source must be an existing regular database file (not a symlink)')
    return path.resolve()


def _connect_readonly(path):
    try:
        connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5)
        connection.execute('PRAGMA busy_timeout=5000')
        return connection
    except sqlite3.Error as exc:
        raise StorageError('Cannot open source database read-only') from exc


def _validate(connection, kind):
    if kind not in KINDS:
        raise StorageError('Unknown Artemis store kind')
    expected_app, allowed_versions, tables = KINDS[kind]
    try:
        application = connection.execute('PRAGMA application_id').fetchone()[0]
        version = connection.execute('PRAGMA user_version').fetchone()[0]
        if application != expected_app or version not in allowed_versions:
            raise StorageError(f'Not a supported Artemis {kind} database')
        existing = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if not set(tables).issubset(existing) or (kind == 'review' and version == 2 and
                                                   'claim_reviews' not in existing):
            raise StorageError('Artemis database schema is incomplete')
        rows = connection.execute('PRAGMA integrity_check').fetchall()
        if len(rows) != 1 or rows[0] != ('ok',):
            raise StorageError('SQLite integrity check failed')
        return {'kind': kind, 'schema_version': version, 'application_id': application}
    except sqlite3.Error as exc:
        raise StorageError('Cannot validate SQLite database integrity') from exc


def verify(kind, source):
    """Verify kind, schema and SQLite integrity without changing the source."""
    source = _existing_file(source)
    with _connect_readonly(source) as connection:
        return _validate(connection, kind)


def snapshot(kind, source, destination):
    """Create a consistent SQLite backup/restore at a *new* path only.

    A temporary database is fully validated before an atomic, no-overwrite hard
    link exposes the destination. SQLite's backup API includes committed WAL data.
    """
    source = _existing_file(source)
    destination = Path(destination).absolute()
    parent = destination.parent
    if not parent.is_dir():
        raise StorageError('Destination parent directory must already exist')
    if destination.exists() or destination.is_symlink():
        raise StorageError('Destination already exists; refusing to overwrite')
    if source == destination.resolve():
        raise StorageError('Source and destination must differ')

    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix='.artemis-snapshot-', suffix='.sqlite', dir=parent)
        os.close(fd)
        os.chmod(temporary, 0o600)
        with _connect_readonly(source) as input_db:
            _validate(input_db, kind)
            with sqlite3.connect(temporary, timeout=5) as output_db:
                input_db.backup(output_db, pages=256, sleep=0.1)
        with _connect_readonly(Path(temporary)) as checked:
            result = _validate(checked, kind)
        with open(temporary, 'rb') as handle:
            os.fsync(handle.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise StorageError('Destination appeared during backup; refusing to overwrite') from exc
        # The link operation makes the fully checked snapshot visible atomically.
        try:
            parent_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except OSError:
            pass  # Some filesystems do not support syncing directory handles.
        return {**result, 'destination': str(destination), 'bytes': destination.stat().st_size}
    except sqlite3.Error as exc:
        raise StorageError('SQLite backup failed; source left unchanged') from exc
    except OSError as exc:
        raise StorageError('Cannot safely create database snapshot') from exc
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def main(argv=None):
    parser = argparse.ArgumentParser(description='Verify, back up or restore a local Artemis SQLite store')
    parser.add_argument('action', choices=('verify', 'backup', 'restore'))
    parser.add_argument('--kind', choices=tuple(KINDS), required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path)
    args = parser.parse_args(argv)
    if (args.action == 'verify') != (args.destination is None):
        parser.error('verify takes no --destination; backup/restore require --destination')
    try:
        result = (verify(args.kind, args.source) if args.action == 'verify'
                  else snapshot(args.kind, args.source, args.destination))
    except StorageError as exc:
        print(f'Artemis storage: {exc}', file=sys.stderr)
        return 2
    print(f"{args.action}: {result['kind']} schema {result['schema_version']} validated" +
          (f"; {result['bytes']} bytes at {result['destination']}" if 'destination' in result else ''))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
