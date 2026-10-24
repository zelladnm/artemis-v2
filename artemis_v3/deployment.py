"""Zero-install local startup, bounded configuration and synthetic field self-test."""
import argparse
import hashlib
import http.client
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import sys
import tempfile
from threading import Thread, Timer
import webbrowser

from . import __version__

ROOT = Path(__file__).resolve().parents[1]
MAX_CONFIG_BYTES = 16 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
ASSETS = ('web/index.html', 'web/app.js', 'web/style.css', 'web/demo/report.json', 'web/demo/ruleset.json')
DEFAULTS = {'data_dir': None, 'port': 0, 'open_browser': True, 'ollama_model': None,
            'ollama_port': 11434, 'model_timeout': 60, 'model_digest': None}


class DeploymentError(ValueError):
    """Operator-facing message authored here, never raw source/config contents."""


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise DeploymentError('Configuration contains duplicate keys.')
        value[key] = item
    return value


def _constant(value):
    raise DeploymentError('Configuration contains an invalid number.')


def _json_file(path, limit):
    try:
        with path.open('rb') as source:
            raw = source.read(limit + 1)
        if len(raw) > limit:
            raise DeploymentError('Local configuration or manifest exceeds its size limit.')
        return json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_pairs, parse_constant=_constant)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise DeploymentError('Cannot read valid local configuration or manifest.') from exc


def default_data_dir():
    if sys.platform == 'win32':
        parent = Path(os.environ.get('LOCALAPPDATA', ''))
        if not parent.is_absolute():
            parent = Path.home() / 'AppData/Local'
        return parent / 'ArtemisV3'
    if sys.platform == 'darwin':
        return Path.home() / 'Library/Application Support/ArtemisV3'
    parent = Path(os.environ.get('XDG_STATE_HOME', ''))
    if not parent.is_absolute():
        parent = Path.home() / '.local/state'
    return parent / 'artemis-v3'


def settings_for(args, root=ROOT):
    settings = dict(DEFAULTS)
    config = Path(args.config).expanduser().resolve() if args.config else root / 'artemis.local.json'
    if args.config or config.exists():
        value = _json_file(config, MAX_CONFIG_BYTES)
        if not isinstance(value, dict) or set(value) - set(DEFAULTS):
            raise DeploymentError('Unknown configuration keys; compare settings.example.json.')
        settings.update(value)
    for name in ('data_dir', 'port', 'ollama_model', 'ollama_port', 'model_timeout', 'model_digest'):
        if getattr(args, name) is not None:
            settings[name] = getattr(args, name)
    if args.no_browser:
        settings['open_browser'] = False
    if args.lite:
        settings.update(ollama_model=None, model_digest=None)
    if (type(settings['port']) is not int or not 0 <= settings['port'] <= 65535 or
            type(settings['ollama_port']) is not int or not 1 <= settings['ollama_port'] <= 65535 or
            type(settings['open_browser']) is not bool or
            type(settings['model_timeout']) not in (int, float) or
            not 0 < settings['model_timeout'] <= 60 or not math.isfinite(settings['model_timeout'])):
        raise DeploymentError('Invalid port, browser flag or model timeout in configuration.')
    model = settings['ollama_model']; digest = settings['model_digest']
    if model is not None and (not isinstance(model, str) or not model.strip() or len(model) > 128 or not model.isprintable()):
        raise DeploymentError('The local model name must contain 1-128 printable characters.')
    if digest is not None and (model is None or not isinstance(digest, str) or not re.fullmatch('[a-fA-F0-9]{64}', digest)):
        raise DeploymentError('A model digest requires a local model and a complete SHA-256 value.')
    if digest is not None:
        settings['model_digest'] = digest.lower()
    directory = settings['data_dir']
    if directory is None:
        directory = default_data_dir()
    else:
        if not isinstance(directory, str) or not directory.strip() or len(directory) > 4096 or not directory.isprintable():
            raise DeploymentError('The data directory must be a nonempty local path.')
        directory = Path(directory).expanduser()
        if not directory.is_absolute():
            directory = (Path.cwd() if args.data_dir is not None else config.parent) / directory
    settings['data_dir'] = directory.resolve()
    return settings


def prepare_data_dir(directory):
    """Probe a new temporary file; never open or modify existing investigation DBs."""
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix='.artemis-write-', dir=directory) as probe:
            probe.write(b'artemis-local-write-check'); probe.flush()
    except OSError as exc:
        raise DeploymentError('Data directory is not writable. Choose another location with --data-dir.') from exc


def bundle_integrity(root):
    manifest = root / 'bundle-manifest.json'
    if not manifest.exists():
        return {'status': 'source_checkout', 'verified_files': 0}
    value = _json_file(manifest, MAX_MANIFEST_BYTES)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'files'} or
            value['schema_version'] != 'artemis-field-bundle/1' or not isinstance(value['files'], list) or
            not 1 <= len(value['files']) <= 256):
        raise DeploymentError('Invalid field-test bundle manifest. Extract a fresh package.')
    seen = set(); total = 0
    for item in value['files']:
        if not isinstance(item, dict) or set(item) != {'path', 'sha256', 'bytes'}:
            raise DeploymentError('Invalid bundle file entry.')
        name = item['path']
        if (not isinstance(name, str) or not name or len(name) > 240 or '\\' in name or ':' in name or
                PurePosixPath(name).is_absolute() or str(PurePosixPath(name)) != name or
                any(part in ('.', '..') for part in name.split('/')) or
                name in seen or not isinstance(item['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', item['sha256']) or
                type(item['bytes']) is not int or not 0 <= item['bytes'] <= 8 * 1024 * 1024):
            raise DeploymentError('Invalid or duplicate bundle file path or fingerprint.')
        target = (root / name).resolve()
        if not target.is_relative_to(root.resolve()) or target.is_symlink():
            raise DeploymentError('Bundle entry escapes the application directory.')
        total += item['bytes']
        if total > 32 * 1024 * 1024:
            raise DeploymentError('Bundle exceeds the field-test size limit.')
        try:
            if not target.is_file() or target.stat().st_size != item['bytes']:
                raise DeploymentError('Bundle file is missing or changed. Extract a fresh package.')
            if hashlib.sha256(target.read_bytes()).hexdigest() != item['sha256']:
                raise DeploymentError('Bundle integrity check failed. Extract a fresh package.')
        except OSError as exc:
            raise DeploymentError('Cannot read a required bundle file.') from exc
        seen.add(name)
    required = {'launch.py', 'artemis_v3/__init__.py', 'artemis_v3/deployment.py', 'artemis_v3/workbench.py'}
    required.update('artemis_v3/' + name for name in ASSETS)
    if not required <= seen:
        raise DeploymentError('Bundle manifest omits required application files.')
    return {'status': 'verified', 'verified_files': len(seen)}


def doctor(settings, root=ROOT):
    checks = {}; errors = []
    checks['python_supported'] = sys.version_info >= (3, 11)
    checks['web_assets_present'] = all((root / 'artemis_v3' / name).is_file() for name in ASSETS)
    try:
        import sqlite3
        sqlite_version = sqlite3.sqlite_version; checks['sqlite_available'] = True
    except ImportError:
        sqlite_version = None; checks['sqlite_available'] = False
    try:
        integrity = bundle_integrity(root); checks['bundle_integrity'] = True
    except DeploymentError:
        integrity = {'status': 'failed', 'verified_files': 0}; checks['bundle_integrity'] = False
        errors.append('application_files_invalid')
    try:
        prepare_data_dir(settings['data_dir']); checks['data_directory_writable'] = True
    except DeploymentError:
        checks['data_directory_writable'] = False; errors.append('data_directory_not_writable')
    return {'schema_version': 'artemis-environment/1', 'status': 'passed' if all(checks.values()) else 'failed',
            'application_version': __version__, 'build_kind': 'first_machine_test_preview',
            'python_version': platform.python_version(), 'system': platform.system(), 'machine': platform.machine(),
            'sqlite_version': sqlite_version, 'checks': checks, 'error_codes': errors, 'bundle': integrity,
            'local_model_configured': settings['ollama_model'] is not None,
            'model_digest_pinned': settings['model_digest'] is not None, 'model_connection': 'not_checked',
            'notice': 'No report data, credentials, environment values, host/user names or absolute paths are included. Review metadata before sharing.'}


def smoke_test():
    """Exercise actual loopback HTTP, parsers and both SQLite stores in a temporary directory."""
    from .workbench import WorkbenchServer
    with tempfile.TemporaryDirectory(prefix='artemis-self-test-') as temporary:
        root = Path(temporary)
        with WorkbenchServer(0, case_db=root / 'cases.sqlite', review_db=root / 'reviews.sqlite') as server:
            thread = Thread(target=server.serve_forever, daemon=True); thread.start()
            def call(path, payload=None):
                connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                headers = {'X-Artemis-Token': server.token, 'Origin': server.origin}
                if payload is not None:
                    headers['Content-Type'] = 'application/json'
                try:
                    connection.request('GET' if payload is None else 'POST', path,
                        json.dumps(payload).encode() if payload is not None else None, headers)
                    response = connection.getresponse(); raw = response.read(1024 * 1024 + 1)
                    if response.status != 200 or len(raw) > 1024 * 1024:
                        raise DeploymentError('Local HTTP self-test failed.')
                    return json.loads(raw)
                finally:
                    connection.close()
            try:
                config = call('/api/config'); inputs = call('/api/demo'); result = call('/api/analyze', inputs)
                archived = call('/api/cases/save', {**inputs, 'archive_title': 'Temporary synthetic self-test'})
                reopened = call('/api/cases/open', {'case_id': archived['case']['case_id']})
                request = {'source_sha256': result['report']['source_sha256'], 'ruleset_sha256': result['ruleset_sha256'],
                    'delta': 0, 'cited_evidence': [result['report']['evidence'][0]['evidence_id']],
                    'rationale': 'Synthetic self-test only', 'reviewer': 'Synthetic self-test', 'decision': 'defer',
                    'reason': 'Temporary local storage check', 'expected_previous_id': None}
                reviewed = call('/api/review', {**inputs, 'review_request': request})
                checks = {'loopback_http': True, 'model_disabled': config['model_enabled'] is False,
                    'synthetic_demo': inputs['synthetic'] is True and result['report']['synthetic'] is True,
                    'source_archive_reopened': reopened['result']['report']['source_sha256'] == result['report']['source_sha256'],
                    'review_saved': reviewed['analyst_review']['decision'] == 'defer',
                    'base_score_preserved': result['rule_assessment']['base_score'] == 1 == reviewed['analyst_review']['base_score']}
                return {'schema_version': 'artemis-self-test/1', 'status': 'passed' if all(checks.values()) else 'failed',
                    'checks': checks, 'source_kind': 'synthetic', 'model_called': False, 'sample_executed': False,
                    'storage': 'temporary_only', 'notice': 'Functional self-test only; not real report or model-quality acceptance.'}
            finally:
                server.shutdown(); thread.join(3)


def _open_browser(origin):
    try:
        if webbrowser.open(origin, new=2):
            return
    except (OSError, webbrowser.Error):
        pass
    print('Browser did not open. Open the loopback URL printed above.', file=sys.stderr, flush=True)


def parser():
    result = argparse.ArgumentParser(description='Artemis v3 first-machine-test launcher; no pip install required')
    mode = result.add_mutually_exclusive_group()
    mode.add_argument('--doctor', action='store_true', help='Check files, SQLite and data-directory writes; output limited environment JSON')
    mode.add_argument('--smoke-test', action='store_true', help='Run synthetic local HTTP/storage checks using temporary stores and no model')
    result.add_argument('--config', help='Explicit local settings JSON; otherwise optional artemis.local.json beside launch.py')
    result.add_argument('--data-dir', help='Separate local investigation directory; defaults to per-user application state')
    result.add_argument('--port', type=int, help='0 chooses a free loopback port (default); explicit occupied ports fail')
    result.add_argument('--no-browser', action='store_true')
    result.add_argument('--lite', action='store_true', help='Disable a configured model for this invocation')
    result.add_argument('--ollama-model', help='Explicit installed local model; no automatic pull')
    result.add_argument('--ollama-port', type=int)
    result.add_argument('--model-timeout', type=float)
    result.add_argument('--model-digest', help='Optional full artifact SHA-256; requires a local model name')
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        settings = settings_for(args)
        if args.smoke_test:
            result = smoke_test(); print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result['status'] == 'passed' else 1
        result = doctor(settings)
        if args.doctor:
            print(json.dumps(result, ensure_ascii=False, indent=2)); return 0 if result['status'] == 'passed' else 1
        if result['status'] != 'passed':
            raise DeploymentError('Startup checks failed. Run doctor.cmd or python launch.py --doctor and read FIRST_TEST.md.')
        from .semantic import OllamaLocalProvider
        from .workbench import WorkbenchServer
        provider = (OllamaLocalProvider(settings['ollama_model'], port=settings['ollama_port'], timeout=settings['model_timeout'],
                    expected_digest=settings['model_digest']) if settings['ollama_model'] is not None else None)
        with WorkbenchServer(settings['port'], case_db=settings['data_dir'] / 'cases.sqlite',
                             review_db=settings['data_dir'] / 'reviews.sqlite', semantic_provider=provider) as server:
            print('Artemis v3 - first machine test (preview)', flush=True)
            print('Open: ' + server.origin, flush=True)
            print('Local data: ' + str(settings['data_dir']), flush=True)
            print('Mode: ' + ('Local AI (explicit requests only)' if provider else 'Lite (no model required)'), flush=True)
            print('Press Ctrl+C in this window to stop.', flush=True)
            if settings['open_browser']:
                opener = Timer(0.25, _open_browser, args=(server.origin,)); opener.daemon = True; opener.start()
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
        return 0
    except (DeploymentError, OSError, ValueError, ImportError) as exc:
        if args.doctor or args.smoke_test:
            print(json.dumps({'schema_version': 'artemis-environment/1', 'status': 'failed',
                              'error_code': 'configuration_or_local_operation_failed'}))
        else:
            print(str(exc) if isinstance(exc, DeploymentError) else
                  'Cannot start Artemis. Check Python, settings, data-directory permissions and the requested port. See FIRST_TEST.md.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
